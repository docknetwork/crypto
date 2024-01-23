use crate::{
    error::VBAccumulatorError,
    kb_positive_accumulator::{
        setup::{PreparedPublicKey, PreparedSetupParams, PublicKey, SetupParams},
        witness::KBPositiveAccumulatorWitness,
    },
    proofs::{MembershipProof, MembershipProofProtocol},
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use short_group_sig::{
    bb_sig_pok::{PoKOfSignatureG1, PoKOfSignatureG1Protocol},
    common::ProvingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol for proving knowledge of the accumulator member and the corresponding witness. This runs 2 protocols, one to prove
/// knowledge of a BB signature and the other to prove knowledge in a non-adaptive accumulator which essentially is a protocol
/// for proving knowledge of a weak-BB signature.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KBPositiveAccumulatorMembershipProofProtocol<E: Pairing> {
    pub sig_protocol: PoKOfSignatureG1Protocol<E>,
    pub accum_protocol: MembershipProofProtocol<E>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KBPositiveAccumulatorMembershipProof<E: Pairing> {
    pub sig_proof: PoKOfSignatureG1<E>,
    pub accum_proof: MembershipProof<E>,
}

impl<E: Pairing> KBPositiveAccumulatorMembershipProofProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &KBPositiveAccumulatorWitness<E>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Self {
        let accum_member_blinding = E::ScalarField::rand(rng);
        let sig_protocol = PoKOfSignatureG1Protocol::init(
            rng,
            &witness.signature,
            element,
            element_blinding,
            Some(accum_member_blinding),
            &pk.sig,
            &params.sig,
            proving_key,
        );

        let accum_protocol = MembershipProofProtocol::init(
            rng,
            *witness.get_accumulator_member(),
            Some(accum_member_blinding),
            &witness.accum_witness,
            &pk.accum,
            &params.accum,
            proving_key,
        );
        Self {
            sig_protocol,
            accum_protocol,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.sig_protocol
            .challenge_contribution(&pk.sig, &params.sig, proving_key, &mut writer)?;
        self.accum_protocol.challenge_contribution(
            accumulator_value,
            &pk.accum,
            &params.accum,
            proving_key,
            &mut writer,
        )?;
        Ok(())
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<KBPositiveAccumulatorMembershipProof<E>, VBAccumulatorError> {
        let sig_proof = self.sig_protocol.clone().gen_proof(challenge)?;
        let accum_proof = self.accum_protocol.clone().gen_proof(challenge)?;
        Ok(KBPositiveAccumulatorMembershipProof {
            sig_proof,
            accum_proof,
        })
    }
}

impl<E: Pairing> KBPositiveAccumulatorMembershipProof<E> {
    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Result<(), VBAccumulatorError> {
        let pk = pk.into();
        let params = params.into();
        self.sig_proof
            .verify(challenge, pk.sig, params.sig.g1, params.sig.g2, proving_key)?;

        self.accum_proof.verify(
            accumulator_value,
            challenge,
            pk.accum,
            params.accum,
            proving_key,
        )?;

        // Check that the signature's randomness is same as the non-adaptive accumulator's member
        if self.sig_proof.get_resp_for_randomness()
            != self.accum_proof.get_schnorr_response_for_element()
        {
            return Err(VBAccumulatorError::MismatchBetweenSignatureAndAccumulatorValue);
        }

        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        proving_key: &ProvingKey<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        let pk = pk.into();
        let params = params.into();
        self.sig_proof.verify_with_randomized_pairing_checker(
            challenge,
            pk.sig,
            params.sig.g1,
            params.sig.g2,
            proving_key,
            pairing_checker,
        )?;
        self.accum_proof.verify_with_randomized_pairing_checker(
            accumulator_value,
            challenge,
            pk.accum,
            params.accum,
            proving_key,
            pairing_checker,
        )?;

        // Check that the signature's randomness is same as the non-adaptive accumulator's member
        if self.sig_proof.get_resp_for_randomness()
            != self.accum_proof.get_schnorr_response_for_element()
        {
            return Err(VBAccumulatorError::MismatchBetweenSignatureAndAccumulatorValue);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.sig_proof
            .challenge_contribution(&pk.sig, &params.sig, proving_key, &mut writer)?;
        self.accum_proof.challenge_contribution(
            accumulator_value,
            &pk.accum,
            &params.accum,
            proving_key,
            &mut writer,
        )?;
        Ok(())
    }

    pub fn get_schnorr_response_for_element(&self) -> &E::ScalarField {
        self.sig_proof.get_resp_for_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::kb_positive_accumulator::adaptive_accumulator::tests::setup_kb_positive_accum;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn membership_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, accumulator, mut state) = setup_kb_positive_accum(&mut rng);
        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(pk.clone());
        let prk = ProvingKey::<G1Affine>::generate_using_hash::<Blake2b512>(b"test-proving-key");

        let mut members = vec![];
        let mut mem_witnesses = vec![];
        let count = 10;

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            let wit = accumulator
                .add::<Blake2b512>(&elem, &sk, &params, &mut state)
                .unwrap();
            members.push(elem);
            mem_witnesses.push(wit);
        }

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);

        let mut proof_create_duration = Duration::default();
        let mut proof_verif_duration = Duration::default();
        let mut proof_verif_with_rpc_duration = Duration::default();

        for i in 0..count {
            let start = Instant::now();
            let protocol = KBPositiveAccumulatorMembershipProofProtocol::init(
                &mut rng,
                members[i],
                None,
                &mem_witnesses[i],
                &pk,
                &params,
                &prk,
            );
            proof_create_duration += start.elapsed();

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(
                    accumulator.value(),
                    &pk,
                    &params,
                    &prk,
                    &mut chal_bytes_prover,
                )
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(
                    accumulator.value(),
                    &pk,
                    &params,
                    &prk,
                    &mut chal_bytes_verifier,
                )
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
            assert_eq!(challenge_prover, challenge_verifier);
            let start = Instant::now();
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                )
                .unwrap();
            proof_verif_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                    &mut pairing_checker,
                )
                .unwrap();
            proof_verif_with_rpc_duration += start.elapsed();
        }

        println!(
            "Time to create {} membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} membership proofs is {:?}",
            count, proof_verif_duration
        );
        println!(
            "Time to verify {} membership proofs with randomized pairing checker is {:?}",
            count, proof_verif_with_rpc_duration
        );
    }
}
