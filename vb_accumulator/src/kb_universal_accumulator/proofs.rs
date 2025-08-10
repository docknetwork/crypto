//! As the KB universal accumulator is made of 2 positive accumulators, its proof of membership and non-membership is the proof
//! of membership in positive accumulator

use crate::{
    error::VBAccumulatorError,
    kb_universal_accumulator::witness::{
        KBUniversalAccumulatorMembershipWitness, KBUniversalAccumulatorNonMembershipWitness,
    },
    prelude::{PreparedPublicKey, PreparedSetupParams},
    proofs::{MembershipProof, MembershipProofProtocol},
    setup::{PublicKey, SetupParams},
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use short_group_sig::common::ProvingKey;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KBUniversalAccumulatorMembershipProofProtocol<E: Pairing>(
    pub MembershipProofProtocol<E>,
);

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KBUniversalAccumulatorNonMembershipProofProtocol<E: Pairing>(
    pub MembershipProofProtocol<E>,
);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct KBUniversalAccumulatorMembershipProof<E: Pairing>(pub MembershipProof<E>);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct KBUniversalAccumulatorNonMembershipProof<E: Pairing>(pub MembershipProof<E>);

impl<E: Pairing> KBUniversalAccumulatorMembershipProofProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &KBUniversalAccumulatorMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Self {
        Self(MembershipProofProtocol::init(
            rng,
            element,
            element_blinding,
            &witness.0,
            pk,
            params,
            prk,
        ))
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0
            .challenge_contribution(accumulator_value, pk, params, prk, writer)
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorMembershipProof<E>, VBAccumulatorError> {
        Ok(KBUniversalAccumulatorMembershipProof(
            self.0.clone().gen_proof(challenge)?,
        ))
    }

    pub fn gen_partial_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorMembershipProof<E>, VBAccumulatorError> {
        Ok(KBUniversalAccumulatorMembershipProof(
            self.0.clone().gen_partial_proof(challenge)?,
        ))
    }
}

impl<E: Pairing> KBUniversalAccumulatorMembershipProof<E> {
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0
            .challenge_contribution(accumulator_value, pk, params, prk, writer)
    }

    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify(accumulator_value, challenge, pk, params, prk)
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_with_randomized_pairing_checker(
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
            pairing_checker,
        )
    }

    pub fn verify_partial(
        &self,
        resp_for_element: &E::ScalarField,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_partial(
            resp_for_element,
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
        )
    }

    pub fn verify_partial_with_randomized_pairing_checker(
        &self,
        resp_for_element: &E::ScalarField,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_partial_with_randomized_pairing_checker(
            resp_for_element,
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
            pairing_checker,
        )
    }

    pub fn get_schnorr_response_for_element(&self) -> Option<&E::ScalarField> {
        self.0.get_schnorr_response_for_element()
    }
}

impl<E: Pairing> KBUniversalAccumulatorNonMembershipProofProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Self {
        Self(MembershipProofProtocol::init(
            rng,
            element,
            element_blinding,
            &witness.0,
            pk,
            params,
            prk,
        ))
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0
            .challenge_contribution(accumulator_value, pk, params, prk, writer)
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorNonMembershipProof<E>, VBAccumulatorError> {
        Ok(KBUniversalAccumulatorNonMembershipProof(
            self.0.clone().gen_proof(challenge)?,
        ))
    }

    pub fn gen_partial_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorNonMembershipProof<E>, VBAccumulatorError> {
        Ok(KBUniversalAccumulatorNonMembershipProof(
            self.0.clone().gen_partial_proof(challenge)?,
        ))
    }
}

impl<E: Pairing> KBUniversalAccumulatorNonMembershipProof<E> {
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0
            .challenge_contribution(accumulator_value, pk, params, prk, writer)
    }

    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify(accumulator_value, challenge, pk, params, prk)
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_with_randomized_pairing_checker(
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
            pairing_checker,
        )
    }

    pub fn verify_partial(
        &self,
        resp_for_element: &E::ScalarField,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_partial(
            resp_for_element,
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
        )
    }

    pub fn verify_partial_with_randomized_pairing_checker(
        &self,
        resp_for_element: &E::ScalarField,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_partial_with_randomized_pairing_checker(
            resp_for_element,
            accumulator_value,
            challenge,
            pk,
            params,
            prk,
            pairing_checker,
        )
    }

    pub fn get_schnorr_response_for_element(&self) -> Option<&E::ScalarField> {
        self.0.get_schnorr_response_for_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb_universal_accumulator::accumulator::tests::setup_kb_universal_accum;
    use ark_bls12_381::Fr;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    #[test]
    fn membership_non_membership_proof() {
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, domain, mut mem_state, mut non_mem_state) =
            setup_kb_universal_accum(&mut rng, max);
        let prk = ProvingKey::generate_using_rng(&mut rng);
        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(keypair.public_key.clone());

        let mut members = vec![];
        let mut non_members = vec![];
        let mut mem_witnesses = vec![];
        let mut non_mem_witnesses = vec![];
        let count = 10;

        for i in 0..count {
            let elem = domain[i];
            accumulator = accumulator
                .add(
                    elem,
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();
            members.push(elem);
            non_members.push(domain[count + i])
        }

        for i in 0..count {
            let w = accumulator
                .get_membership_witness(&members[i], &keypair.secret_key, &mem_state)
                .unwrap();
            assert!(accumulator.verify_membership(&members[i], &w, &keypair.public_key, &params));
            mem_witnesses.push(w);

            let w = accumulator
                .get_non_membership_witness(
                    &non_members[i],
                    &keypair.secret_key,
                    &mut non_mem_state,
                )
                .unwrap();
            assert!(accumulator.verify_non_membership(
                &non_members[i],
                &w,
                &keypair.public_key,
                &params
            ));
            non_mem_witnesses.push(w);
        }

        let mut mem_proof_create_duration = Duration::default();
        let mut mem_proof_verif_duration = Duration::default();
        let mut mem_proof_verif_with_prepared_duration = Duration::default();
        let mut mem_proof_verif_with_rand_pair_check_duration = Duration::default();
        let mut mem_proof_verif_with_prepared_and_rand_pair_check_duration = Duration::default();
        let mut non_mem_proof_create_duration = Duration::default();
        let mut non_mem_proof_verif_duration = Duration::default();
        let mut non_mem_proof_verif_with_prepared_duration = Duration::default();
        let mut non_mem_proof_verif_with_rand_pair_check_duration = Duration::default();
        let mut non_mem_proof_verif_with_prepared_and_rand_pair_check_duration =
            Duration::default();

        let mut mem_pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        let mut non_mem_pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);

        for i in 0..count {
            let start = Instant::now();
            let protocol = KBUniversalAccumulatorMembershipProofProtocol::init(
                &mut rng,
                members[i],
                None,
                &mem_witnesses[i],
                &keypair.public_key,
                &params,
                &prk,
            );
            mem_proof_create_duration += start.elapsed();

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(
                    accumulator.mem_value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_prover,
                )
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            mem_proof_create_duration += start.elapsed();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(
                    accumulator.mem_value(),
                    &keypair.public_key,
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
                    accumulator.mem_value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
            mem_proof_verif_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify(
                    accumulator.mem_value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                )
                .unwrap();
            mem_proof_verif_with_prepared_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.mem_value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                    &mut mem_pairing_checker,
                )
                .unwrap();
            mem_proof_verif_with_rand_pair_check_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.mem_value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                    &mut mem_pairing_checker,
                )
                .unwrap();
            mem_proof_verif_with_prepared_and_rand_pair_check_duration += start.elapsed();

            let start = Instant::now();
            let protocol = KBUniversalAccumulatorNonMembershipProofProtocol::init(
                &mut rng,
                non_members[i],
                None,
                &non_mem_witnesses[i],
                &keypair.public_key,
                &params,
                &prk,
            );
            non_mem_proof_create_duration += start.elapsed();

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(
                    accumulator.non_mem_value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_prover,
                )
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            non_mem_proof_create_duration += start.elapsed();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(
                    accumulator.non_mem_value(),
                    &keypair.public_key,
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
                    accumulator.non_mem_value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
            non_mem_proof_verif_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify(
                    accumulator.non_mem_value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                )
                .unwrap();
            non_mem_proof_verif_with_prepared_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.non_mem_value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                    &mut non_mem_pairing_checker,
                )
                .unwrap();
            non_mem_proof_verif_with_rand_pair_check_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.non_mem_value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                    &mut non_mem_pairing_checker,
                )
                .unwrap();
            non_mem_proof_verif_with_prepared_and_rand_pair_check_duration += start.elapsed();
        }

        let start = Instant::now();
        assert!(mem_pairing_checker.verify());
        mem_proof_verif_with_rand_pair_check_duration += start.elapsed();

        let start = Instant::now();
        assert!(non_mem_pairing_checker.verify());
        non_mem_proof_verif_with_rand_pair_check_duration += start.elapsed();

        println!(
            "Time to create {} membership proofs is {:?}",
            count, mem_proof_create_duration
        );
        println!(
            "Time to verify {} membership proofs is {:?}",
            count, mem_proof_verif_duration
        );
        println!(
            "Time to verify {} membership proofs using prepared params is {:?}",
            count, mem_proof_verif_with_prepared_duration
        );
        println!(
            "Time to verify {} membership proofs using randomized pairing checker is {:?}",
            count, mem_proof_verif_with_rand_pair_check_duration
        );
        println!(
            "Time to verify {} membership proofs using prepared params and randomized pairing checker is {:?}",
            count, mem_proof_verif_with_prepared_and_rand_pair_check_duration
        );

        println!(
            "Time to create {} non-membership proofs is {:?}",
            count, non_mem_proof_create_duration
        );
        println!(
            "Time to verify {} non-membership proofs is {:?}",
            count, non_mem_proof_verif_duration
        );
        println!(
            "Time to verify {} non-membership proofs using prepared params is {:?}",
            count, non_mem_proof_verif_with_prepared_duration
        );
        println!(
            "Time to verify {} non-membership proofs using randomized pairing checker is {:?}",
            count, non_mem_proof_verif_with_rand_pair_check_duration
        );
        println!(
            "Time to verify {} non-membership proofs using prepared params and randomized pairing checker is {:?}",
            count, non_mem_proof_verif_with_prepared_and_rand_pair_check_duration
        );
    }
}
