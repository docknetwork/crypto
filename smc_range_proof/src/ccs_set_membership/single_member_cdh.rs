//! Check membership of a single element in the set. This is based on an optimized protocol for proof of knowledge of
//! weak-BB signature described in the CDH paper.

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing, common::MemberCommitmentKey,
    error::SmcRangeProofError, prelude::SetMembershipCheckParams,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use schnorr_pok::discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol};
use short_group_sig::weak_bb_sig_pok_cdh::{PoKOfSignatureG1, PoKOfSignatureG1Protocol};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetMembershipCheckProtocol<E: Pairing> {
    /// Protocol for proving knowledge of the weak-BB signature on the set member
    pub pok_sig: PoKOfSignatureG1Protocol<E>,
    /// Protocol for proving knowledge of the opening to commitment to the set member
    pub sc: PokTwoDiscreteLogsProtocol<E::G1Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckProof<E: Pairing> {
    /// Proof of knowledge of the weak-BB signature on the set member
    pub pok_sig: PoKOfSignatureG1<E>,
    /// Proof of knowledge of the opening to commitment to the set member
    pub sc: PokTwoDiscreteLogs<E::G1Affine>,
}

impl<E: Pairing> SetMembershipCheckProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        member: E::ScalarField,
        r: E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        let sig = params.get_sig_for_member(&member)?;
        let s = E::ScalarField::rand(rng);
        let pok_sig =
            PoKOfSignatureG1Protocol::init(rng, sig, member, Some(s), &params.bb_sig_params.g1);
        let sc = PokTwoDiscreteLogsProtocol::init(
            member,
            s,
            &comm_key.g,
            r,
            E::ScalarField::rand(rng),
            &comm_key.h,
        );
        Ok(Self { pok_sig, sc })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.pok_sig
            .challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        self.sc
            .challenge_contribution(&comm_key.g, &comm_key.h, commitment, &mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> SetMembershipCheckProof<E> {
        SetMembershipCheckProof {
            pok_sig: self.pok_sig.gen_proof(challenge),
            sc: self.sc.gen_proof(challenge),
        }
    }
}

impl<E: Pairing> SetMembershipCheckProof<E> {
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        self.pok_sig.verify(
            challenge,
            E::G2Prepared::from(params.bb_pk.0),
            &params.bb_sig_params.g1,
            params.bb_sig_params.g2_prepared,
        )?;
        if !self
            .sc
            .verify(commitment, &comm_key.g, &comm_key.h, challenge)
        {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        // Note: The following check could be avoided if the abstraction PokTwoDiscreteLogsProtocol wasnt used
        if *self.pok_sig.get_resp_for_message() != self.sc.response1 {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParamsWithPairing<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.pok_sig
            .challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        self.sc
            .challenge_contribution(&comm_key.g, &comm_key.h, commitment, &mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs_set_membership::setup::{
        SetMembershipCheckParams, SetMembershipCheckParamsWithPairing,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::misc::n_rand;
    use schnorr_pok::compute_random_oracle_challenge;
    use short_group_sig::common::SignatureParams;
    use std::time::Instant;

    #[test]
    fn membership_check() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let set_size = 10;
        let sig_params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);

        let set = n_rand(&mut rng, set_size).collect::<Vec<_>>();
        let (params, _) =
            SetMembershipCheckParams::new_given_sig_params(&mut rng, set.clone(), sig_params);
        params.verify().unwrap();

        let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
        params_with_pairing.verify().unwrap();

        let comm_key = MemberCommitmentKey::generate_using_rng(&mut rng);
        let member = set[3].clone();
        let randomness = Fr::rand(&mut rng);
        let commitment = comm_key.commit(&member, &randomness);

        let start = Instant::now();
        let protocol =
            SetMembershipCheckProtocol::init(&mut rng, member, randomness, &comm_key, &params)
                .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&commitment, &comm_key, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);
        println!(
            "Time to prove membership in a set of size {}: {:?}",
            set_size,
            start.elapsed()
        );

        let start = Instant::now();
        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(
                &commitment,
                &comm_key,
                &params_with_pairing,
                &mut chal_bytes_verifier,
            )
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify(
                &commitment,
                &challenge_verifier,
                &comm_key,
                params_with_pairing.clone(),
            )
            .unwrap();
        println!(
            "Time to verify membership in a set of size {}: {:?}",
            set_size,
            start.elapsed()
        );

        let mut bytes = vec![];
        proof.serialize_compressed(&mut bytes).unwrap();
        println!(
            "Membership proof size for a set of size {}: {} bytes",
            set_size,
            bytes.len()
        );
    }
}
