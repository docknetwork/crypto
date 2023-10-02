//! Check membership of a single element in the set using keyed-verification, i.e. verifier knows
//! the secret key for BB sig

use crate::{
    bb_sig::SecretKey, ccs_set_membership::setup::SetMembershipCheckParams,
    common::MemberCommitmentKey, error::SmcRangeProofError,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckWithKVProtocol<E: Pairing> {
    /// The set member that is committed
    pub member: E::ScalarField,
    /// Randomness for the commitment
    pub r: E::ScalarField,
    /// Randomness used to randomize the signature
    pub v: E::ScalarField,
    /// The randomized signature over the committed member
    pub V: E::G1Affine,
    pub a: E::G1Affine,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
    pub s: E::ScalarField,
    pub t: E::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckWithKVProof<E: Pairing> {
    /// The randomized signature over the committed member
    pub V: E::G1Affine,
    pub a: E::G1Affine,
    pub D: E::G1Affine,
    pub z_v: E::ScalarField,
    pub z_sigma: E::ScalarField,
    pub z_r: E::ScalarField,
}

impl<E: Pairing> SetMembershipCheckWithKVProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        member: E::ScalarField,
        r: E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        let v = E::ScalarField::rand(rng);
        let m = E::ScalarField::rand(rng);
        let t = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);
        let V = params.get_sig_for_member(&member)?.0 * v;
        let D = comm_key.commit(&s, &m);
        // a = V * -s + g1 * t
        let a = (V * -s + params.bb_sig_params.g1 * t).into_affine();
        Ok(Self {
            member,
            r,
            v,
            V: V.into(),
            a,
            D: D.into(),
            m,
            s,
            t,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        Self::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> SetMembershipCheckWithKVProof<E> {
        let z_v = self.t - (self.v * challenge);
        let z_r = self.m - (self.r * challenge);
        let z_sigma = self.s - (self.member * challenge);
        SetMembershipCheckWithKVProof {
            V: self.V,
            a: self.a,
            D: self.D,
            z_v,
            z_r,
            z_sigma,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        V: &E::G1Affine,
        a: &E::G1Affine,
        D: &E::G1Affine,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        params.serialize_for_schnorr_protocol_for_kv(&mut writer)?;
        comm_key.serialize_compressed(&mut writer)?;
        for sig in &params.sigs {
            sig.0.serialize_compressed(&mut writer)?;
        }
        commitment.serialize_compressed(&mut writer)?;
        V.serialize_compressed(&mut writer)?;
        a.serialize_compressed(&mut writer)?;
        D.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> SetMembershipCheckWithKVProof<E> {
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        secret_key: &SecretKey<E::ScalarField>,
    ) -> Result<(), SmcRangeProofError> {
        // Check commitment * challenge + g * z_sigma + h * z_r == D
        if (*commitment * challenge + comm_key.commit(&self.z_sigma, &self.z_r)).into_affine()
            != self.D
        {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        // Check a == V * (challenge * secret_key - z_sigma) + g1 * z_v
        if self.a
            != (self.V * (secret_key.0 * challenge - self.z_sigma)
                + params.bb_sig_params.g1 * self.z_v)
                .into_affine()
        {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        SetMembershipCheckWithKVProtocol::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bb_sig::SignatureParams, ccs_set_membership::setup::SetMembershipCheckParams};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::misc::n_rand;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn membership_check() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let set_size = 10;
        let sig_params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);

        let set = n_rand(&mut rng, set_size).collect::<Vec<_>>();
        let (params, sk) =
            SetMembershipCheckParams::new_given_sig_params(&mut rng, set.clone(), sig_params);
        params.verify().unwrap();

        let comm_key = MemberCommitmentKey::generate_using_rng(&mut rng);
        let member = set[3].clone();
        let randomness = Fr::rand(&mut rng);
        let commitment = comm_key.commit(&member, &randomness);

        let protocol = SetMembershipCheckWithKVProtocol::init(
            &mut rng, member, randomness, &comm_key, &params,
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&commitment, &comm_key, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&commitment, &comm_key, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify(&commitment, &challenge_verifier, &comm_key, &params, &sk)
            .unwrap();
    }
}
