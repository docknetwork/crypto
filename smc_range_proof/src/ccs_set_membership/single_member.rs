//! Check membership of a single element in the set. This is described in Fig. 1 in the CCS paper.
//! The calculations are changed a bit to be consistent with other instances of Schnorr protocol in this project.

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing, common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    io::Write,
    ops::{Mul, Neg},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetMembershipCheckProtocol<E: Pairing> {
    /// The set member that is committed
    pub member: E::ScalarField,
    /// Randomness for the commitment
    pub r: E::ScalarField,
    /// Randomness used to randomize the signature
    pub v: E::ScalarField,
    /// The randomized signature over the committed member
    pub V: E::G1Affine,
    pub a: PairingOutput<E>,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
    pub s: E::ScalarField,
    pub t: E::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckProof<E: Pairing> {
    /// The randomized signature over the committed member
    pub V: E::G1Affine,
    pub a: PairingOutput<E>,
    pub D: E::G1Affine,
    pub z_v: E::ScalarField,
    pub z_sigma: E::ScalarField,
    pub z_r: E::ScalarField,
}

impl<E: Pairing> SetMembershipCheckProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        member: E::ScalarField,
        r: E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        let params = params.into();
        let v = E::ScalarField::rand(rng);
        let m = E::ScalarField::rand(rng);
        let t = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);
        let V = params.get_sig_for_member(&member)?.0 * v;
        let D = comm_key.commit(&s, &m);
        // Following is different from the paper, the paper has `-s` and `t` but here its opposite
        // a = e(V, g2) * s + e(g1, g2) * -t = e(V * s, g2) + e(g1, g2) * -t
        let a = E::pairing(
            E::G1Prepared::from(V * s),
            params.bb_sig_params.g2_prepared.clone(),
        ) + params.bb_sig_params.g1g2.mul(-t);
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
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        Self::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> SetMembershipCheckProof<E> {
        // Following is different from the paper, the paper has `-` but here its `+`
        let z_v = self.t + (self.v * challenge);
        let z_r = self.m + (self.r * challenge);
        let z_sigma = self.s + (self.member * challenge);
        SetMembershipCheckProof {
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
        a: &PairingOutput<E>,
        D: &E::G1Affine,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        params.serialize_for_schnorr_protocol(&mut writer)?;
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        V.serialize_compressed(&mut writer)?;
        a.serialize_compressed(&mut writer)?;
        D.serialize_compressed(&mut writer)?;
        Ok(())
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
        // Check g * z_sigma + h * z_r - commitment * challenge == D
        if (comm_key.commit(&self.z_sigma, &self.z_r) + (commitment.into_group().neg() * challenge))
            .into_affine()
            != self.D
        {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        let params = params.into();
        // Check a == e(V, y) * challenge + e(V, g2) * z_sigma + e(g1, g2) * -z_v
        // => a == e(V, y*challenge + g2 * z_sigma) - e(g1, g2) * z_v
        // => a + e(g1, g2) * z_v == e(V, y*challenge + g2 * z_sigma)
        let lhs = self.a + (params.bb_sig_params.g1g2 * self.z_v);
        let rhs = E::pairing(
            E::G1Prepared::from(self.V),
            E::G2Prepared::from(
                (params.bb_pk.0 * challenge) + (params.bb_sig_params.g2 * self.z_sigma),
            ),
        );
        if lhs != rhs {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        SetMembershipCheckProtocol::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
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
        let protocol = SetMembershipCheckProtocol::init(
            &mut rng,
            member,
            randomness,
            &comm_key,
            params_with_pairing.clone(),
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(
                &commitment,
                &comm_key,
                params_with_pairing.clone(),
                &mut chal_bytes_prover,
            )
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
                params_with_pairing.clone(),
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
