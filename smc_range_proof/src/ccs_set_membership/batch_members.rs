//! Check membership of a batch of elements in the set

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
    cfg_into_iter,
    io::Write,
    ops::{Mul, Neg},
    rand::RngCore,
    vec::Vec,
};
use dock_crypto_utils::misc::n_rand;

use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetMembershipBatchCheckProtocol<E: Pairing> {
    pub members: Vec<E::ScalarField>,
    pub r: Vec<E::ScalarField>,
    pub v: Vec<E::ScalarField>,
    pub V: Vec<E::G1Affine>,
    pub a: Vec<PairingOutput<E>>,
    pub D: Vec<E::G1Affine>,
    pub m: Vec<E::ScalarField>,
    pub s: Vec<E::ScalarField>,
    pub t: Vec<E::ScalarField>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipBatchCheckProof<E: Pairing> {
    pub V: Vec<E::G1Affine>,
    pub a: Vec<PairingOutput<E>>,
    pub D: Vec<E::G1Affine>,
    pub z_v: Vec<E::ScalarField>,
    pub z_sigma: Vec<E::ScalarField>,
    pub z_r: Vec<E::ScalarField>,
}

impl<E: Pairing> SetMembershipBatchCheckProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        members: Vec<E::ScalarField>,
        r: Vec<E::ScalarField>,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        assert_eq!(members.len(), r.len());
        let params = params.into();
        let v = n_rand(rng, members.len()).collect::<Vec<_>>();
        let V = randomize_sigs!(&members, &v, &params);
        let m = n_rand(rng, members.len()).collect::<Vec<E::ScalarField>>();
        let s = n_rand(rng, members.len()).collect::<Vec<E::ScalarField>>();
        let t = n_rand(rng, members.len()).collect::<Vec<E::ScalarField>>();

        // Note: This can be optimized for larger batches by using a table of comm_key elements
        let D = cfg_into_iter!(0..members.len())
            .map(|i| comm_key.commit(&s[i], &m[i]))
            .collect::<Vec<_>>();
        let a = cfg_into_iter!(0..members.len())
            .map(|i| {
                E::pairing(
                    E::G1Prepared::from(V[i] * s[i]),
                    params.bb_sig_params.g2_prepared.clone(),
                ) + params.bb_sig_params.g1g2.mul(-t[i])
            })
            .collect::<Vec<_>>();
        Ok(Self {
            members,
            r,
            v,
            V: E::G1::normalize_batch(&V),
            a,
            D,
            m,
            s,
            t,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitments: &[E::G1Affine],
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        Self::compute_challenge_contribution(
            &self.V,
            &self.a,
            &self.D,
            commitments,
            comm_key,
            params,
            writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> SetMembershipBatchCheckProof<E> {
        let z_v = cfg_into_iter!(0..self.V.len())
            .map(|i| self.t[i] + (self.v[i] * challenge))
            .collect::<Vec<_>>();
        let z_sigma = cfg_into_iter!(0..self.V.len())
            .map(|i| self.s[i] + (self.members[i] * challenge))
            .collect::<Vec<_>>();
        let z_r = cfg_into_iter!(0..self.V.len())
            .map(|i| self.m[i] + (self.r[i] * challenge))
            .collect::<Vec<_>>();
        SetMembershipBatchCheckProof {
            V: self.V,
            a: self.a,
            D: self.D,
            z_v,
            z_sigma,
            z_r,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        V: &[E::G1Affine],
        a: &[PairingOutput<E>],
        D: &[E::G1Affine],
        commitments: &[E::G1Affine],
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        params.serialize_for_schnorr_protocol(&mut writer)?;
        comm_key.serialize_compressed(&mut writer)?;
        for sig in &params.sigs {
            sig.0.serialize_compressed(&mut writer)?;
        }
        for comm in commitments {
            comm.serialize_compressed(&mut writer)?;
        }
        for V_i in V {
            V_i.serialize_compressed(&mut writer)?;
        }
        for a_i in a {
            a_i.serialize_compressed(&mut writer)?;
        }
        D.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> SetMembershipBatchCheckProof<E> {
    pub fn verify(
        &self,
        commitments: &[E::G1Affine],
        challenge: &E::ScalarField,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        // TODO: Check size of vectors in proof
        assert_eq!(self.V.len(), commitments.len());
        assert_eq!(self.a.len(), commitments.len());
        assert_eq!(self.z_v.len(), commitments.len());
        assert_eq!(self.z_sigma.len(), commitments.len());

        // Note: Following can be optimized for larger batches by taking a random linear combination of the following
        for i in 0..commitments.len() {
            if (comm_key.commit(&self.z_sigma[i], &self.z_r[i])
                + (commitments[i].into_group().neg() * challenge))
                .into_affine()
                != self.D[i]
            {
                return Err(SmcRangeProofError::InvalidSetMembershipProof);
            }
        }

        // y * c
        let yc = params.bb_pk.0 * challenge;
        // g2 * z_sigma
        let g2_z_sigma = multiply_field_elems_with_same_group_elem(
            params.bb_sig_params.g2.into_group(),
            &self.z_sigma,
        );

        // TODO: Allow verifying with randomized pairing checker
        for i in 0..commitments.len() {
            let lhs = self.a[i] + (params.bb_sig_params.g1g2 * self.z_v[i]);
            let rhs = E::pairing(
                E::G1Prepared::from(self.V[i]),
                E::G2Prepared::from(yc + g2_z_sigma[i]),
            );
            if lhs != rhs {
                return Err(SmcRangeProofError::InvalidSetMembershipProof);
            }
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitments: &[E::G1Affine],
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        SetMembershipBatchCheckProtocol::compute_challenge_contribution(
            &self.V,
            &self.a,
            &self.D,
            commitments,
            comm_key,
            params,
            writer,
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
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use dock_crypto_utils::misc::n_rand;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::Instant;

    #[test]
    fn membership_batch_check() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let set_size = 20;
        let batch_size = 10;

        let set = n_rand(&mut rng, set_size).collect::<Vec<_>>();
        let (params, _) = SetMembershipCheckParams::<Bls12_381>::new::<_, Blake2b512>(
            &mut rng,
            b"test",
            set.clone(),
        );
        params.verify().unwrap();

        let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
        params_with_pairing.verify().unwrap();

        let comm_key = MemberCommitmentKey::generate_using_rng(&mut rng);

        let members = (0..batch_size).map(|i| set[i]).collect::<Vec<_>>();
        let randomness = n_rand(&mut rng, batch_size).collect::<Vec<_>>();
        let commitments = (0..batch_size)
            .map(|i| comm_key.commit(&members[i], &randomness[i]))
            .collect::<Vec<_>>();

        let protocol = SetMembershipBatchCheckProtocol::init(
            &mut rng,
            members,
            randomness,
            &comm_key,
            params_with_pairing.clone(),
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(
                &commitments,
                &comm_key,
                params_with_pairing.clone(),
                &mut chal_bytes_prover,
            )
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(
                &commitments,
                &comm_key,
                params_with_pairing.clone(),
                &mut chal_bytes_verifier,
            )
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        let start = Instant::now();
        proof
            .verify(
                &commitments,
                &challenge_verifier,
                &comm_key,
                params_with_pairing.clone(),
            )
            .unwrap();
        println!("Time to verify={:?}", start.elapsed());
    }
}
