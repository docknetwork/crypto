//! Same as CCS perfect range proof protocol but does Keyed-Verification, i.e the verifies knows the
//! secret key of the BB-sig

use crate::{
    bb_sig::SecretKey, ccs_set_membership::setup::SetMembershipCheckParams,
    common::MemberCommitmentKey, error::SmcRangeProofError,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{misc::n_rand, msm::multiply_field_elems_with_same_group_elem};

use crate::common::padded_base_n_digits_as_field_elements;

use crate::ccs_range_proof::util::check_commitment_for_prefect_range;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSPerfectRangeProofWithKVProtocol<E: Pairing> {
    pub base: u16,
    pub digits: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub v: Vec<E::ScalarField>,
    pub V: Vec<E::G1Affine>,
    pub a: Vec<E::G1Affine>,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
    pub s: Vec<E::ScalarField>,
    pub t: Vec<E::ScalarField>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSPerfectRangeWithKVProof<E: Pairing> {
    pub base: u16,
    pub V: Vec<E::G1Affine>,
    pub a: Vec<E::G1Affine>,
    pub D: E::G1Affine,
    pub z_v: Vec<E::ScalarField>,
    pub z_sigma: Vec<E::ScalarField>,
    pub z_r: E::ScalarField,
}

impl<E: Pairing> CCSPerfectRangeProofWithKVProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        Self::init_given_base(
            rng,
            value,
            randomness,
            max,
            params.get_supported_base_for_range_proof(),
            comm_key,
            params,
        )
    }

    pub fn init_given_base<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        max: u64,
        base: u16,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        params.validate_base(base)?;

        let l = find_l(max, base) as usize;

        // Note: This is different from the paper as only a single `m` needs to be created.
        let m = E::ScalarField::rand(rng);
        let s = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D = comm_key.commit_decomposed(base, &s, &m);

        let digits = padded_base_n_digits_as_field_elements(value, base, l);
        let t = n_rand(rng, l).collect::<Vec<_>>();
        let v = n_rand(rng, l).collect::<Vec<_>>();
        let V = randomize_sigs!(&digits, &v, &params);
        let g1t =
            multiply_field_elems_with_same_group_elem(params.bb_sig_params.g1.into_group(), &t);
        let a = cfg_into_iter!(0..l)
            .map(|i| (V[i] * -s[i]) + g1t[i])
            .collect::<Vec<_>>();
        Ok(Self {
            base,
            digits,
            r: randomness,
            v,
            V: E::G1::normalize_batch(&V),
            a: E::G1::normalize_batch(&a),
            D,
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

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSPerfectRangeWithKVProof<E> {
        gen_proof_perfect_range!(self, challenge, CCSPerfectRangeWithKVProof)
    }

    pub fn compute_challenge_contribution<W: Write>(
        V: &[E::G1Affine],
        a: &[E::G1Affine],
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

impl<E: Pairing> CCSPerfectRangeWithKVProof<E> {
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        secret_key: &SecretKey<E::ScalarField>,
    ) -> Result<(), SmcRangeProofError> {
        self.non_crypto_validate(max, &params)?;
        check_commitment_for_prefect_range::<E>(
            self.base,
            &self.z_sigma,
            &self.z_r,
            &self.D,
            commitment,
            challenge,
            comm_key,
        )?;

        let g1v = multiply_field_elems_with_same_group_elem(
            params.bb_sig_params.g1.into_group(),
            &self.z_v,
        );

        let sk_c = secret_key.0 * challenge;
        for i in 0..self.V.len() {
            // Check a[i] == V[i] * (challenge * secret_key - z_sigma[i]) + g1 * z_v[i]
            if self.a[i] != (self.V[i] * (sk_c - self.z_sigma[i]) + g1v[i]).into_affine() {
                return Err(SmcRangeProofError::InvalidRangeProof);
            }
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
        CCSPerfectRangeProofWithKVProtocol::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    fn non_crypto_validate(
        &self,
        max: u64,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<(), SmcRangeProofError> {
        params.validate_base(self.base)?;
        let l = find_l(max, self.base) as usize;
        assert_eq!(self.V.len(), l);
        assert_eq!(self.a.len(), l);
        assert_eq!(self.z_v.len(), l);
        assert_eq!(self.z_sigma.len(), l);
        Ok(())
    }
}

fn find_l(max: u64, base: u16) -> u16 {
    let l = max.ilog(base as u64);
    let power = (base as u64).pow(l);
    assert_eq!(power, max);
    l as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs_set_membership::setup::SetMembershipCheckParams;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn range_proof_for_perfect_range() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for base in [2, 4, 8, 16] {
            let (params, sk) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for _ in 0..5 {
                for l in [10, 15] {
                    // TODO: Combine base and l in outer for loop
                    let max = (base as u64).pow(l);
                    let value = u64::rand(&mut rng) % max;
                    assert!(value < max);
                    let randomness = Fr::rand(&mut rng);
                    let commitment = comm_key.commit(&Fr::from(value), &randomness);
                    let protocol = CCSPerfectRangeProofWithKVProtocol::init_given_base(
                        &mut rng, value, randomness, max, base, &comm_key, &params,
                    )
                    .unwrap();

                    let mut chal_bytes_prover = vec![];
                    protocol
                        .challenge_contribution(
                            &commitment,
                            &comm_key,
                            &params,
                            &mut chal_bytes_prover,
                        )
                        .unwrap();
                    let challenge_prover =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

                    let proof = protocol.gen_proof(&challenge_prover);

                    let mut chal_bytes_verifier = vec![];
                    proof
                        .challenge_contribution(
                            &commitment,
                            &comm_key,
                            &params,
                            &mut chal_bytes_verifier,
                        )
                        .unwrap();
                    let challenge_verifier =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
                    assert_eq!(challenge_prover, challenge_verifier);

                    assert_eq!(proof.V.len(), l as usize);
                    proof
                        .verify(
                            &commitment,
                            &challenge_verifier,
                            max,
                            &comm_key,
                            &params,
                            &sk,
                        )
                        .unwrap();
                }
            }
        }
    }
}
