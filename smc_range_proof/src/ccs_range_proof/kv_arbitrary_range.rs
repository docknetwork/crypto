//! Same as CCS arbitrary range proof protocol but does Keyed-Verification, i.e the verifies knows the
//! secret key of the BB-sig

use crate::{
    bb_sig::SecretKey, ccs_set_membership::setup::SetMembershipCheckParams,
    common::MemberCommitmentKey, error::SmcRangeProofError,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, format, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::misc::n_rand;

use crate::ccs_range_proof::util::{check_commitment_for_arbitrary_range, find_l_greater_than};
use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::common::padded_base_n_digits_as_field_elements;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSArbitraryRangeProofWithKVProtocol<E: Pairing> {
    pub base: u16,
    pub digits_min: Vec<E::ScalarField>,
    pub digits_max: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub v_min: Vec<E::ScalarField>,
    pub v_max: Vec<E::ScalarField>,
    pub V_min: Vec<E::G1Affine>,
    pub V_max: Vec<E::G1Affine>,
    pub a_min: Vec<E::G1Affine>,
    pub a_max: Vec<E::G1Affine>,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
    pub s: Vec<E::ScalarField>,
    pub t_min: Vec<E::ScalarField>,
    pub t_max: Vec<E::ScalarField>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSArbitraryRangeWithKVProof<E: Pairing> {
    pub base: u16,
    pub V_min: Vec<E::G1Affine>,
    pub V_max: Vec<E::G1Affine>,
    pub a_min: Vec<E::G1Affine>,
    pub a_max: Vec<E::G1Affine>,
    pub D: E::G1Affine,
    pub z_v_min: Vec<E::ScalarField>,
    pub z_v_max: Vec<E::ScalarField>,
    pub z_sigma_min: Vec<E::ScalarField>,
    pub z_sigma_max: Vec<E::ScalarField>,
    pub z_r: E::ScalarField,
}

impl<E: Pairing> CCSArbitraryRangeProofWithKVProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        Self::init_given_base(
            rng,
            value,
            randomness,
            min,
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
        min: u64,
        max: u64,
        base: u16,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<Self, SmcRangeProofError> {
        if min > value {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "value={} should be >= min={}",
                value, min
            )));
        }
        if value >= max {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "value={} should be < max={}",
                value, max
            )));
        }

        params.validate_base(base)?;

        let l = find_l_greater_than(max, base) as usize;

        let m = E::ScalarField::rand(rng);
        let s = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D = comm_key.commit_decomposed(base, &s, &m);

        let digits_min = padded_base_n_digits_as_field_elements(value - min, base, l);
        let digits_max = padded_base_n_digits_as_field_elements(
            value + (base as u64).pow(l as u32) - max,
            base,
            l,
        );

        let t_min = n_rand(rng, l).collect::<Vec<_>>();
        let t_max = n_rand(rng, l).collect::<Vec<_>>();
        let v_min = n_rand(rng, l).collect::<Vec<_>>();
        let v_max = n_rand(rng, l).collect::<Vec<_>>();

        // Randomize all signatures. Different randomizer vectors `v_min` and `v_max` are chosen to avoid leaking
        // the information that some digits are potentially same at the same indices, i.e
        // `V_min_i = V_max_i` if same `v_min` and `v_min` were used when `A_min_i = A_max_i`

        // V_min_i = A_min * v_min_i
        let V_min = randomize_sigs!(&digits_min, &v_min, &params);
        // V_max_i = A_max * v_max_i
        let V_max = randomize_sigs!(&digits_max, &v_max, &params);

        let g = params.bb_sig_params.g1.into_group();
        // g * t_min_i
        let g1t_min = multiply_field_elems_with_same_group_elem(g.clone(), &t_min);
        // g * t_max_i
        let g1t_max = multiply_field_elems_with_same_group_elem(g, &t_max);

        let a_min = cfg_into_iter!(0..l)
            .map(|i| (V_min[i] * -s[i]) + g1t_min[i])
            .collect::<Vec<_>>();
        let a_max = cfg_into_iter!(0..l)
            .map(|i| (V_max[i] * -s[i]) + g1t_max[i])
            .collect::<Vec<_>>();

        Ok(Self {
            base,
            digits_min,
            digits_max,
            r: randomness,
            v_min,
            v_max,
            V_min: E::G1::normalize_batch(&V_min),
            V_max: E::G1::normalize_batch(&V_max),
            a_min: E::G1::normalize_batch(&a_min),
            a_max: E::G1::normalize_batch(&a_max),
            D,
            m,
            s,
            t_min,
            t_max,
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
            &self.V_min,
            &self.V_max,
            &self.a_min,
            &self.a_max,
            &self.D,
            commitment,
            comm_key,
            params,
            writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSArbitraryRangeWithKVProof<E> {
        gen_proof_arbitrary_range!(self, challenge, CCSArbitraryRangeWithKVProof)
    }

    pub fn compute_challenge_contribution<W: Write>(
        V_min: &[E::G1Affine],
        V_max: &[E::G1Affine],
        a_min: &[E::G1Affine],
        a_max: &[E::G1Affine],
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
        for V_i in V_min {
            V_i.serialize_compressed(&mut writer)?;
        }
        for V_i in V_max {
            V_i.serialize_compressed(&mut writer)?;
        }
        for a_i in a_min {
            a_i.serialize_compressed(&mut writer)?;
        }
        for a_i in a_max {
            a_i.serialize_compressed(&mut writer)?;
        }
        D.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> CCSArbitraryRangeWithKVProof<E> {
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        secret_key: &SecretKey<E::ScalarField>,
    ) -> Result<(), SmcRangeProofError> {
        self.non_crypto_validate(min, max, &params)?;
        check_commitment_for_arbitrary_range::<E>(
            self.base,
            &self.z_sigma_min,
            &self.z_sigma_max,
            &self.z_r,
            &self.D,
            min,
            max,
            commitment,
            challenge,
            comm_key,
        )?;

        let g1 = params.bb_sig_params.g1.into_group();
        let g1v_min = multiply_field_elems_with_same_group_elem(g1.clone(), &self.z_v_min);
        let g1v_max = multiply_field_elems_with_same_group_elem(g1, &self.z_v_max);

        for i in 0..self.V_min.len() {
            if self.a_min[i]
                != (self.V_min[i] * (secret_key.0 * challenge - self.z_sigma_min[i]) + g1v_min[i])
                    .into_affine()
            {
                return Err(SmcRangeProofError::InvalidRangeProof);
            }
            if self.a_max[i]
                != (self.V_max[i] * (secret_key.0 * challenge - self.z_sigma_max[i]) + g1v_max[i])
                    .into_affine()
            {
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
        CCSArbitraryRangeProofWithKVProtocol::compute_challenge_contribution(
            &self.V_min,
            &self.V_max,
            &self.a_min,
            &self.a_max,
            &self.D,
            commitment,
            comm_key,
            params,
            writer,
        )
    }

    fn non_crypto_validate(
        &self,
        min: u64,
        max: u64,
        params: &SetMembershipCheckParams<E>,
    ) -> Result<(), SmcRangeProofError> {
        if min >= max {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "min={} should be < max={}",
                min, max
            )));
        }
        params.validate_base(self.base)?;
        let l = find_l_greater_than(max, self.base) as usize;
        assert_eq!(self.V_min.len(), l);
        assert_eq!(self.V_max.len(), l);
        assert_eq!(self.a_min.len(), l);
        assert_eq!(self.a_max.len(), l);
        assert_eq!(self.z_sigma_min.len(), l);
        assert_eq!(self.z_sigma_max.len(), l);
        Ok(())
    }
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
    use std::time::{Duration, Instant};

    #[test]
    fn range_proof_for_arbitrary_range() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let mut proving_time = Duration::default();
        let mut verifying_time = Duration::default();
        let mut num_proofs = 0;

        for base in [2, 4, 8, 16] {
            let (params, sk) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for _ in 0..5 {
                let shift = base.ilog2();
                let mut a = [
                    u64::rand(&mut rng) >> shift,
                    u64::rand(&mut rng) >> shift,
                    u64::rand(&mut rng) >> shift,
                ];
                // let mut a = [
                //     u16::rand(&mut rng) as u64,
                //     u16::rand(&mut rng) as u64,
                //     u16::rand(&mut rng) as u64,
                // ];
                a.sort();
                let min = a[0];
                let max = a[2];
                let value = a[1];
                assert!(value >= min);
                assert!(value < max);
                let randomness = Fr::rand(&mut rng);
                let commitment = comm_key.commit(&Fr::from(value), &randomness);

                // Params with incorrect base should fail
                let params_with_smaller_base = {
                    let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base - 1);
                    params.verify().unwrap();
                    params
                };
                assert!(CCSArbitraryRangeProofWithKVProtocol::init_given_base(
                    &mut rng,
                    value,
                    randomness,
                    min,
                    max,
                    base,
                    &comm_key,
                    &params_with_smaller_base,
                )
                .is_err());

                // min > max should fail
                assert!(CCSArbitraryRangeProofWithKVProtocol::init_given_base(
                    &mut rng, value, randomness, max, min, base, &comm_key, &params,
                )
                .is_err());

                // Params with larger base should work
                let (params_with_larger_base, sk_larger) = {
                    let (params, sk) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base + 1);
                    params.verify().unwrap();
                    (params, sk)
                };

                for (p, sk) in [(&params, &sk), (&params_with_larger_base, &sk_larger)] {
                    let start = Instant::now();
                    let protocol = CCSArbitraryRangeProofWithKVProtocol::init_given_base(
                        &mut rng, value, randomness, min, max, base, &comm_key, p,
                    )
                    .unwrap();

                    let mut chal_bytes_prover = vec![];
                    protocol
                        .challenge_contribution(&commitment, &comm_key, p, &mut chal_bytes_prover)
                        .unwrap();
                    let challenge_prover =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

                    let proof = protocol.gen_proof(&challenge_prover);
                    proving_time += start.elapsed();
                    // assert_eq!(proof.V.len(), l as usize);

                    let start = Instant::now();
                    let mut chal_bytes_verifier = vec![];
                    proof
                        .challenge_contribution(&commitment, &comm_key, p, &mut chal_bytes_verifier)
                        .unwrap();
                    let challenge_verifier =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
                    assert_eq!(challenge_prover, challenge_verifier);

                    proof
                        .verify(&commitment, &challenge_verifier, min, max, &comm_key, p, sk)
                        .unwrap();
                    verifying_time += start.elapsed();

                    num_proofs += 1;
                }
            }
        }

        println!(
            "For {} proofs, proving_time={:?} and verifying_time={:?}",
            num_proofs, proving_time, verifying_time
        );
    }
}
