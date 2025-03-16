//! Range proof protocol as described in section 4.4 of the paper [Efficient Protocols for Set Membership and Range Proofs](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15).
//! Considers an arbitrary range `[min, max)`. This essentially executes 2 instances of the protocol for perfect range `[0, u^l)`
//!
//! A difference with the paper is that a single `D` is created in the paper which can lead to the verifier learning that some digits
//! are same in values in those 2 protocols.
//!
//! Secondly, less number of digits are needed as `l` is chosen such that `max - min < u^l` rather than `max < u^l`.

use crate::{
    ccs_range_proof::util::{check_commitment_for_arbitrary_range, find_l_for_arbitrary_range},
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing,
    common::{padded_base_n_digits_as_field_elements, MemberCommitmentKey},
    error::SmcRangeProofError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, format, io::Write, ops::Mul, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    expect_equality, misc::n_rand, msm::WindowTable,
    randomized_pairing_check::RandomizedPairingChecker,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CCSArbitraryRangeProofProtocol<E: Pairing> {
    pub base: u16,
    pub digits_min: Vec<E::ScalarField>,
    pub digits_max: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub v_min: Vec<E::ScalarField>,
    pub v_max: Vec<E::ScalarField>,
    pub V_min: Vec<E::G1Affine>,
    pub V_max: Vec<E::G1Affine>,
    pub a_min: Vec<PairingOutput<E>>,
    pub a_max: Vec<PairingOutput<E>>,
    pub D_min: E::G1Affine,
    pub m_min: E::ScalarField,
    pub s_min: Vec<E::ScalarField>,
    pub D_max: E::G1Affine,
    pub m_max: E::ScalarField,
    pub s_max: Vec<E::ScalarField>,
    pub t_min: Vec<E::ScalarField>,
    pub t_max: Vec<E::ScalarField>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSArbitraryRangeProof<E: Pairing> {
    pub base: u16,
    pub V_min: Vec<E::G1Affine>,
    pub V_max: Vec<E::G1Affine>,
    pub a_min: Vec<PairingOutput<E>>,
    pub a_max: Vec<PairingOutput<E>>,
    pub D_min: E::G1Affine,
    pub D_max: E::G1Affine,
    pub z_v_min: Vec<E::ScalarField>,
    pub z_v_max: Vec<E::ScalarField>,
    pub z_sigma_min: Vec<E::ScalarField>,
    pub z_sigma_max: Vec<E::ScalarField>,
    pub z_r_min: E::ScalarField,
    pub z_r_max: E::ScalarField,
}

impl<E: Pairing> CCSArbitraryRangeProofProtocol<E> {
    /// Initialize the protocol for proving `min <= value < max`
    pub fn init<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        let params = params.into();
        Self::init_given_base(
            rng,
            value,
            randomness,
            min,
            max,
            params.get_max_base_for_range_proof(),
            comm_key,
            params,
        )
    }

    /// Initialize the protocol for proving `min <= value < max`
    pub fn init_given_base<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        min: u64,
        max: u64,
        base: u16,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
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

        let params = params.into();

        params.validate_base(base)?;

        let l = find_l_for_arbitrary_range(max, min, base) as usize;

        // Different randomizer vectors `s_min` and `s_max` are chosen to avoid leaking
        // the information that some digits are potentially same at the same indices, i.e
        // `z_sigma_min_i = z_sigma_max_i` if same `s_min` and `s_max` were used when `digits_min_i = digits_max_i`
        let m_min = E::ScalarField::rand(rng);
        let s_min = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D_min = comm_key.commit_decomposed(base, &s_min, &m_min);
        let m_max = E::ScalarField::rand(rng);
        let s_max = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D_max = comm_key.commit_decomposed(base, &s_max, &m_max);

        let digits_min = padded_base_n_digits_as_field_elements(value - min, base, l);
        let digits_max = padded_base_n_digits_as_field_elements(
            value + (base as u64).pow(l as u32) - max,
            base,
            l,
        );

        let t_min = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let t_max = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let v_min = n_rand(rng, l).collect::<Vec<_>>();
        let v_max = n_rand(rng, l).collect::<Vec<_>>();

        // Randomize all signatures. Different randomizer vectors `v_min` and `v_max` are chosen to avoid leaking
        // the information that some digits are potentially same at the same indices, i.e
        // `V_min_i = V_max_i` if same `v_min` and `v_max` were used when `A_min_i = A_max_i`

        // V_min_i = A_min * v_min_i
        let V_min = randomize_sigs!(&digits_min, &v_min, &params);
        // V_max_i = A_max * v_max_i
        let V_max = randomize_sigs!(&digits_max, &v_max, &params);

        let a_min = cfg_into_iter!(0..l)
            .map(|i| {
                E::pairing(
                    E::G1Prepared::from(V_min[i] * s_min[i]),
                    params.bb_sig_params.g2_prepared.clone(),
                ) + params.bb_sig_params.g1g2.mul(-t_min[i])
            })
            .collect::<Vec<_>>();
        let a_max = cfg_into_iter!(0..l)
            .map(|i| {
                E::pairing(
                    E::G1Prepared::from(V_max[i] * s_max[i]),
                    params.bb_sig_params.g2_prepared.clone(),
                ) + params.bb_sig_params.g1g2.mul(-t_max[i])
            })
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
            a_min,
            a_max,
            D_min,
            m_min,
            s_min,
            D_max,
            m_max,
            s_max,
            t_min,
            t_max,
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
            &self.V_min,
            &self.V_max,
            &self.a_min,
            &self.a_max,
            &self.D_min,
            &self.D_max,
            commitment,
            comm_key,
            params,
            writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSArbitraryRangeProof<E> {
        let z_v_min = cfg_into_iter!(0..self.V_min.len())
            .map(|i| self.t_min[i] + (self.v_min[i] * challenge))
            .collect::<Vec<_>>();
        let z_v_max = cfg_into_iter!(0..self.V_max.len())
            .map(|i| self.t_max[i] + (self.v_max[i] * challenge))
            .collect::<Vec<_>>();
        let z_sigma_min = cfg_into_iter!(0..self.V_min.len())
            .map(|i| self.s_min[i] + (self.digits_min[i] * challenge))
            .collect::<Vec<_>>();
        let z_sigma_max = cfg_into_iter!(0..self.V_max.len())
            .map(|i| self.s_max[i] + (self.digits_max[i] * challenge))
            .collect::<Vec<_>>();
        let z_r_min = self.m_min + (self.r * challenge);
        let z_r_max = self.m_max + (self.r * challenge);
        CCSArbitraryRangeProof {
            base: self.base,
            V_min: self.V_min,
            V_max: self.V_max,
            a_min: self.a_min,
            a_max: self.a_max,
            D_min: self.D_min,
            D_max: self.D_max,
            z_v_min,
            z_v_max,
            z_sigma_min,
            z_sigma_max,
            z_r_min,
            z_r_max,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        V_min: &[E::G1Affine],
        V_max: &[E::G1Affine],
        a_min: &[PairingOutput<E>],
        a_max: &[PairingOutput<E>],
        D_min: &E::G1Affine,
        D_max: &E::G1Affine,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        params.serialize_for_schnorr_protocol(&mut writer)?;
        comm_key.serialize_compressed(&mut writer)?;
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
        D_min.serialize_compressed(&mut writer)?;
        D_max.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> CCSArbitraryRangeProof<E> {
    /// Verify the proof for `min <= value < max` where `commitment` is a Pedersen commitment to `value`
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        self.verify_except_pairings(commitment, challenge, min, max, comm_key, &params)?;

        let (yc_sigma_min, yc_sigma_max, lhs_min, lhs_max) =
            self.compute_for_pairing_check(challenge, &params);

        if cfg_into_iter!(0..self.V_min.len())
            .map(|i| {
                let rhs = E::pairing(
                    E::G1Prepared::from(self.V_min[i]),
                    E::G2Prepared::from(yc_sigma_min[i]),
                );
                if lhs_min[i] != rhs {
                    return false;
                }
                let rhs = E::pairing(
                    E::G1Prepared::from(self.V_max[i]),
                    E::G2Prepared::from(yc_sigma_max[i]),
                );
                if lhs_max[i] != rhs {
                    return false;
                }
                return true;
            })
            .any(|r| r == false)
        {
            return Err(SmcRangeProofError::InvalidRangeProof);
        }

        Ok(())
    }

    /// Verify the proof for `min <= value < max` where `commitment` is a Pedersen commitment to `value`
    pub fn verify_given_randomized_pairing_checker(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        self.verify_except_pairings(commitment, challenge, min, max, comm_key, &params)?;
        let (yc_sigma_min, yc_sigma_max, lhs_min, lhs_max) =
            self.compute_for_pairing_check(challenge, &params);

        for i in 0..self.V_min.len() {
            pairing_checker.add_multiple_sources_and_target(
                &[self.V_min[i]],
                &[yc_sigma_min[i]],
                &lhs_min[i],
            );
            pairing_checker.add_multiple_sources_and_target(
                &[self.V_max[i]],
                &[yc_sigma_max[i]],
                &lhs_max[i],
            );
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
        CCSArbitraryRangeProofProtocol::compute_challenge_contribution(
            &self.V_min,
            &self.V_max,
            &self.a_min,
            &self.a_max,
            &self.D_min,
            &self.D_max,
            commitment,
            comm_key,
            params,
            writer,
        )
    }

    pub fn verify_except_pairings(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> Result<(), SmcRangeProofError> {
        if min >= max {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "min={} should be < max={}",
                min, max
            )));
        }
        params.validate_base(self.base)?;
        let l = find_l_for_arbitrary_range(max, min, self.base) as usize;
        expect_equality!(
            self.V_min.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.V_max.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.a_min.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.a_max.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.z_sigma_min.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.z_sigma_max.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        check_commitment_for_arbitrary_range::<E::G1Affine>(
            self.base,
            &self.z_sigma_min,
            &self.z_sigma_max,
            &self.z_r_min,
            &self.z_r_max,
            &self.D_min,
            &self.D_max,
            min,
            max,
            commitment,
            challenge,
            comm_key,
        )
    }

    fn compute_for_pairing_check(
        &self,
        challenge: &E::ScalarField,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> (
        Vec<E::G2>,
        Vec<E::G2>,
        Vec<PairingOutput<E>>,
        Vec<PairingOutput<E>>,
    ) {
        // y * c
        let yc = params.bb_pk.0 * challenge;

        let table = WindowTable::new(
            core::cmp::max(self.z_sigma_min.len(), self.z_sigma_max.len()),
            params.bb_sig_params.g2.into_group(),
        );
        // g2 * z_sigma_min
        let g2_z_sigma_min = table.multiply_many(&self.z_sigma_min);
        // g2 * z_sigma_max
        let g2_z_sigma_max = table.multiply_many(&self.z_sigma_max);

        let lhs_min = cfg_into_iter!(0..self.V_min.len())
            .map(|i| self.a_min[i] + (params.bb_sig_params.g1g2 * self.z_v_min[i]))
            .collect::<Vec<_>>();
        let lhs_max = cfg_into_iter!(0..self.V_max.len())
            .map(|i| self.a_max[i] + (params.bb_sig_params.g1g2 * self.z_v_max[i]))
            .collect::<Vec<_>>();
        let yc_sigma_min = cfg_into_iter!(0..g2_z_sigma_min.len())
            .map(|i| yc + g2_z_sigma_min[i])
            .collect::<Vec<_>>();
        let yc_sigma_max = cfg_into_iter!(0..g2_z_sigma_max.len())
            .map(|i| yc + g2_z_sigma_max[i])
            .collect::<Vec<_>>();

        (yc_sigma_min, yc_sigma_max, lhs_min, lhs_max)
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

        for base in [2, 4, 8, 10, 13, 16] {
            let mut proving_time = Duration::default();
            let mut verifying_time = Duration::default();
            let mut verifying_with_rpc_time = Duration::default();
            let mut num_proofs = 0;
            let mut proof_size = 0;

            let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
            params_with_pairing.verify().unwrap();

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

                // Params with smaller base should fail
                let params_with_smaller_base = {
                    let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base - 1);
                    SetMembershipCheckParamsWithPairing::from(params.clone())
                };
                assert!(CCSArbitraryRangeProofProtocol::init_given_base(
                    &mut rng,
                    value,
                    randomness,
                    min,
                    max,
                    base,
                    &comm_key,
                    params_with_smaller_base,
                )
                .is_err());

                // min > max should fail
                assert!(CCSArbitraryRangeProofProtocol::init_given_base(
                    &mut rng,
                    value,
                    randomness,
                    max,
                    min,
                    base,
                    &comm_key,
                    params_with_pairing.clone(),
                )
                .is_err());

                // Params with larger base should work
                let params_with_larger_base = {
                    let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base + 1);
                    SetMembershipCheckParamsWithPairing::from(params.clone())
                };

                for params in [params_with_pairing.clone(), params_with_larger_base] {
                    let start = Instant::now();
                    let protocol = CCSArbitraryRangeProofProtocol::init_given_base(
                        &mut rng,
                        value,
                        randomness,
                        min,
                        max,
                        base,
                        &comm_key,
                        params.clone(),
                    )
                    .unwrap();

                    let mut chal_bytes_prover = vec![];
                    protocol
                        .challenge_contribution(
                            &commitment,
                            &comm_key,
                            params.clone(),
                            &mut chal_bytes_prover,
                        )
                        .unwrap();
                    let challenge_prover =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

                    let proof = protocol.gen_proof(&challenge_prover);
                    proving_time += start.elapsed();
                    // assert_eq!(proof.V.len(), l as usize);

                    let start = Instant::now();
                    let mut chal_bytes_verifier = vec![];
                    proof
                        .challenge_contribution(
                            &commitment,
                            &comm_key,
                            params.clone(),
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
                            min,
                            max,
                            &comm_key,
                            params.clone(),
                        )
                        .unwrap();
                    verifying_time += start.elapsed();

                    let start = Instant::now();
                    let mut pairing_checker =
                        RandomizedPairingChecker::new_using_rng(&mut rng, true);
                    proof
                        .verify_given_randomized_pairing_checker(
                            &commitment,
                            &challenge_verifier,
                            min,
                            max,
                            &comm_key,
                            params.clone(),
                            &mut pairing_checker,
                        )
                        .unwrap();
                    assert!(pairing_checker.verify());
                    verifying_with_rpc_time += start.elapsed();

                    let mut bytes = vec![];
                    proof.serialize_compressed(&mut bytes).unwrap();
                    proof_size = bytes.len();

                    num_proofs += 1;
                }
            }

            println!("For base={} and {} proofs, proof size = {}, average proving time={:?}, average verifying time={:?} and average verifying time using randomized pairing checker={:?}", base, num_proofs, proof_size, proving_time/num_proofs, verifying_time/num_proofs, verifying_with_rpc_time/num_proofs);
        }
    }
}
