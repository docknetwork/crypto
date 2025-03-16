//! Range proof protocol as described in Fig.3 of the paper [Efficient Protocols for Set Membership and Range Proofs](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15).
//! Considers a perfect-range, i.e. range of the form `[0, u^l)` where `u` is the base and the upper bound is a power of the base.
//! The calculations are changed a bit to be consistent with other instances of Schnorr protocol in this project.

use crate::{
    ccs_range_proof::util::{check_commitment_for_prefect_range, find_l_for_perfect_range},
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing,
    common::{padded_base_n_digits_as_field_elements, MemberCommitmentKey},
    error::SmcRangeProofError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, io::Write, ops::Mul, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    expect_equality, misc::n_rand, msm::multiply_field_elems_with_same_group_elem,
    randomized_pairing_check::RandomizedPairingChecker,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CCSPerfectRangeProofProtocol<E: Pairing> {
    pub base: u16,
    pub digits: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub v: Vec<E::ScalarField>,
    pub V: Vec<E::G1Affine>,
    pub a: Vec<PairingOutput<E>>,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
    pub s: Vec<E::ScalarField>,
    pub t: Vec<E::ScalarField>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSPerfectRangeProof<E: Pairing> {
    pub base: u16,
    pub V: Vec<E::G1Affine>,
    pub a: Vec<PairingOutput<E>>,
    pub D: E::G1Affine,
    pub z_v: Vec<E::ScalarField>,
    pub z_sigma: Vec<E::ScalarField>,
    pub z_r: E::ScalarField,
}

impl<E: Pairing> CCSPerfectRangeProofProtocol<E> {
    /// Initialize the protocol for proving `0 <= value < max`
    pub fn init<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        let params = params.into();
        Self::init_given_base(
            rng,
            value,
            randomness,
            max,
            params.get_max_base_for_range_proof(),
            comm_key,
            params,
        )
    }

    /// Initialize the protocol for proving `0 <= value < max`
    pub fn init_given_base<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: E::ScalarField,
        max: u64,
        base: u16,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        let params = params.into();

        params.validate_base(base)?;

        let l = find_l_for_perfect_range(max, base)? as usize;

        // Note: This is different from the paper as only a single `m` needs to be created.
        let m = E::ScalarField::rand(rng);
        let s = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D = comm_key.commit_decomposed(base, &s, &m);

        let digits = padded_base_n_digits_as_field_elements(value, base, l);
        let t = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let v = n_rand(rng, l).collect::<Vec<_>>();
        let V = randomize_sigs!(&digits, &v, &params);
        // Following is different from the paper, the paper has `-s` and `t` but here its opposite
        let a = cfg_into_iter!(0..l)
            .map(|i| {
                E::pairing(
                    E::G1Prepared::from(V[i] * s[i]),
                    params.bb_sig_params.g2_prepared.clone(),
                ) + params.bb_sig_params.g1g2.mul(-t[i])
            })
            .collect::<Vec<_>>();
        Ok(Self {
            base,
            digits,
            r: randomness,
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
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        Self::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSPerfectRangeProof<E> {
        // Following is different from the paper, the paper has `-` but here its `+`
        let z_v = cfg_into_iter!(0..self.V.len())
            .map(|i| self.t[i] + (self.v[i] * challenge))
            .collect::<Vec<_>>();
        let z_sigma = cfg_into_iter!(0..self.V.len())
            .map(|i| self.s[i] + (self.digits[i] * challenge))
            .collect::<Vec<_>>();
        let z_r = self.m + (self.r * challenge);
        CCSPerfectRangeProof {
            base: self.base,
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

impl<E: Pairing> CCSPerfectRangeProof<E> {
    /// Verify the proof for `0 <= value < max` where `commitment` is a Pedersen commitment to `value`
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        self.verify_except_pairings(commitment, challenge, max, comm_key, &params)?;

        let (yc_sigma, lhs) = self.compute_for_pairing_check(challenge, &params);
        if cfg_into_iter!(0..self.V.len())
            .map(|i| {
                let rhs = E::pairing(
                    E::G1Prepared::from(self.V[i]),
                    E::G2Prepared::from(yc_sigma[i]),
                );
                lhs[i] == rhs
            })
            .any(|r| r == false)
        {
            return Err(SmcRangeProofError::InvalidRangeProof);
        }
        Ok(())
    }

    /// Verify the proof for `0 <= value < max` where `commitment` is a Pedersen commitment to `value`
    pub fn verify_given_randomized_pairing_checker(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
        self.verify_except_pairings(commitment, challenge, max, comm_key, &params)?;

        let (yc_sigma, lhs) = self.compute_for_pairing_check(challenge, &params);

        for i in 0..self.V.len() {
            pairing_checker.add_multiple_sources_and_target(&[self.V[i]], &[yc_sigma[i]], &lhs[i]);
        }
        Ok(())
    }

    pub fn verify_except_pairings(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> Result<(), SmcRangeProofError> {
        params.validate_base(self.base)?;
        let l = find_l_for_perfect_range(max, self.base)? as usize;

        expect_equality!(
            self.V.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.a.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.z_v.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.z_sigma.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        check_commitment_for_prefect_range::<E::G1Affine>(
            self.base,
            &self.z_sigma,
            &self.z_r,
            &self.D,
            commitment,
            challenge,
            comm_key,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        writer: W,
    ) -> Result<(), SmcRangeProofError> {
        CCSPerfectRangeProofProtocol::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    fn compute_for_pairing_check(
        &self,
        challenge: &E::ScalarField,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> (Vec<E::G2>, Vec<PairingOutput<E>>) {
        // y * c
        let yc = params.bb_pk.0 * challenge;
        // g2_z_sigma_i = g2 * z_sigma_i
        let g2_z_sigma = multiply_field_elems_with_same_group_elem(
            params.bb_sig_params.g2.into_group(),
            &self.z_sigma,
        );
        // lhs_i = a_i + e(g1, g2) * z_v_i
        let lhs = cfg_into_iter!(0..self.V.len())
            .map(|i| self.a[i] + (params.bb_sig_params.g1g2 * self.z_v[i]))
            .collect::<Vec<_>>();
        // yc_sigma_i = yc + g2_z_sigma_i
        let yc_sigma = cfg_into_iter!(0..g2_z_sigma.len())
            .map(|i| yc + g2_z_sigma[i])
            .collect::<Vec<_>>();
        (yc_sigma, lhs)
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
    fn range_proof_for_perfect_range() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for base in [2, 3, 4, 5, 8, 10, 15, 20] {
            let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
            params_with_pairing.verify().unwrap();

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for l in [10, 12] {
                let mut proving_time = Duration::default();
                let mut verifying_time = Duration::default();
                let mut verifying_with_rpc_time = Duration::default();
                let mut proof_size = 0;
                for _ in 0..5 {
                    // TODO: Combine base and l in outer for loop
                    let max = (base as u64).pow(l);
                    let value = u64::rand(&mut rng) % max;
                    assert!(value < max);
                    let randomness = Fr::rand(&mut rng);
                    let commitment = comm_key.commit(&Fr::from(value), &randomness);
                    let start = Instant::now();
                    let protocol = CCSPerfectRangeProofProtocol::init_given_base(
                        &mut rng,
                        value,
                        randomness,
                        max,
                        base,
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
                    proving_time += start.elapsed();

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

                    assert_eq!(proof.V.len(), l as usize);
                    proof
                        .verify(
                            &commitment,
                            &challenge_verifier,
                            max,
                            &comm_key,
                            params_with_pairing.clone(),
                        )
                        .unwrap();
                    verifying_time += start.elapsed();

                    let mut pairing_checker =
                        RandomizedPairingChecker::new_using_rng(&mut rng, true);
                    let start = Instant::now();
                    proof
                        .verify_given_randomized_pairing_checker(
                            &commitment,
                            &challenge_verifier,
                            max,
                            &comm_key,
                            params_with_pairing.clone(),
                            &mut pairing_checker,
                        )
                        .unwrap();
                    assert!(pairing_checker.verify());
                    verifying_with_rpc_time += start.elapsed();

                    let mut bytes = vec![];
                    proof.serialize_compressed(&mut bytes).unwrap();
                    proof_size = bytes.len();
                }
                println!("For base {} and max {}, proof size = {}, average proving time = {:?}, average verifying time = {:?} and average verifying time using randomized pairing checker={:?}", base, (base as u64).pow(l), proof_size, proving_time / 5, verifying_time / 5, verifying_with_rpc_time/5);
            }
        }
    }
}
