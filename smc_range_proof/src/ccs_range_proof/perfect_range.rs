//! Range proof protocol as described in Fig.3 of the paper [Efficient Protocols for Set Membership and Range Proofs](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15).
//! Considers a perfect-range, i.e. range of the form `[0, u^l)` where `u` is the base and the upper bound is a power of the base.

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing, common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, io::Write, ops::Mul, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{misc::n_rand, msm::multiply_field_elems_with_same_group_elem};

use crate::common::padded_base_n_digits_as_field_elements;
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

use crate::ccs_range_proof::util::{check_commitment_for_prefect_range, find_l};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
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
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<Self, SmcRangeProofError> {
        let params = params.into();

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
        let a = cfg_into_iter!(0..l)
            .map(|i| {
                E::pairing(
                    E::G1Prepared::from(V[i] * -s[i]),
                    params.bb_sig_params.g2_prepared.clone(),
                ) + params.bb_sig_params.g1g2.mul(t[i])
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
        gen_proof_perfect_range!(self, challenge, CCSPerfectRangeProof)
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

impl<E: Pairing> CCSPerfectRangeProof<E> {
    pub fn verify(
        &self,
        commitment: &E::G1Affine,
        challenge: &E::ScalarField,
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();
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

        let (yc_sigma, lhs) = self.compute_for_pairing_check(challenge, &params);
        for i in 0..self.V.len() {
            let rhs = E::pairing(
                E::G1Prepared::from(self.V[i]),
                E::G2Prepared::from(yc_sigma[i]),
            );
            if lhs[i] != rhs {
                return Err(SmcRangeProofError::InvalidRangeProof);
            }
        }
        Ok(())
    }

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

        let (yc_sigma, lhs) = self.compute_for_pairing_check(challenge, &params);

        for i in 0..self.V.len() {
            pairing_checker.add_multiple_sources_and_target(&[self.V[i]], &[yc_sigma[i]], &lhs[i]);
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
        CCSPerfectRangeProofProtocol::compute_challenge_contribution(
            &self.V, &self.a, &self.D, commitment, comm_key, params, writer,
        )
    }

    fn non_crypto_validate(
        &self,
        max: u64,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> Result<(), SmcRangeProofError> {
        params.validate_base(self.base)?;
        let l = find_l(max, self.base) as usize;
        assert_eq!(self.V.len(), l);
        assert_eq!(self.a.len(), l);
        assert_eq!(self.z_v.len(), l);
        assert_eq!(self.z_sigma.len(), l);
        Ok(())
    }

    fn compute_for_pairing_check(
        &self,
        challenge: &E::ScalarField,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> (Vec<E::G2>, Vec<PairingOutput<E>>) {
        // y * c
        let yc = params.bb_pk.0 * challenge;
        // g2 * z_sigma
        let g2_z_sigma = multiply_field_elems_with_same_group_elem(
            params.bb_sig_params.g2.into_group(),
            &self.z_sigma,
        );
        let lhs = cfg_into_iter!(0..self.V.len())
            .map(|i| self.a[i] - (params.bb_sig_params.g1g2 * self.z_v[i]))
            .collect::<Vec<_>>();
        let yc_sigma = cfg_into_iter!(0..g2_z_sigma.len())
            .map(|i| yc - g2_z_sigma[i])
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

    #[test]
    fn range_proof_for_perfect_range() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for base in [2, 4, 8, 16] {
            let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
            params_with_pairing.verify().unwrap();

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for _ in 0..5 {
                for l in [10, 15] {
                    // TODO: Combine base and l in outer for loop
                    let max = (base as u64).pow(l);
                    let value = u64::rand(&mut rng) % max;
                    assert!(value < max);
                    let randomness = Fr::rand(&mut rng);
                    let commitment = comm_key.commit(&Fr::from(value), &randomness);
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

                    let mut pairing_checker =
                        RandomizedPairingChecker::new_using_rng(&mut rng, true);
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
                }
            }
        }
    }
}
