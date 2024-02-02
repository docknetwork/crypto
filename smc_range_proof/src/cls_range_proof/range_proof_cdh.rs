use crate::{
    ccs_set_membership::setup::{SetMembershipCheckParams, SetMembershipCheckParamsWithPairing},
    cls_range_proof::{util, util::get_range_and_randomness_multiple},
    common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, format, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{ff::inner_product, misc::n_rand};
use short_group_sig::weak_bb_sig_pok_cdh::{PoKOfSignatureG1, PoKOfSignatureG1Protocol};

use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

use crate::cls_range_proof::util::check_commitment;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CLSRangeProofProtocol<E: Pairing> {
    pub base: u16,
    pub pok_sigs: Vec<PoKOfSignatureG1Protocol<E>>,
    pub r: E::ScalarField,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CLSRangeProof<E: Pairing> {
    pub base: u16,
    pub pok_sigs: Vec<PoKOfSignatureG1<E>>,
    pub D: E::G1Affine,
    pub resp_r: E::ScalarField,
}

impl<E: Pairing> CLSRangeProofProtocol<E> {
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
        mut value: u64,
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

        let (range, randomness_multiple) = get_range_and_randomness_multiple(base, min, max);
        value = value - min;
        if randomness_multiple != 1 {
            value = value * (base - 1) as u64;
        }

        let l = util::find_number_of_digits(range, base);
        let G = util::find_sumset_boundaries(range, base, l);

        // Note: This is different from the paper as only a single `m` needs to be created.
        let m = E::ScalarField::rand(rng);
        let msg_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D = comm_key.commit(
            &inner_product(
                &msg_blindings,
                &cfg_into_iter!(G.clone())
                    .map(|G_i| E::ScalarField::from(G_i))
                    .collect::<Vec<_>>(),
            ),
            &(m * E::ScalarField::from(randomness_multiple)),
        );

        if let Some(digits) = util::solve_linear_equations(value, &G, base) {
            // Following is only for debugging
            // let mut expected = 0_u64;
            // for j in 0..digits.len() {
            //     assert!(digits[j] < base);
            //     expected += digits[j] as u64 * G[j];
            // }
            // assert_eq!(expected, value);

            let digits = cfg_into_iter!(digits)
                .map(|d| E::ScalarField::from(d))
                .collect::<Vec<_>>();
            let mut sigs = Vec::with_capacity(l as usize);
            for d in &digits {
                sigs.push(params.get_sig_for_member(d)?);
            }
            let sig_randomizers = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
            let sc_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();

            let pok_sigs = cfg_into_iter!(sig_randomizers)
                .zip(cfg_into_iter!(msg_blindings))
                .zip(cfg_into_iter!(sc_blindings))
                .zip(cfg_into_iter!(sigs))
                .zip(cfg_into_iter!(digits))
                .map(
                    |((((sig_randomizer_i, msg_blinding_i), sc_blinding_i), sig_i), msg_i)| {
                        PoKOfSignatureG1Protocol::init_with_given_randomness(
                            sig_randomizer_i,
                            msg_blinding_i,
                            sc_blinding_i,
                            sig_i,
                            msg_i,
                            &params.bb_sig_params.g1,
                        )
                    },
                )
                .collect::<Vec<_>>();
            Ok(Self {
                base,
                r: randomness,
                pok_sigs,
                D,
                m,
            })
        } else {
            Err(SmcRangeProofError::InvalidRange(range, base))
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs {
            sig.challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CLSRangeProof<E> {
        let pok_sigs = cfg_into_iter!(self.pok_sigs)
            .map(|sig| sig.gen_proof(challenge))
            .collect::<Vec<_>>();
        CLSRangeProof {
            base: self.base,
            D: self.D,
            pok_sigs,
            resp_r: self.m + self.r * challenge,
        }
    }
}

impl<E: Pairing> CLSRangeProof<E> {
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

        let pk = E::G2Prepared::from(params.bb_pk.0);
        let g2 = params.bb_sig_params.g2_prepared;
        let results = cfg_iter!(self.pok_sigs)
            .map(|p| {
                p.verify(challenge, pk.clone(), &params.bb_sig_params.g1, g2.clone())
                    .map_err(|e| SmcRangeProofError::ShortGroupSig(e))
            })
            .collect::<Vec<_>>();
        for r in results {
            r?;
        }

        Ok(())
    }

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

        let pk = E::G2Prepared::from(params.bb_pk.0);
        let g2 = params.bb_sig_params.g2_prepared;
        let results = cfg_iter!(self.pok_sigs)
            .map(|p| {
                let r = p.verify_except_pairings(challenge, &params.bb_sig_params.g1);
                if let Err(e) = r {
                    return Err(SmcRangeProofError::ShortGroupSig(e));
                }
                Ok(())
            })
            .collect::<Vec<_>>();
        for r in results {
            r?;
        }

        for p in &self.pok_sigs {
            pairing_checker.add_sources(&p.A_prime, pk.clone(), &p.A_bar, g2.clone());
        }

        Ok(())
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
        params.validate_base(self.base)?;
        if min >= max {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "min={} should be < max={}",
                min, max
            )));
        }
        let resp_d = cfg_iter!(self.pok_sigs)
            .map(|p| *p.get_resp_for_message())
            .collect::<Vec<_>>();
        check_commitment::<E>(
            self.base,
            &resp_d,
            &self.resp_r,
            &self.D,
            min,
            max,
            commitment,
            challenge,
            comm_key,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs {
            sig.challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
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
    fn cls_range_proof() {
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

            let mut proving_time = Duration::default();
            let mut verifying_time = Duration::default();
            let mut verifying_with_rpc_time = Duration::default();
            let mut proof_size = 0;
            let mut num_proofs = 0;

            for _ in 0..5 {
                let mut a = [
                    u16::rand(&mut rng) as u64,
                    u16::rand(&mut rng) as u64,
                    u16::rand(&mut rng) as u64,
                ];
                a.sort();
                let min = a[0];
                let max = a[2];
                let value = a[1];
                assert!(value > min);
                assert!(value < max);
                let randomness = Fr::rand(&mut rng);
                let commitment = comm_key.commit(&Fr::from(value), &randomness);

                // Params with incorrect base should fail
                let params_with_smaller_base = {
                    let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base - 1);
                    params
                };
                assert!(CLSRangeProofProtocol::init_given_base(
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
                assert!(CLSRangeProofProtocol::init_given_base(
                    &mut rng, value, randomness, max, min, base, &comm_key, &params,
                )
                .is_err());

                // Params with larger base should work
                let params_with_larger_base = {
                    let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base + 1);
                    params
                };

                for (params, pp) in [
                    (params.clone(), params_with_pairing.clone()),
                    (
                        params_with_larger_base.clone(),
                        SetMembershipCheckParamsWithPairing::from(params_with_larger_base.clone()),
                    ),
                ] {
                    let start = Instant::now();
                    let protocol = CLSRangeProofProtocol::init_given_base(
                        &mut rng, value, randomness, min, max, base, &comm_key, &params,
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
                    proving_time += start.elapsed();

                    let start = Instant::now();
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

                    // assert_eq!(proof.V.len(), l as usize);
                    proof
                        .verify(&commitment, &challenge_verifier, min, max, &comm_key, pp)
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
                            params,
                            &mut pairing_checker,
                        )
                        .unwrap();
                    verifying_with_rpc_time += start.elapsed();

                    let mut bytes = vec![];
                    proof.serialize_compressed(&mut bytes).unwrap();
                    proof_size = bytes.len();

                    num_proofs += 1;
                }
            }
            println!("For base={} and {} proofs, proof size = {}, average proving time={:?}, average verifying time={:?} and average verifying time using randomized pairing checker {:?}", base, num_proofs, proof_size, proving_time/num_proofs, verifying_time/num_proofs, verifying_with_rpc_time/num_proofs);
        }
    }
}
