//! Same as CLS range range proof protocol but does Keyed-Verification, i.e the verifies knows the
//! secret key of the BB-sig

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsKV,
    cls_range_proof::util::{check_commitment, get_sumset_parameters},
    common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, format, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{ff::inner_product, misc::n_rand};
use short_group_sig::{
    weak_bb_sig::SecretKey,
    weak_bb_sig_pok_kv::{PoKOfSignatureG1KV, PoKOfSignatureG1KVProtocol},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CLSRangeProofWithKVProtocol<G: AffineRepr> {
    pub base: u16,
    pub pok_sigs: Vec<PoKOfSignatureG1KVProtocol<G>>,
    pub r: G::ScalarField,
    pub D: G,
    pub m: G::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CLSRangeProofWithKV<G: AffineRepr> {
    pub base: u16,
    pub pok_sigs: Vec<PoKOfSignatureG1KV<G>>,
    pub D: G,
    pub resp_r: G::ScalarField,
}

impl<G: AffineRepr> CLSRangeProofWithKVProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: G::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
    ) -> Result<Self, SmcRangeProofError> {
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

    pub fn init_given_base<R: RngCore>(
        rng: &mut R,
        value: u64,
        randomness: G::ScalarField,
        min: u64,
        max: u64,
        base: u16,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
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

        let (l, G, randomness_multiple, digits) = get_sumset_parameters(value, min, max, base);

        // Note: This is different from the paper as only a single `m` needs to be created.
        let m = G::ScalarField::rand(rng);
        let msg_blindings = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let D = comm_key.commit(
            &inner_product(
                &msg_blindings,
                &cfg_into_iter!(G.clone())
                    .map(|G_i| G::ScalarField::from(G_i))
                    .collect::<Vec<_>>(),
            ),
            &(m * G::ScalarField::from(randomness_multiple)),
        );

        let digits = cfg_into_iter!(digits)
            .map(|d| G::ScalarField::from(d))
            .collect::<Vec<_>>();
        let sc_blindings = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let sig_randomizers = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let mut sigs = Vec::with_capacity(l as usize);
        for d in &digits {
            sigs.push(params.get_sig_for_member(d)?);
        }
        let pok_sigs = cfg_into_iter!(sig_randomizers)
            .zip(cfg_into_iter!(msg_blindings))
            .zip(cfg_into_iter!(sc_blindings))
            .zip(cfg_into_iter!(sigs))
            .zip(cfg_into_iter!(digits))
            .map(
                |((((sig_randomizer_i, msg_blinding_i), sc_blinding_i), sig_i), msg_i)| {
                    PoKOfSignatureG1KVProtocol::init_with_given_randomness(
                        sig_randomizer_i,
                        msg_blinding_i,
                        sc_blinding_i,
                        sig_i,
                        msg_i,
                        &params.bb_sig_params,
                    )
                },
            )
            .collect();
        Ok(Self {
            base,
            pok_sigs,
            r: randomness,
            D,
            m,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> CLSRangeProofWithKV<G> {
        let pok_sigs = cfg_into_iter!(self.pok_sigs)
            .map(|p| p.gen_proof(challenge))
            .collect::<Vec<_>>();
        CLSRangeProofWithKV {
            base: self.base,
            pok_sigs,
            D: self.D,
            resp_r: self.m + (self.r * challenge),
        }
    }
}

impl<G: AffineRepr> CLSRangeProofWithKV<G> {
    pub fn verify(
        &self,
        commitment: &G,
        challenge: &G::ScalarField,
        min: u64,
        max: u64,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        secret_key: &SecretKey<G::ScalarField>,
    ) -> Result<(), SmcRangeProofError> {
        params.validate_base(self.base)?;
        if min >= max {
            return Err(SmcRangeProofError::IncorrectBounds(format!(
                "min={} should be < max={}",
                min, max
            )));
        }

        let resp_d = cfg_iter!(self.pok_sigs)
            .map(|p| *p.get_resp_for_message().unwrap())
            .collect::<Vec<_>>();
        check_commitment::<G>(
            self.base,
            &resp_d,
            &self.resp_r,
            &self.D,
            min,
            max,
            commitment,
            challenge,
            comm_key,
        )?;
        let results = cfg_iter!(self.pok_sigs)
            .map(|p| {
                p.verify(challenge, secret_key, &params.bb_sig_params)
                    .map_err(|e| SmcRangeProofError::ShortGroupSig(e))
            })
            .collect::<Vec<_>>();
        for r in results {
            r?;
        }

        // let g1v = multiply_field_elems_with_same_group_elem(
        //     params.bb_sig_params.g1.into_group(),
        //     &self.z_v,
        // );
        //
        // let sk_c = secret_key.0 * challenge;
        //
        // for i in 0..self.V.len() {
        //     if self.a[i] != (self.V[i] * (sk_c - self.z_sigma[i]) + g1v[i]).into_affine() {
        //         return Err(SmcRangeProofError::InvalidRangeProof);
        //     }
        // }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
        Ok(())
    }

    // fn non_crypto_validate(
    //     &self,
    //     min: u64,
    //     max: u64,
    //     params: &SetMembershipCheckParams<E>,
    // ) -> Result<(), SmcRangeProofError> {
    //     params.validate_base(self.base)?;
    //     if min >= max {
    //         return Err(SmcRangeProofError::IncorrectBounds(format!(
    //             "min={} should be < max={}",
    //             min, max
    //         )));
    //     }
    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
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
        let mut proving_time = Duration::default();
        let mut verifying_time = Duration::default();
        let mut num_proofs = 0;

        for base in [2, 4, 8, 16] {
            let (params, sk) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for _ in 0..5 {
                let mut a = [
                    u64::rand(&mut rng),
                    u64::rand(&mut rng),
                    u64::rand(&mut rng),
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
                    let (params, _) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base - 1);
                    params
                };
                assert!(CLSRangeProofWithKVProtocol::init_given_base(
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
                assert!(CLSRangeProofWithKVProtocol::init_given_base(
                    &mut rng, value, randomness, max, min, base, &comm_key, &params,
                )
                .is_err());

                // Params with larger base should work
                let (params_with_larger_base, sk_larger) = {
                    let (params, sk) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base + 1);
                    (params, sk)
                };

                for (p, sk) in [(&params, &sk), (&params_with_larger_base, &sk_larger)] {
                    let start = Instant::now();
                    let protocol = CLSRangeProofWithKVProtocol::init_given_base(
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

                    let start = Instant::now();
                    let mut chal_bytes_verifier = vec![];
                    proof
                        .challenge_contribution(&commitment, &comm_key, p, &mut chal_bytes_verifier)
                        .unwrap();
                    let challenge_verifier =
                        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
                    assert_eq!(challenge_prover, challenge_verifier);

                    // assert_eq!(proof.V.len(), l as usize);
                    proof
                        .verify(&commitment, &challenge_verifier, min, max, &comm_key, p, sk)
                        .unwrap();
                    verifying_time += start.elapsed();

                    num_proofs += 1;
                }
            }
        }

        println!(
            "For {} proofs, average proving_time={:?} and average verifying_time={:?}",
            num_proofs,
            proving_time / num_proofs,
            verifying_time / num_proofs
        );
    }
}
