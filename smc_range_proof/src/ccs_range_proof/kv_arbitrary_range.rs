//! Same as CCS arbitrary range proof protocol but does Keyed-Verification, i.e. the verifies knows the
//! secret key of the BB-sig

use crate::{
    ccs_range_proof::util::{check_commitment_for_arbitrary_range, find_l_for_arbitrary_range},
    ccs_set_membership::setup::SetMembershipCheckParamsKV,
    common::{padded_base_n_digits_as_field_elements, MemberCommitmentKey},
    error::SmcRangeProofError,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, format, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{expect_equality, misc::n_rand};
use short_group_sig::{
    weak_bb_sig::SecretKey,
    weak_bb_sig_pok_kv::{PoKOfSignatureG1KV, PoKOfSignatureG1KVProtocol},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CCSArbitraryRangeProofWithKVProtocol<G: AffineRepr> {
    pub base: u16,
    pub r: G::ScalarField,
    pub pok_sigs_min: Vec<PoKOfSignatureG1KVProtocol<G>>,
    pub pok_sigs_max: Vec<PoKOfSignatureG1KVProtocol<G>>,
    pub D_min: G,
    pub m_min: G::ScalarField,
    pub D_max: G,
    pub m_max: G::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSArbitraryRangeWithKVProof<G: AffineRepr> {
    pub base: u16,
    pub D_min: G,
    pub D_max: G,
    pub pok_sigs_min: Vec<PoKOfSignatureG1KV<G>>,
    pub pok_sigs_max: Vec<PoKOfSignatureG1KV<G>>,
    pub resp_r_min: G::ScalarField,
    pub resp_r_max: G::ScalarField,
}

impl<G: AffineRepr> CCSArbitraryRangeProofWithKVProtocol<G> {
    /// Initialize the protocol for proving `min <= value < max`
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

    /// Initialize the protocol for proving `min <= value < max`
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

        let l = find_l_for_arbitrary_range(max, min, base) as usize;

        let m_min = G::ScalarField::rand(rng);
        let msg_blindings_min = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let D_min = comm_key.commit_decomposed(base, &msg_blindings_min, &m_min);
        let m_max = G::ScalarField::rand(rng);
        let msg_blindings_max = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let D_max = comm_key.commit_decomposed(base, &msg_blindings_max, &m_max);

        let digits_min = padded_base_n_digits_as_field_elements(value - min, base, l);
        let digits_max = padded_base_n_digits_as_field_elements(
            value + (base as u64).pow(l as u32) - max,
            base,
            l,
        );

        let mut sigs = Vec::with_capacity(2 * l);
        for d in &digits_min {
            sigs.push(params.get_sig_for_member(d)?);
        }
        for d in &digits_max {
            sigs.push(params.get_sig_for_member(d)?);
        }

        let sig_randomizers_min = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let sig_randomizers_max = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let sc_blindings_min = n_rand(rng, l).collect::<Vec<G::ScalarField>>();
        let sc_blindings_max = n_rand(rng, l).collect::<Vec<G::ScalarField>>();

        let pok_sigs_min = cfg_into_iter!(sig_randomizers_min)
            .zip(cfg_into_iter!(msg_blindings_min))
            .zip(cfg_into_iter!(sc_blindings_min))
            .zip(cfg_into_iter!(sigs[..l]))
            .zip(cfg_into_iter!(digits_min))
            .map(
                |((((sig_randomizer_i, msg_blinding_i), sc_blinding_i), sig_i), msg_i)| {
                    PoKOfSignatureG1KVProtocol::<G>::init_with_given_randomness(
                        sig_randomizer_i,
                        msg_blinding_i,
                        sc_blinding_i,
                        sig_i,
                        msg_i,
                        &params.bb_sig_params,
                    )
                },
            )
            .collect::<Vec<_>>();

        let pok_sigs_max = cfg_into_iter!(sig_randomizers_max)
            .zip(cfg_into_iter!(msg_blindings_max))
            .zip(cfg_into_iter!(sc_blindings_max))
            .zip(cfg_into_iter!(sigs[l..]))
            .zip(cfg_into_iter!(digits_max))
            .map(
                |((((sig_randomizer_i, msg_blinding_i), sc_blinding_i), sig_i), msg_i)| {
                    PoKOfSignatureG1KVProtocol::<G>::init_with_given_randomness(
                        sig_randomizer_i,
                        msg_blinding_i,
                        sc_blinding_i,
                        sig_i,
                        msg_i,
                        &params.bb_sig_params,
                    )
                },
            )
            .collect::<Vec<_>>();

        Ok(Self {
            base,
            r: randomness,
            pok_sigs_min,
            pok_sigs_max,
            D_min,
            m_min,
            D_max,
            m_max,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs_min {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        for sig in &self.pok_sigs_max {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D_min.serialize_compressed(&mut writer)?;
        self.D_max.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> CCSArbitraryRangeWithKVProof<G> {
        let pok_sigs_min = cfg_into_iter!(self.pok_sigs_min)
            .map(|p| p.gen_proof(challenge))
            .collect::<Vec<_>>();
        let pok_sigs_max = cfg_into_iter!(self.pok_sigs_max)
            .map(|p| p.gen_proof(challenge))
            .collect::<Vec<_>>();
        CCSArbitraryRangeWithKVProof {
            base: self.base,
            pok_sigs_min,
            pok_sigs_max,
            D_min: self.D_min,
            D_max: self.D_max,
            resp_r_min: self.m_min + self.r * challenge,
            resp_r_max: self.m_max + self.r * challenge,
        }
    }
}

impl<G: AffineRepr> CCSArbitraryRangeWithKVProof<G> {
    /// Verify the proof for `min <= value < max` where `commitment` is a Pedersen commitment to `value`
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
        let l = find_l_for_arbitrary_range(max, min, self.base) as usize;
        expect_equality!(
            self.pok_sigs_min.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        expect_equality!(
            self.pok_sigs_max.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );

        let resp_d_min = cfg_iter!(self.pok_sigs_min)
            .map(|p| *p.get_resp_for_message().unwrap())
            .collect::<Vec<_>>();
        let resp_d_max = cfg_iter!(self.pok_sigs_max)
            .map(|p| *p.get_resp_for_message().unwrap())
            .collect::<Vec<_>>();
        check_commitment_for_arbitrary_range::<G>(
            self.base,
            &resp_d_min,
            &resp_d_max,
            &self.resp_r_min,
            &self.resp_r_max,
            &self.D_min,
            &self.D_max,
            min,
            max,
            commitment,
            challenge,
            comm_key,
        )?;
        let results = cfg_iter!(self.pok_sigs_min)
            .chain(cfg_iter!(self.pok_sigs_max))
            .map(|p| {
                if let Err(e) = p.verify(challenge, secret_key, &params.bb_sig_params) {
                    return Err(SmcRangeProofError::ShortGroupSig(e));
                }
                Ok(())
            })
            .collect::<Vec<_>>();
        for r in results {
            r?;
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for sig in &self.pok_sigs_min {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        for sig in &self.pok_sigs_max {
            sig.challenge_contribution(&params.bb_sig_params, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D_min.serialize_compressed(&mut writer)?;
        self.D_max.serialize_compressed(&mut writer)?;
        Ok(())
    }
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
    fn range_proof_for_arbitrary_range() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let mut proving_time = Duration::default();
        let mut verifying_time = Duration::default();
        let mut num_proofs = 0;

        for base in [2, 4, 8, 10, 13, 16] {
            let (params, sk) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);

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
                    let (params, _) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base - 1);
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
                    let (params, sk) = SetMembershipCheckParamsKV::<G1Affine>::new_for_range_proof::<
                        _,
                        Blake2b512,
                    >(&mut rng, b"test", base + 1);
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
            "For {} proofs, average proving_time={:?} and average verifying_time={:?}",
            num_proofs,
            proving_time / num_proofs,
            verifying_time / num_proofs
        );
    }
}
