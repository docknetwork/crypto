//! Same as CCS perfect range proof protocol but does Keyed-Verification, i.e. the verifies knows the
//! secret key of the BB-sig

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParams, common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::pairing::Pairing;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::misc::n_rand;
use short_group_sig::weak_bb_sig::SecretKey;

use crate::common::padded_base_n_digits_as_field_elements;

use crate::ccs_range_proof::util::check_commitment_for_prefect_range;
use dock_crypto_utils::expect_equality;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use short_group_sig::weak_bb_sig_pok_kv::{PoKOfSignatureG1KV, PoKOfSignatureG1KVProtocol};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CCSPerfectRangeProofWithKVProtocol<E: Pairing> {
    pub base: u16,
    pub r: E::ScalarField,
    pub pok_sigs: Vec<PoKOfSignatureG1KVProtocol<E::G1Affine>>,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSPerfectRangeWithKVProof<E: Pairing> {
    pub base: u16,
    pub pok_sigs: Vec<PoKOfSignatureG1KV<E::G1Affine>>,
    pub D: E::G1Affine,
    pub resp_r: E::ScalarField,
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
        let msg_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let sc_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let sig_randomizers = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let D = comm_key.commit_decomposed(base, &msg_blindings, &m);

        let digits = padded_base_n_digits_as_field_elements(value, base, l);
        let mut sigs = Vec::with_capacity(l);
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
                        &params.bb_sig_params.g1,
                    )
                },
            )
            .collect();

        Ok(Self {
            base,
            r: randomness,
            pok_sigs,
            D,
            m,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for p in &self.pok_sigs {
            p.challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSPerfectRangeWithKVProof<E> {
        let pok_sigs = cfg_into_iter!(self.pok_sigs)
            .map(|p| p.gen_proof(challenge))
            .collect::<Vec<_>>();

        CCSPerfectRangeWithKVProof {
            base: self.base,
            pok_sigs,
            D: self.D,
            resp_r: self.m + (self.r * challenge),
        }
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
        params.validate_base(self.base)?;
        let l = find_l(max, self.base) as usize;
        expect_equality!(
            self.pok_sigs.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );
        let z_sigma = cfg_iter!(self.pok_sigs)
            .map(|p| *p.get_resp_for_message())
            .collect::<Vec<_>>();
        check_commitment_for_prefect_range::<E>(
            self.base,
            &z_sigma,
            &self.resp_r,
            &self.D,
            commitment,
            challenge,
            comm_key,
        )?;

        let results = cfg_iter!(self.pok_sigs)
            .map(|p| {
                p.verify(challenge, secret_key, &params.bb_sig_params.g1)
                    .map_err(|e| SmcRangeProofError::ShortGroupSig(e))
            })
            .collect::<Vec<_>>();
        for r in results {
            r?;
        }

        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &E::G1Affine,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParams<E>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        for p in &self.pok_sigs {
            p.challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
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

                    assert_eq!(proof.pok_sigs.len(), l as usize);
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
