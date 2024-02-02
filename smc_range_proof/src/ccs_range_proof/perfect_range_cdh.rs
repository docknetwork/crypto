//! Range proof protocol based on Fig.3 of the paper [Efficient Protocols for Set Membership and Range Proofs](https://link.springer.com/chapter/10.1007/978-3-540-89255-7_15).
//! Considers a perfect-range, i.e. range of the form `[0, u^l)` where `u` is the base and the upper bound is a power of the base.
//! The difference with the paper is the protocol used to prove knowledge of weak-BB sig which is taken from the CDH paper.

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsWithPairing, common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::pairing::Pairing;
use ark_std::io::Write;

use crate::{
    ccs_range_proof::util::find_l, ccs_set_membership::setup::SetMembershipCheckParams,
    common::padded_base_n_digits_as_field_elements,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::misc::n_rand;
use short_group_sig::weak_bb_sig_pok_cdh::{PoKOfSignatureG1, PoKOfSignatureG1Protocol};

use crate::ccs_range_proof::util::check_commitment_for_prefect_range;
use dock_crypto_utils::{expect_equality, randomized_pairing_check::RandomizedPairingChecker};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CCSPerfectRangeProofProtocol<E: Pairing> {
    pub base: u16,
    /// Protocols to prove knowledge of signature on digits. One protocol for each digit
    pub pok_sigs: Vec<PoKOfSignatureG1Protocol<E>>,
    /// Randomness used in the commitment to the value
    pub r: E::ScalarField,
    pub D: E::G1Affine,
    pub m: E::ScalarField,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSPerfectRangeProof<E: Pairing> {
    pub base: u16,
    /// Proof of knowledge of signature on digits. One proof for each digit
    pub pok_sigs: Vec<PoKOfSignatureG1<E>>,
    pub D: E::G1Affine,
    pub resp_r: E::ScalarField,
}

impl<E: Pairing> CCSPerfectRangeProofProtocol<E> {
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
        let msg_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let m = E::ScalarField::rand(rng);
        let digits = padded_base_n_digits_as_field_elements(value, base, l);
        let mut sigs = Vec::with_capacity(l);
        for d in &digits {
            sigs.push(params.get_sig_for_member(d)?);
        }
        let sig_randomizers = n_rand(rng, l).collect::<Vec<E::ScalarField>>();
        let sc_blindings = n_rand(rng, l).collect::<Vec<E::ScalarField>>();

        let D = comm_key.commit_decomposed(base, &msg_blindings, &m);

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
            pok_sigs,
            r: randomness,
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
        for sig in &self.pok_sigs {
            sig.challenge_contribution(&params.bb_sig_params.g1, &mut writer)?;
        }
        comm_key.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        self.D.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> CCSPerfectRangeProof<E> {
        let pok_sigs = cfg_into_iter!(self.pok_sigs)
            .map(|p| p.gen_proof(challenge))
            .collect::<Vec<_>>();
        CCSPerfectRangeProof {
            base: self.base,
            D: self.D,
            pok_sigs,
            resp_r: self.m + self.r * challenge,
        }
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

        self.verify_except_pairings(commitment, challenge, max, comm_key, &params)?;

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
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: impl Into<SetMembershipCheckParamsWithPairing<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), SmcRangeProofError> {
        let params = params.into();

        self.verify_except_pairings(commitment, challenge, max, comm_key, &params)?;

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
        max: u64,
        comm_key: &MemberCommitmentKey<E::G1Affine>,
        params: &SetMembershipCheckParamsWithPairing<E>,
    ) -> Result<(), SmcRangeProofError> {
        params.validate_base(self.base)?;
        let l = find_l(max, self.base) as usize;
        expect_equality!(
            self.pok_sigs.len(),
            l,
            SmcRangeProofError::ProofShorterThanExpected
        );

        let resp_d = cfg_iter!(self.pok_sigs)
            .map(|p| *p.get_resp_for_message())
            .collect::<Vec<_>>();
        check_commitment_for_prefect_range::<E>(
            self.base,
            &resp_d,
            &self.resp_r,
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
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
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

        for base in [2, 4, 8, 16] {
            let (params, _) = SetMembershipCheckParams::<Bls12_381>::new_for_range_proof::<
                _,
                Blake2b512,
            >(&mut rng, b"test", base);
            params.verify().unwrap();

            let params_with_pairing = SetMembershipCheckParamsWithPairing::from(params.clone());
            params_with_pairing.verify().unwrap();

            let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

            for l in [10, 15] {
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

                    // TODO: Temp fix error
                    let mut temp = params_with_pairing.clone();
                    temp.bb_pk.0 = G2Affine::rand(&mut rng);
                    assert!(proof
                        .verify(&commitment, &challenge_verifier, max, &comm_key, temp,)
                        .is_err());

                    // assert!(proof
                    //     .verify(
                    //         &commitment,
                    //         &challenge_verifier,
                    //         value - 1,
                    //         &comm_key,
                    //         params_with_pairing.clone(),
                    //     )
                    //     .is_err());

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
