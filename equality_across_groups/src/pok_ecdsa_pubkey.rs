//! Proof of knowledge of ECDSA public key on short Weierstrass curve. Is a slight variation of the protocol described in section 6 of the paper [ZKAttest Ring and Group Signatures for Existing ECDSA Keys](https://eprint.iacr.org/2021/1183)
//!
//! An ECDSA signature `(r, s)` is transformed to `(R, z=s/r)` as per the paper. The new ECDSA verification equation
//! becomes `z*R - g*t*r^-1 = q` where `q` is the public key, `g` is the generator and `t` is the hashed message.
//! This is equivalent to `-g*t*r^-1 = q + z*(-R)`
//!
//! The verifier gets a commitment to the public key `q` and `-z*R` but knows `R, t, g and r` (`r` is the truncated x coordinate of `R`).
//!
//! Thus using the protocols for scalar multiplication and point addition, the prover proves:
//! - Given commitments to `z` and `-z*R`, the scalar multiplication of `z` and `-R` is indeed `-z*R`
//! - Given commitments to `q` and `-z*R`, the sum of `q` and `-z*R` is indeed `-g*t*r^-1`
//!

#![allow(non_snake_case)]

use crate::{
    ec::{
        commitments::{CommitmentWithOpening, PointCommitment, PointCommitmentWithOpening},
        sw_point_addition::PointAdditionProof,
        sw_scalar_mult::ScalarMultiplicationProof,
    },
    error::Error,
    tom256::Affine as Tom256Affine,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_secp256r1::{Affine, Fr, G_GENERATOR_X, G_GENERATOR_Y};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec};
use dock_crypto_utils::{commitment::PedersenCommitmentKey, transcript::Transcript};
use kvac::bbs_sharp::ecdsa;

const SECP_GEN: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

/// ECDSA signature but transformed to be more suitable for the zero knowledge proof
pub struct TransformedEcdsaSig {
    pub R: Affine,
    pub z: Fr,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofOfKnowledgeEcdsaPublicKey<const NUM_REPS_SCALAR_MULT: usize = 128> {
    /// Point R from signature
    pub R: Affine,
    // Question: Is there any additional proof of correctness of `comm_z` and `comm_minus_zR` needed?
    /// Commitment to scalar `z`
    pub comm_z: Affine,
    /// Commitment to coordinates of `-z*R`
    pub comm_minus_zR: PointCommitment<Tom256Affine>,
    /// Proof of relation `z * -R = -z*R`
    pub proof_minus_zR: ScalarMultiplicationProof<Affine, Tom256Affine, NUM_REPS_SCALAR_MULT>,
    /// Proof of relation `-g*t*r^-1 = q + z*(-R)`
    pub proof_add: PointAdditionProof<Affine, Tom256Affine>,
}

impl TransformedEcdsaSig {
    pub fn new(
        sig: &ecdsa::Signature,
        hashed_message: Fr,
        public_key: Affine,
    ) -> Result<Self, Error> {
        let s_inv = sig
            .response
            .inverse()
            .ok_or(Error::EcdsaSigResponseNotInvertible)?;
        let r_inv = sig
            .rand_x_coord
            .inverse()
            .ok_or(Error::EcdsaSigResponseNotInvertible)?;
        let u1 = hashed_message * s_inv;
        let u2 = sig.rand_x_coord * s_inv;
        let R = (SECP_GEN * u1 + public_key * u2).into_affine();
        Ok(Self {
            R,
            z: sig.response * r_inv,
        })
    }

    pub fn verify_prehashed(&self, hashed_message: Fr, public_key: Affine) -> Result<(), Error> {
        let r_inv = Self::r_inv(&self.R)?;
        let t_r_inv = hashed_message * r_inv;
        let zR = self.R * self.z;
        if (zR - (SECP_GEN * t_r_inv)) != public_key.into_group() {
            return Err(Error::InvalidTransformedEcdsaSig);
        }
        Ok(())
    }

    pub fn r_inv(R: &Affine) -> Result<Fr, Error> {
        Fr::from(R.x.into_bigint())
            .inverse()
            .ok_or(Error::EcdsaSigResponseNotInvertible)
    }
}

impl<const NUM_REPS_SCALAR_MULT: usize> ProofOfKnowledgeEcdsaPublicKey<NUM_REPS_SCALAR_MULT> {
    /// Proof that the (transformed) ECDSA signature on the pre-hashed message `hashed_message` can
    /// be verified by the public key `public_key`. `comm_public_key` is the commitment to the
    /// coordinates of the public key point
    pub fn new<R: RngCore>(
        rng: &mut R,
        sig: TransformedEcdsaSig,
        hashed_message: Fr,
        public_key: Affine,
        comm_public_key: PointCommitmentWithOpening<Tom256Affine>,
        comm_key_secp: &PedersenCommitmentKey<Affine>,
        comm_key_tom: &PedersenCommitmentKey<Tom256Affine>,
        transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<Self, Error> {
        let minus_R = sig.R.neg();
        let minus_zR = (minus_R * sig.z).into_affine();
        // -g*t*r^-1
        let minus_g_t_r_inv = (SECP_GEN * (hashed_message * TransformedEcdsaSig::r_inv(&sig.R)?))
            .neg()
            .into_affine();
        let comm_z = CommitmentWithOpening::new(rng, sig.z, comm_key_secp);
        let comm_minus_zR = PointCommitmentWithOpening::new(rng, &minus_zR, comm_key_tom)?;
        transcript.append(b"R", &sig.R);
        transcript.append(b"comm_z", &comm_z.comm);
        transcript.append(b"comm_minus_zR", &comm_minus_zR.comm);
        transcript.append(b"minus_g_t_r_inv", &minus_g_t_r_inv);
        let proof_minus_zR =
            ScalarMultiplicationProof::<Affine, Tom256Affine, NUM_REPS_SCALAR_MULT>::new(
                rng,
                comm_z.clone(),
                comm_minus_zR.clone(),
                minus_zR,
                minus_R,
                comm_key_secp,
                comm_key_tom,
                transcript,
            )?;
        let proof_add = PointAdditionProof::new(
            rng,
            comm_minus_zR.clone(),
            comm_public_key.clone(),
            minus_zR,
            public_key,
            minus_g_t_r_inv,
            comm_key_tom,
            transcript,
        )?;
        Ok(Self {
            R: sig.R,
            comm_z: comm_z.comm,
            comm_minus_zR: comm_minus_zR.comm,
            proof_minus_zR,
            proof_add,
        })
    }

    pub fn verify(
        &self,
        hashed_message: Fr,
        comm_public_key: &PointCommitment<Tom256Affine>,
        comm_key_secp: &PedersenCommitmentKey<Affine>,
        comm_key_tom: &PedersenCommitmentKey<Tom256Affine>,
        transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<(), Error> {
        let minus_R = self.R.neg();
        let minus_g_t_r_inv = (SECP_GEN * (hashed_message * TransformedEcdsaSig::r_inv(&self.R)?))
            .neg()
            .into_affine();
        transcript.append(b"R", &self.R);
        transcript.append(b"comm_z", &self.comm_z);
        transcript.append(b"comm_minus_zR", &self.comm_minus_zR);
        transcript.append(b"minus_g_t_r_inv", &minus_g_t_r_inv);
        self.proof_minus_zR.verify(
            &self.comm_z,
            &self.comm_minus_zR,
            &minus_R,
            comm_key_secp,
            comm_key_tom,
            transcript,
        )?;
        self.proof_add.verify(
            &self.comm_minus_zR,
            comm_public_key,
            &minus_g_t_r_inv,
            comm_key_tom,
            transcript,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ec::commitments::from_base_field_to_scalar_field, eq_across_groups::ProofLargeWitness,
        util::timing_info,
    };
    use ark_bls12_381::{Fr as BlsFr, G1Affine as BlsG1Affine};
    use ark_secp256r1::Fq;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
    use dock_crypto_utils::transcript::new_merlin_transcript;
    use rand_core::OsRng;
    use std::time::{Duration, Instant};

    #[test]
    fn transformed_sig_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let sk = Fr::rand(&mut rng);
        let pk = (SECP_GEN * sk).into_affine();

        let message = Fr::rand(&mut rng);
        let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);
        assert!(sig.verify_prehashed(message, pk));

        let transformed_sig = TransformedEcdsaSig::new(&sig, message, pk).unwrap();
        transformed_sig.verify_prehashed(message, pk).unwrap();
    }

    #[test]
    fn pok_ecdsa_pubkey() {
        let mut rng = OsRng::default();

        let comm_key_secp = PedersenCommitmentKey::<Affine>::new::<Blake2b512>(b"test1");
        let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(b"test2");

        let sk = Fr::rand(&mut rng);
        let pk = (SECP_GEN * sk).into_affine();

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let num_iters = 10;
        for i in 0..num_iters {
            let message = Fr::rand(&mut rng);
            let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);
            let transformed_sig = TransformedEcdsaSig::new(&sig, message, pk).unwrap();
            transformed_sig.verify_prehashed(message, pk).unwrap();

            let comm_pk = PointCommitmentWithOpening::new(&mut rng, &pk, &comm_key_tom).unwrap();

            let start = Instant::now();
            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key_secp", &comm_key_secp);
            prover_transcript.append(b"comm_key_tom", &comm_key_tom);
            let proof = ProofOfKnowledgeEcdsaPublicKey::<128>::new(
                &mut rng,
                transformed_sig,
                message,
                pk,
                comm_pk.clone(),
                &comm_key_secp,
                &comm_key_tom,
                &mut prover_transcript,
            )
            .unwrap();
            prov_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
            verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
            proof
                .verify(
                    message,
                    &comm_pk.comm,
                    &comm_key_secp,
                    &comm_key_tom,
                    &mut verifier_transcript,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            if i == 0 {
                println!("Proof size = {} bytes", proof.compressed_size());
            }
        }

        println!("For {} iterations", num_iters);
        println!("Proving time: {:?}", timing_info(prov_time));
        println!("Verifying time: {:?}", timing_info(ver_time));
    }

    #[test]
    fn pok_ecdsa_pubkey_committed_in_bls12_381_commitment() {
        // This test creates an ECDSA public key, commits to its coordinates in Pedersen commitments on the Tom-256 curve
        // as well as the BLS12-381 curve.
        // It then creates an ECDSA signature, proves that it can be verified by the public key committed
        // on the Tom-256 curve.
        // It then proves that the key (its coordinates) committed in the Tom-256 curve are the same as the ones
        // committed in the BLS12-381 curve.

        let mut rng = OsRng::default();

        const WITNESS_BIT_SIZE: usize = 64;
        const CHALLENGE_BIT_SIZE: usize = 180;
        const ABORT_PARAM: usize = 8;
        const RESPONSE_BYTE_SIZE: usize = 32;
        const NUM_REPS: usize = 1;
        const NUM_CHUNKS: usize = 4;

        let comm_key_secp = PedersenCommitmentKey::<Affine>::new::<Blake2b512>(b"test1");
        let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(b"test2");
        let comm_key_bls = PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>(b"test3");

        let base = 2;
        let mut bpp_setup_params = BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<
            Blake2b512,
        >(
            b"test", base, WITNESS_BIT_SIZE as u16, NUM_CHUNKS as u32
        );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        let sk = Fr::rand(&mut rng);
        let pk = (SECP_GEN * sk).into_affine();

        let comm_pk = PointCommitmentWithOpening::new(&mut rng, &pk, &comm_key_tom).unwrap();

        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(pk.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(pk.y().unwrap());

        let bls_comm_pk_rx = BlsFr::rand(&mut rng);
        let bls_comm_pk_ry = BlsFr::rand(&mut rng);
        let bls_comm_pk_x = comm_key_bls.commit(&pk_x, &bls_comm_pk_rx);
        let bls_comm_pk_y = comm_key_bls.commit(&pk_y, &bls_comm_pk_ry);

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let num_iters = 10;
        for i in 0..num_iters {
            let message = Fr::rand(&mut rng);
            let sig = ecdsa::Signature::new_prehashed(&mut rng, message, sk);

            let start = Instant::now();
            let transformed_sig = TransformedEcdsaSig::new(&sig, message, pk).unwrap();
            transformed_sig.verify_prehashed(message, pk).unwrap();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key_secp", &comm_key_secp);
            prover_transcript.append(b"comm_key_tom", &comm_key_tom);
            prover_transcript.append(b"comm_key_bls", &comm_key_bls);
            prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
            let pok_pubkey = ProofOfKnowledgeEcdsaPublicKey::<128>::new(
                &mut rng,
                transformed_sig,
                message,
                pk,
                comm_pk.clone(),
                &comm_key_secp,
                &comm_key_tom,
                &mut prover_transcript,
            )
            .unwrap();

            // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
            let proof_eq_pk_x = ProofLargeWitness::<
                Tom256Affine,
                BlsG1Affine,
                NUM_CHUNKS,
                WITNESS_BIT_SIZE,
                CHALLENGE_BIT_SIZE,
                ABORT_PARAM,
                RESPONSE_BYTE_SIZE,
                NUM_REPS,
            >::new(
                &mut rng,
                &comm_pk.x,
                comm_pk.r_x,
                bls_comm_pk_rx,
                &comm_key_tom,
                &comm_key_bls,
                base,
                bpp_setup_params.clone(),
                &mut prover_transcript,
            )
            .unwrap();

            // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
            let proof_eq_pk_y = ProofLargeWitness::<
                Tom256Affine,
                BlsG1Affine,
                NUM_CHUNKS,
                WITNESS_BIT_SIZE,
                CHALLENGE_BIT_SIZE,
                ABORT_PARAM,
                RESPONSE_BYTE_SIZE,
                NUM_REPS,
            >::new(
                &mut rng,
                &comm_pk.y,
                comm_pk.r_y,
                bls_comm_pk_ry,
                &comm_key_tom,
                &comm_key_bls,
                base,
                bpp_setup_params.clone(),
                &mut prover_transcript,
            )
            .unwrap();
            prov_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
            verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
            verifier_transcript.append(b"comm_key_bls", &comm_key_bls);
            verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
            pok_pubkey
                .verify(
                    message,
                    &comm_pk.comm,
                    &comm_key_secp,
                    &comm_key_tom,
                    &mut verifier_transcript,
                )
                .unwrap();

            proof_eq_pk_x
                .verify(
                    &comm_pk.comm.x,
                    &bls_comm_pk_x,
                    &comm_key_tom,
                    &comm_key_bls,
                    &bpp_setup_params,
                    &mut verifier_transcript,
                )
                .unwrap();

            proof_eq_pk_y
                .verify(
                    &comm_pk.comm.y,
                    &bls_comm_pk_y,
                    &comm_key_tom,
                    &comm_key_bls,
                    &bpp_setup_params,
                    &mut verifier_transcript,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            if i == 0 {
                let s_pk = pok_pubkey.compressed_size();
                let s_pk_x = proof_eq_pk_x.compressed_size();
                let s_pk_y = proof_eq_pk_y.compressed_size();
                println!(
                    "Total proof size = {} bytes. Proof size for equality of committed x and y coordinates = {} bytes",
                    s_pk + s_pk_x + s_pk_y, s_pk_x + s_pk_y
                );
            }
        }

        println!("For {} iterations", num_iters);
        println!("Proving time: {:?}", timing_info(prov_time));
        println!("Verifying time: {:?}", timing_info(ver_time));
    }
}
