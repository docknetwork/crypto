//! Proof of knowledge of ECDSA signature with public key committed on a short Weierstrass curve. Is a slight variation of the protocol
//! described in section 6 of the paper [ZKAttest Ring and Group Signatures for Existing ECDSA Keys](https://eprint.iacr.org/2021/1183).
//! However, the point addition and scalar multiplication used are from the paper [CDLS: Proving Knowledge of Committed Discrete Logarithms with Soundness](https://eprint.iacr.org/2023/1595)
//!
//! To prove the knowledge of the signature, an ECDSA signature on the verifier's chosen message is generated
//! which should be verifiable using the committed public key but the signature can't be transmitted entirely as the public key
//! can be learnt from the signature.
//!
//! An ECDSA signature `(r, s)` is transformed to `(R, z=s/r)` as per the paper. The new ECDSA verification equation
//! becomes `z*R - g*t*r^-1 = q` where `q` is the public key, `g` is the generator and `t` is the hashed message.
//! This is equivalent to `-g*t*r^-1 = q + z*(-R)`
//!
//! The verifier gets a commitment to the public key `q` and `-z*R` but knows `R, t, g and r` (`r` is the truncated x coordinate of `R`).
//! Note that the verifier should not learn `z` or `s` otherwise it will learn the public key.
//!
//! Thus using the protocols for scalar multiplication and point addition, the prover proves:
//! - Given commitments to `z` and `-z*R`, the scalar multiplication of `z` and `-R` is indeed `-z*R`
//! - Given commitments to `q` and `-z*R`, the sum of `q` and `-z*R` is indeed `-g*t*r^-1`. Note that the `-g*t*r^-1` is public but
//! the point addition protocol expects all 3 points to be committed so the prover commits to `-g*t*r^-1` and the proof
//! contains the randomness used in its commitment. The verifier can itself compute `-g*t*r^-1` so using the randomness in the proof,
//! it computes the same commitment to `-g*t*r^-1` as the prover's. So I could use a point addition protocol where the resulting point
//! isn't committed but that protocol isn't going to be any better than the currently implemented one.
//!
//! Generic over the ECDSA curve `C0` and the cycle curve `C1` (whose scalar field matches the base field of `C0`).

#![allow(non_snake_case)]

use crate::{
    ec::{
        commitments::{
            CommitmentWithOpening, PointCommitment, PointCommitmentWithOpening, SWPoint,
        },
        sw_point_addition::{PointAdditionProof, PointAdditionProtocol},
        sw_scalar_mult::{ScalarMultiplicationProof, ScalarMultiplicationProtocol},
    },
    error::Error,
    tom256,
};
use ark_ec::{short_weierstrass::Affine, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker,
};
use kvac::bbs_sharp::ecdsa;

/// ECDSA signature but transformed to be more suitable for the zero knowledge proof.
/// Generic over the ECDSA curve `C`.
pub struct TransformedEcdsaSig<C: SWPoint>
where
    C::BaseField: PrimeField,
{
    pub R: Affine<C>,
    pub z: C::ScalarField,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PoKEcdsaSigCommittedPublicKeyProtocol<
    C0: SWPoint,
    C1: SWPoint<ScalarField = C0::BaseField>,
    const NUM_REPS_SCALAR_MULT: usize = 128,
> where
    C0::BaseField: PrimeField,
{
    /// Point R from signature
    pub R: Affine<C0>,
    /// Commitment to scalar `z`
    pub comm_z: Affine<C0>,
    /// Commitment to coordinates of `-z*R`
    pub comm_minus_zR: PointCommitment<C1>,
    /// Randomness in the commitment to coordinates of `-g*t*r^-1` so verifier can create the same commitment
    /// to `-g*t*r^-1` as the prover.
    pub comm_minus_g_t_r_inv_rand: (C1::ScalarField, C1::ScalarField),
    /// Protocol for relation `z * -R = -z*R`
    pub protocol_minus_zR: ScalarMultiplicationProtocol<C0, C1, NUM_REPS_SCALAR_MULT>,
    /// Protocol for relation `-g*t*r^-1 = q + z*(-R)`
    pub protocol_add: PointAdditionProtocol<C0, C1>,
}

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKEcdsaSigCommittedPublicKey<
    C0: SWPoint,
    C1: SWPoint<ScalarField = C0::BaseField>,
    const NUM_REPS_SCALAR_MULT: usize = 128,
> where
    C0::BaseField: PrimeField,
{
    /// Point R from signature
    pub R: Affine<C0>,
    /// Commitment to scalar `z`
    pub comm_z: Affine<C0>,
    /// Commitment to coordinates of `-z*R`
    pub comm_minus_zR: PointCommitment<C1>,
    /// Randomness in the commitment to coordinates of `-g*t*r^-1` so verifier can create the same commitment
    /// to `-g*t*r^-1` as the prover.
    pub comm_minus_g_t_r_inv_rand: (C1::ScalarField, C1::ScalarField),
    /// Proof of relation `z * -R = -z*R`
    pub proof_minus_zR: ScalarMultiplicationProof<C0, C1, NUM_REPS_SCALAR_MULT>,
    /// Proof of relation `-g*t*r^-1 = q + z*(-R)`
    pub proof_add: PointAdditionProof<C0, C1>,
}

impl<C: SWPoint> TransformedEcdsaSig<C>
where
    C::BaseField: PrimeField,
{
    pub fn new(
        sig: &ecdsa::Signature<C>,
        hashed_message: C::ScalarField,
        public_key: Affine<C>,
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
        let R = (C::GENERATOR * u1 + public_key * u2).into_affine();
        Ok(Self {
            R,
            z: sig.response * r_inv,
        })
    }

    pub fn verify_prehashed(
        &self,
        hashed_message: C::ScalarField,
        public_key: Affine<C>,
    ) -> Result<(), Error> {
        let r_inv = Self::r_inv(&self.R)?;
        let t_r_inv = hashed_message * r_inv;
        let zR = self.R * self.z;
        if (zR - (C::GENERATOR * t_r_inv)) != public_key.into_group() {
            return Err(Error::InvalidTransformedEcdsaSig);
        }
        Ok(())
    }

    pub fn r_inv(R: &Affine<C>) -> Result<C::ScalarField, Error> {
        let x_scalar = C::ScalarField::from_le_bytes_mod_order(&R.x.into_bigint().to_bytes_le());
        x_scalar
            .inverse()
            .ok_or(Error::EcdsaSigResponseNotInvertible)
    }
}

impl<C0: SWPoint, C1: SWPoint<ScalarField = C0::BaseField>, const NUM_REPS_SCALAR_MULT: usize>
    PoKEcdsaSigCommittedPublicKeyProtocol<C0, C1, NUM_REPS_SCALAR_MULT>
where
    C0::BaseField: PrimeField,
{
    /// Prove that the (transformed) ECDSA signature on the pre-hashed message `hashed_message` can
    /// be verified by the public key `public_key`. `comm_public_key` is the commitment to the
    /// coordinates of the public key point
    pub fn init<R: RngCore>(
        rng: &mut R,
        sig: TransformedEcdsaSig<C0>,
        hashed_message: C0::ScalarField,
        public_key: Affine<C0>,
        comm_public_key: PointCommitmentWithOpening<C1>,
        comm_key_secp: &PedersenCommitmentKey<Affine<C0>>,
        comm_key_tom: &PedersenCommitmentKey<Affine<C1>>,
    ) -> Result<Self, Error> {
        let minus_R = sig.R.neg();
        let minus_zR = (minus_R * sig.z).into_affine();
        // -g*t*r^-1
        let minus_g_t_r_inv = (C0::GENERATOR
            * (hashed_message * TransformedEcdsaSig::<C0>::r_inv(&sig.R)?))
        .neg()
        .into_affine();
        let comm_z = CommitmentWithOpening::new(rng, sig.z, comm_key_secp);
        let comm_minus_zR = PointCommitmentWithOpening::new(rng, &minus_zR, comm_key_tom)?;
        let comm_minus_g_t_r_inv =
            PointCommitmentWithOpening::new(rng, &minus_g_t_r_inv, comm_key_tom)?;
        let protocol_minus_zR = ScalarMultiplicationProtocol::<C0, C1, NUM_REPS_SCALAR_MULT>::init(
            rng,
            comm_z.clone(),
            comm_minus_zR.clone(),
            minus_zR,
            minus_R,
            comm_key_secp,
            comm_key_tom,
        )?;
        let protocol_add = PointAdditionProtocol::init(
            rng,
            comm_minus_zR.clone(),
            comm_public_key.clone(),
            comm_minus_g_t_r_inv.clone(),
            minus_zR,
            public_key,
            minus_g_t_r_inv,
            comm_key_tom,
        )?;
        Ok(Self {
            R: sig.R,
            comm_z: comm_z.comm,
            comm_minus_zR: comm_minus_zR.comm,
            comm_minus_g_t_r_inv_rand: (comm_minus_g_t_r_inv.r_x, comm_minus_g_t_r_inv.r_y),
            protocol_minus_zR,
            protocol_add,
        })
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.R.serialize_compressed(&mut writer)?;
        self.comm_z.serialize_compressed(&mut writer)?;
        self.comm_minus_zR.serialize_compressed(&mut writer)?;
        self.comm_minus_g_t_r_inv_rand
            .0
            .serialize_compressed(&mut writer)?;
        self.comm_minus_g_t_r_inv_rand
            .1
            .serialize_compressed(&mut writer)?;
        self.protocol_minus_zR.challenge_contribution(&mut writer)?;
        self.protocol_add.challenge_contribution(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(
        self,
        challenge: &C1::ScalarField,
    ) -> PoKEcdsaSigCommittedPublicKey<C0, C1, NUM_REPS_SCALAR_MULT> {
        let challenge_bytes = challenge.clone().into_bigint().to_bytes_le();
        let proof_minus_zR = self.protocol_minus_zR.gen_proof(&challenge_bytes);
        let proof_add = self.protocol_add.gen_proof(challenge);
        PoKEcdsaSigCommittedPublicKey {
            R: self.R,
            comm_z: self.comm_z,
            comm_minus_zR: self.comm_minus_zR,
            comm_minus_g_t_r_inv_rand: self.comm_minus_g_t_r_inv_rand,
            proof_minus_zR,
            proof_add,
        }
    }
}

impl<C0: SWPoint, C1: SWPoint<ScalarField = C0::BaseField>, const NUM_REPS_SCALAR_MULT: usize>
    PoKEcdsaSigCommittedPublicKey<C0, C1, NUM_REPS_SCALAR_MULT>
where
    C0::BaseField: PrimeField,
{
    /// Proof that the (transformed) ECDSA signature on the pre-hashed message `hashed_message` can
    /// be verified by the committed public key. `comm_public_key` is the commitment to the
    /// coordinates of the public key point
    pub fn verify(
        &self,
        hashed_message: C0::ScalarField,
        comm_public_key: &PointCommitment<C1>,
        challenge: &C1::ScalarField,
        comm_key_secp: &PedersenCommitmentKey<Affine<C0>>,
        comm_key_tom: &PedersenCommitmentKey<Affine<C1>>,
    ) -> Result<(), Error> {
        let minus_R = self.R.neg();
        let minus_g_t_r_inv = (C0::GENERATOR
            * (hashed_message * TransformedEcdsaSig::<C0>::r_inv(&self.R)?))
        .neg()
        .into_affine();
        let comm_minus_g_t_r_inv = PointCommitmentWithOpening::new_given_randomness(
            &minus_g_t_r_inv,
            self.comm_minus_g_t_r_inv_rand.0,
            self.comm_minus_g_t_r_inv_rand.1,
            comm_key_tom,
        )?;
        let challenge_bytes = challenge.clone().into_bigint().to_bytes_le();
        self.proof_minus_zR.verify(
            &self.comm_z,
            &self.comm_minus_zR,
            &minus_R,
            &challenge_bytes,
            comm_key_secp,
            comm_key_tom,
        )?;
        self.proof_add.verify(
            &self.comm_minus_zR,
            comm_public_key,
            &comm_minus_g_t_r_inv.comm,
            challenge,
            comm_key_tom,
        )?;
        Ok(())
    }

    /// Same as `Self::verify` but delegated the scalar multiplication checks to `RandomizedMultChecker`
    pub fn verify_using_randomized_mult_checker(
        &self,
        hashed_message: C0::ScalarField,
        comm_public_key: PointCommitment<C1>,
        challenge: &C1::ScalarField,
        comm_key_secp: PedersenCommitmentKey<Affine<C0>>,
        comm_key_tom: PedersenCommitmentKey<Affine<C1>>,
        rmc_1: &mut RandomizedMultChecker<Affine<C0>>,
        rmc_2: &mut RandomizedMultChecker<Affine<C1>>,
    ) -> Result<(), Error> {
        let minus_R = self.R.neg();
        let minus_g_t_r_inv = (C0::GENERATOR
            * (hashed_message * TransformedEcdsaSig::<C0>::r_inv(&self.R)?))
        .neg()
        .into_affine();
        let comm_minus_g_t_r_inv = PointCommitmentWithOpening::new_given_randomness(
            &minus_g_t_r_inv,
            self.comm_minus_g_t_r_inv_rand.0,
            self.comm_minus_g_t_r_inv_rand.1,
            &comm_key_tom,
        )?;
        let challenge_bytes = challenge.clone().into_bigint().to_bytes_le();
        self.proof_minus_zR.verify_using_randomized_mult_checker(
            self.comm_z,
            self.comm_minus_zR,
            minus_R,
            &challenge_bytes,
            comm_key_secp,
            comm_key_tom,
            rmc_1,
            rmc_2,
        )?;
        self.proof_add.verify_using_randomized_mult_checker(
            self.comm_minus_zR,
            comm_public_key,
            comm_minus_g_t_r_inv.comm,
            challenge,
            comm_key_tom,
            rmc_2,
        )?;
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.R.serialize_compressed(&mut writer)?;
        self.comm_z.serialize_compressed(&mut writer)?;
        self.comm_minus_zR.serialize_compressed(&mut writer)?;
        self.comm_minus_g_t_r_inv_rand
            .0
            .serialize_compressed(&mut writer)?;
        self.comm_minus_g_t_r_inv_rand
            .1
            .serialize_compressed(&mut writer)?;
        self.proof_minus_zR.challenge_contribution(&mut writer)?;
        self.proof_add.challenge_contribution(&mut writer)?;
        Ok(())
    }
}

/// Type alias using secp256r1 as the ECDSA curve and tom256 as the cycle curve.
pub type TransformedEcdsaSigP256 = TransformedEcdsaSig<ark_secp256r1::Config>;
pub type PoKEcdsaSigCommittedPublicKeyProtocolP256 =
    PoKEcdsaSigCommittedPublicKeyProtocol<ark_secp256r1::Config, tom256::Config>;
pub type PoKEcdsaSigCommittedPublicKeyP256 =
    PoKEcdsaSigCommittedPublicKey<ark_secp256r1::Config, tom256::Config>;

/// Type alias using secp256k1 as the ECDSA curve and secq256k1 as the cycle curve.
pub type TransformedEcdsaSigK1 = TransformedEcdsaSig<ark_secp256k1::Config>;
pub type PoKEcdsaSigCommittedPublicKeyProtocolK1 =
    PoKEcdsaSigCommittedPublicKeyProtocol<ark_secp256k1::Config, ark_secq256k1::Config>;
pub type PoKEcdsaSigCommittedPublicKeyK1 =
    PoKEcdsaSigCommittedPublicKey<ark_secp256k1::Config, ark_secq256k1::Config>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ec::commitments::{from_base_field_to_scalar_field, SWPoint},
        eq_across_groups::ProofLargeWitness,
    };
    use ark_bls12_381::{Fr as BlsFr, G1Affine as BlsG1Affine};
    use ark_secp256k1::Fq as K1Fq;
    use ark_secp256r1::Fq as P256Fq;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
    use dock_crypto_utils::{
        randomized_mult_checker::RandomizedMultChecker,
        transcript::{new_merlin_transcript, Transcript},
    };
    use rand_core::OsRng;
    use std::time::Instant;
    use test_utils::statistics::statistics;

    fn test_transformed_sig_verify<C: SWPoint>()
    where
        C::BaseField: PrimeField,
    {
        let mut rng = StdRng::seed_from_u64(0u64);
        let sk = C::ScalarField::rand(&mut rng);
        let pk = (C::GENERATOR * sk).into_affine();

        let message = C::ScalarField::rand(&mut rng);
        let sig = ecdsa::Signature::<C>::new_prehashed(&mut rng, message, sk);
        sig.verify_prehashed(message, pk).unwrap();

        let transformed_sig = TransformedEcdsaSig::<C>::new(&sig, message, pk).unwrap();
        transformed_sig.verify_prehashed(message, pk).unwrap();
    }

    fn test_pok_ecdsa_sig_comm_pubkey<C0: SWPoint, C1: SWPoint<ScalarField = C0::BaseField>>()
    where
        C0::BaseField: PrimeField,
    {
        let mut rng = OsRng::default();

        let comm_key_secp = PedersenCommitmentKey::<Affine<C0>>::new::<Blake2b512>(b"test1");
        let comm_key_tom = PedersenCommitmentKey::<Affine<C1>>::new::<Blake2b512>(b"test2");

        let sk = C0::ScalarField::rand(&mut rng);
        let pk = (C0::GENERATOR * sk).into_affine();

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let mut ver_rmc_time = vec![];
        let num_iters = 10;
        for i in 0..num_iters {
            let message = C0::ScalarField::rand(&mut rng);
            let sig = ecdsa::Signature::<C0>::new_prehashed(&mut rng, message, sk);
            let transformed_sig = TransformedEcdsaSig::<C0>::new(&sig, message, pk).unwrap();
            transformed_sig.verify_prehashed(message, pk).unwrap();

            let comm_pk = PointCommitmentWithOpening::new(&mut rng, &pk, &comm_key_tom).unwrap();

            let start = Instant::now();
            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key_secp", &comm_key_secp);
            prover_transcript.append(b"comm_key_tom", &comm_key_tom);
            prover_transcript.append(b"comm_pk", &comm_pk.comm);
            prover_transcript.append(b"message", &message);

            let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<C0, C1, 128>::init(
                &mut rng,
                transformed_sig,
                message,
                pk,
                comm_pk.clone(),
                &comm_key_secp,
                &comm_key_tom,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge_prover);
            prov_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
            verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
            verifier_transcript.append(b"comm_pk", &comm_pk.comm);
            verifier_transcript.append(b"message", &message);

            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
            assert_eq!(challenge_prover, challenge_verifier);
            proof
                .verify(
                    message,
                    &comm_pk.comm,
                    &challenge_verifier,
                    &comm_key_secp,
                    &comm_key_tom,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
            verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
            verifier_transcript.append(b"comm_pk", &comm_pk.comm);
            verifier_transcript.append(b"message", &message);

            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
            assert_eq!(challenge_prover, challenge_verifier);

            let mut checker_1 = RandomizedMultChecker::<Affine<C0>>::new_using_rng(&mut rng);
            let mut checker_2 = RandomizedMultChecker::<Affine<C1>>::new_using_rng(&mut rng);

            proof
                .verify_using_randomized_mult_checker(
                    message,
                    comm_pk.comm,
                    &challenge_verifier,
                    comm_key_secp.clone(),
                    comm_key_tom.clone(),
                    &mut checker_1,
                    &mut checker_2,
                )
                .unwrap();
            checker_1.verify().unwrap();
            checker_2.verify().unwrap();
            ver_rmc_time.push(start.elapsed());

            if i == 0 {
                println!("Proof size = {} bytes", proof.compressed_size());
            }
        }

        println!("For {num_iters} iterations");
        println!("Proving time: {:?}", statistics(prov_time));
        println!("Verifying time: {:?}", statistics(ver_time));
        println!(
            "Verifying time with randomized multiplication check: {:?}",
            statistics(ver_rmc_time)
        );
    }

    fn test_pok_ecdsa_pubkey_committed_in_bls12_381_commitment<
        C0: SWPoint,
        C1: SWPoint<ScalarField = C0::BaseField>,
    >()
    where
        C0::BaseField: PrimeField,
    {
        let mut rng = OsRng::default();

        const WITNESS_BIT_SIZE: usize = 64;
        const CHALLENGE_BIT_SIZE: usize = 180;
        const ABORT_PARAM: usize = 8;
        const RESPONSE_BYTE_SIZE: usize = 32;
        const NUM_REPS: usize = 1;
        const NUM_CHUNKS: usize = 4;

        let comm_key_secp = PedersenCommitmentKey::<Affine<C0>>::new::<Blake2b512>(b"test1");
        let comm_key_tom = PedersenCommitmentKey::<Affine<C1>>::new::<Blake2b512>(b"test2");
        let comm_key_bls = PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>(b"test3");

        // Bulletproofs++ setup
        let base = 2;
        let mut bpp_setup_params = BppSetupParams::<Affine<C1>>::new_for_perfect_range_proof::<
            Blake2b512,
        >(
            b"test", base, WITNESS_BIT_SIZE as u16, NUM_CHUNKS as u32
        );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        // ECDSA public key setup
        let sk = C0::ScalarField::rand(&mut rng);
        let pk = (C0::GENERATOR * sk).into_affine();

        // Commit to ECDSA public key on cycle curve
        let comm_pk = PointCommitmentWithOpening::new(&mut rng, &pk, &comm_key_tom).unwrap();

        // Commit to ECDSA public key on BLS12-381 curve
        let pk_x = from_base_field_to_scalar_field::<C0::BaseField, BlsFr>(pk.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<C0::BaseField, BlsFr>(pk.y().unwrap());
        let bls_comm_pk_rx = BlsFr::rand(&mut rng);
        let bls_comm_pk_ry = BlsFr::rand(&mut rng);
        let bls_comm_pk_x = comm_key_bls.commit(&pk_x, &bls_comm_pk_rx);
        let bls_comm_pk_y = comm_key_bls.commit(&pk_y, &bls_comm_pk_ry);

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let num_iters = 10;
        for i in 0..num_iters {
            let message = C0::ScalarField::rand(&mut rng);
            let sig = ecdsa::Signature::<C0>::new_prehashed(&mut rng, message, sk);

            let start = Instant::now();
            let transformed_sig = TransformedEcdsaSig::<C0>::new(&sig, message, pk).unwrap();
            transformed_sig.verify_prehashed(message, pk).unwrap();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key_secp", &comm_key_secp);
            prover_transcript.append(b"comm_key_tom", &comm_key_tom);
            prover_transcript.append(b"comm_key_bls", &comm_key_bls);
            prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
            prover_transcript.append(b"comm_pk", &comm_pk.comm);
            prover_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
            prover_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
            prover_transcript.append(b"message", &message);

            let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<C0, C1, 128>::init(
                &mut rng,
                transformed_sig,
                message,
                pk,
                comm_pk.clone(),
                &comm_key_secp,
                &comm_key_tom,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge_prover);

            // Proof that x coordinate is same in both cycle curve and BLS12-381 commitments
            let proof_eq_pk_x = ProofLargeWitness::<
                Affine<C1>,
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

            // Proof that y coordinate is same in both cycle curve and BLS12-381 commitments
            let proof_eq_pk_y = ProofLargeWitness::<
                Affine<C1>,
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
            verifier_transcript.append(b"comm_pk", &comm_pk.comm);
            verifier_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
            verifier_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
            verifier_transcript.append(b"message", &message);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();

            let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
            assert_eq!(challenge_prover, challenge_verifier);

            proof
                .verify(
                    message,
                    &comm_pk.comm,
                    &challenge_verifier,
                    &comm_key_secp,
                    &comm_key_tom,
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
                    None,
                    None,
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
                    None,
                    None,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            if i == 0 {
                println!(
                    "Total proof size = {} bytes",
                    proof.compressed_size()
                        + proof_eq_pk_x.compressed_size()
                        + proof_eq_pk_y.compressed_size()
                );
                println!(
                    "Proof size for equality of committed x and y coordinates = {} bytes",
                    proof_eq_pk_x.compressed_size() + proof_eq_pk_y.compressed_size()
                );
            }
        }

        println!("For {} iterations", num_iters);
        println!("Proving time: {:?}", statistics(prov_time));
        println!("Verifying time: {:?}", statistics(ver_time));
    }

    #[test]
    fn transformed_sig_verify_p256() {
        test_transformed_sig_verify::<ark_secp256r1::Config>();
    }

    #[test]
    fn transformed_sig_verify_k1() {
        test_transformed_sig_verify::<ark_secp256k1::Config>();
    }

    #[test]
    fn pok_ecdsa_sig_comm_pubkey_p256() {
        test_pok_ecdsa_sig_comm_pubkey::<ark_secp256r1::Config, tom256::Config>();
    }

    #[test]
    fn pok_ecdsa_sig_comm_pubkey_k1() {
        test_pok_ecdsa_sig_comm_pubkey::<ark_secp256k1::Config, ark_secq256k1::Config>();
    }

    #[test]
    fn pok_ecdsa_pubkey_committed_in_bls12_381_commitment_p256() {
        test_pok_ecdsa_pubkey_committed_in_bls12_381_commitment::<
            ark_secp256r1::Config,
            tom256::Config,
        >();
    }

    #[test]
    fn pok_ecdsa_pubkey_committed_in_bls12_381_commitment_k1() {
        test_pok_ecdsa_pubkey_committed_in_bls12_381_commitment::<
            ark_secp256k1::Config,
            ark_secq256k1::Config,
        >();
    }
}
