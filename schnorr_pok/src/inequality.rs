//! Protocol to prove inequality (≠) of a discrete log in zero knowledge. Based on section 1 of this
//! [paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/U-Prove20Inequality20Proof20Extension.pdf) but is an optimized version of it.
//! We have a commitment to a value `m` as `C = g * m + h * r` and we want to prove that `m` ≠ `v` where `m` is not known to verifier but `C` and `v` are.
//! The protocol works as follows:
//! 1. Prover choose a random `a` and computes `k = -a * r`
//! 2. Prover computes `B = g * (m - v) * a`. If `B` is sent to the verifier and the verifier checks that `B` ≠ 1 then it
//! will be convinced that `m` ≠ `v`. Multiplication with `a` is necessary to stop the verifier from computing `g * m` from `B`
//! 3. `B` can also be written as `(C  - g * v) * a + h * k` as `C * a - g * v * a + h * k = g * (m-v) * a + h * r * a + h * -a * r`.
//! 4. The prover runs 3 instances of Schnorr's proof of knowledge as below:
//!     a. knowledge of `m` and `r` in `C = g * m + h * r`
//!     b. knowledge of `(m - v) * a` in `B = g * (m - v) * a`.
//!     c. knowledge of `a` and `k` in `B = (C  - g * v) * a + h * k`
//!
//! For proving inequality of 2 committed values, i.e. to prove `m1` ≠ `m2` when given commitments `C1 = g * m1 + h * r1` and `C2 = g * m2 + h * r2`,
//! use the above protocol with commitment set to `C1 - C2` and `v = 0` as `C1 - C2 = g * (m1 - m2) + h * (r1 - r2)`. If `(m1 - m2)` ≠ 0, then `m1` ≠ `m2``
//!
//! Protocol to prove inequality of two discrete logs is taken from section 6 of the paper [Practical Verifiable Encryption and Decryption of Discrete Logarithms](https://www.shoup.net/papers/verenc.pdf).
//! Here we prove that prover only knows one of the discrete log unlike above, i.e. given `y = g * x` and `z = h * k`,
//! prover and verifier know `g`, `h`, `y` and `z` and prover additionally knows `x` but not `k`.

use crate::{
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    error::SchnorrError,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use core::mem;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol};
use dock_crypto_utils::{commitment::PedersenCommitmentKey, serde_utils::ArkObjectBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove inequality of discrete log (committed in a Pedersen commitment) with either a
/// public value or another discrete log
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct DiscreteLogInequalityProtocol<G: AffineRepr> {
    /// `B = g * (m - v) * a`
    pub b: G,
    /// For proving knowledge of `m` and `r` in `C = g * m + h * r`
    pub sc_c: PokTwoDiscreteLogsProtocol<G>,
    /// For proving knowledge of `(m - v) * a` in `B = g * (m - v) * a`.
    pub sc_b: PokDiscreteLogProtocol<G>,
    /// For proving knowledge of `a` and `k` in `B = (C  - g * v) * a + h * k`
    pub sc_b_ped: PokTwoDiscreteLogsProtocol<G>,
}

/// Proof created using `DiscreteLogInequalityProtocol`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct InequalityProof<G: AffineRepr> {
    /// `B = g * (m - v) * a`
    #[serde_as(as = "ArkObjectBytes")]
    pub b: G,
    /// For proving knowledge of `m` and `r` in `C = g * m + h * r`
    pub sc_c: PokTwoDiscreteLogs<G>,
    /// For proving knowledge of `(m - v) * a` in `B = g * (m - v) * a`.
    pub sc_b: PokDiscreteLog<G>,
    /// For proving knowledge of `a` and `k` in `B = (C  - g * v) * a + h * k`
    pub sc_b_ped: PokTwoDiscreteLogs<G>,
}

impl<G: AffineRepr> DiscreteLogInequalityProtocol<G> {
    /// Initiate proof generation when proving discrete log inequality with a public value,
    /// i.e. `value` ≠ `inequal_to` given commitment `commitment = g * value + h * randomness`
    pub fn new_for_inequality_with_public_value<R: RngCore>(
        rng: &mut R,
        value: G::ScalarField,
        randomness: G::ScalarField,
        commitment: &G,
        inequal_to: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<Self, SchnorrError> {
        if &value == inequal_to {
            return Err(SchnorrError::ValueMustNotBeEqual);
        }
        let a = G::ScalarField::rand(rng);
        let k = -(randomness * a);
        let sc_c = PokTwoDiscreteLogsProtocol::init(
            value,
            G::ScalarField::rand(rng),
            &comm_key.g,
            randomness,
            G::ScalarField::rand(rng),
            &comm_key.h,
        );
        let w = (value - inequal_to) * a;
        let b = comm_key.g * w;
        let sc_b = PokDiscreteLogProtocol::init(w, G::ScalarField::rand(rng), &comm_key.g);
        let sc_b_ped = PokTwoDiscreteLogsProtocol::init(
            a,
            G::ScalarField::rand(rng),
            &Self::base_for_b(commitment, inequal_to, comm_key),
            k,
            G::ScalarField::rand(rng),
            &comm_key.h,
        );
        Ok(Self {
            b: b.into_affine(),
            sc_c,
            sc_b,
            sc_b_ped,
        })
    }

    /// Initiate proof generation when proving discrete log inequality with another discrete log,
    /// i.e. `value1` ≠ `value2` given commitments `commitment1 = g * value1 + h * randomness1` and
    /// `commitment2 = g * value2 + h * randomness2`
    pub fn new_for_inequality_with_committed_value<R: RngCore>(
        rng: &mut R,
        value1: G::ScalarField,
        randomness1: G::ScalarField,
        commitment1: &G,
        value2: G::ScalarField,
        randomness2: G::ScalarField,
        commitment2: &G,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<Self, SchnorrError> {
        if value1 == value2 {
            return Err(SchnorrError::ValueMustNotBeEqual);
        }
        Self::new_for_inequality_with_public_value(
            rng,
            value1 - value2,
            randomness1 - randomness2,
            &Self::transformed_commitments_for_committed_inequality(commitment1, commitment2),
            &G::ScalarField::zero(),
            comm_key,
        )
    }

    pub fn challenge_contribution_for_public_inequality<W: Write>(
        &self,
        commitment: &G,
        inequal_to: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(
            &self.b,
            commitment,
            inequal_to,
            &self.sc_c.t,
            &self.sc_b.t,
            &self.sc_b_ped.t,
            comm_key,
            writer,
        )
    }

    pub fn challenge_contribution_for_committed_inequality<W: Write>(
        &self,
        commitment1: &G,
        commitment2: &G,
        comm_key: &PedersenCommitmentKey<G>,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(
            &self.b,
            &Self::transformed_commitments_for_committed_inequality(commitment1, commitment2),
            &G::ScalarField::zero(),
            &self.sc_c.t,
            &self.sc_b.t,
            &self.sc_b_ped.t,
            comm_key,
            writer,
        )
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> InequalityProof<G> {
        let sc_c = mem::take(&mut self.sc_c).gen_proof(challenge);
        let sc_b = mem::take(&mut self.sc_b).gen_proof(challenge);
        let sc_b_ped = mem::take(&mut self.sc_b_ped).gen_proof(challenge);
        InequalityProof {
            b: self.b,
            sc_c,
            sc_b,
            sc_b_ped,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        b: &G,
        commitment: &G,
        inequal_to: &G::ScalarField,
        t_c: &G,
        t_b: &G,
        t_b_ped: &G,
        comm_key: &PedersenCommitmentKey<G>,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        comm_key.g.serialize_compressed(&mut writer)?;
        comm_key.h.serialize_compressed(&mut writer)?;
        commitment.serialize_compressed(&mut writer)?;
        t_c.serialize_compressed(&mut writer)?;
        b.serialize_compressed(&mut writer)?;
        t_b.serialize_compressed(&mut writer)?;
        Self::base_for_b(commitment, inequal_to, comm_key).serialize_compressed(&mut writer)?;
        t_b_ped.serialize_compressed(&mut writer)?;
        Ok(())
    }

    fn transformed_commitments_for_committed_inequality(commitment1: &G, commitment2: &G) -> G {
        (commitment1.into_group() - commitment2.into_group()).into()
    }

    /// commitment - (g * v)
    fn base_for_b(
        commitment: &G,
        inequal_to: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> G {
        (commitment.into_group() - (comm_key.g * inequal_to)).into()
    }
}

impl<G: AffineRepr> InequalityProof<G> {
    pub fn verify_for_inequality_with_public_value(
        &self,
        commitment: &G,
        inequal_to: &G::ScalarField,
        challenge: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<(), SchnorrError> {
        if self.b.is_zero() {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        if !self
            .sc_c
            .verify(commitment, &comm_key.g, &comm_key.h, challenge)
        {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        if !self.sc_b.verify(&self.b, &comm_key.g, challenge) {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        if !self.sc_b_ped.verify(
            &self.b,
            &DiscreteLogInequalityProtocol::base_for_b(commitment, inequal_to, comm_key),
            &comm_key.h,
            challenge,
        ) {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        Ok(())
    }

    pub fn verify_for_inequality_with_committed_value(
        &self,
        commitment1: &G,
        commitment2: &G,
        challenge: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<(), SchnorrError> {
        self.verify_for_inequality_with_public_value(
            &DiscreteLogInequalityProtocol::transformed_commitments_for_committed_inequality(
                commitment1,
                commitment2,
            ),
            &G::ScalarField::zero(),
            challenge,
            comm_key,
        )
    }

    pub fn challenge_contribution_for_public_inequality<W: Write>(
        &self,
        commitment: &G,
        inequal_to: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
        writer: W,
    ) -> Result<(), SchnorrError> {
        DiscreteLogInequalityProtocol::compute_challenge_contribution(
            &self.b,
            commitment,
            inequal_to,
            &self.sc_c.t,
            &self.sc_b.t,
            &self.sc_b_ped.t,
            comm_key,
            writer,
        )
    }

    pub fn challenge_contribution_for_committed_inequality<W: Write>(
        &self,
        commitment1: &G,
        commitment2: &G,
        comm_key: &PedersenCommitmentKey<G>,
        writer: W,
    ) -> Result<(), SchnorrError> {
        DiscreteLogInequalityProtocol::compute_challenge_contribution(
            &self.b,
            &DiscreteLogInequalityProtocol::transformed_commitments_for_committed_inequality(
                commitment1,
                commitment2,
            ),
            &G::ScalarField::zero(),
            &self.sc_c.t,
            &self.sc_b.t,
            &self.sc_b_ped.t,
            comm_key,
            writer,
        )
    }
}

/// Protocol to prove inequality of two discrete logs when only one of them is known to the prover.
/// Given `y = g * x` and `z = h * k`, prover and verifier know `g`, `h`, `y` and `z` and prover
/// additionally knows `x` but not `k`
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct UnknownDiscreteLogInequalityProtocol<G: AffineRepr> {
    /// `c = (h * x - z) * r`
    pub c: G,
    /// For proving knowledge of `alpha` and `beta` in `c = h * alpha - z * beta`
    pub sc_c: PokTwoDiscreteLogsProtocol<G>,
    /// For proving knowledge of `alpha` and `beta` in `0 = g * alpha - y * beta`
    pub sc_zero: PokTwoDiscreteLogsProtocol<G>,
}

/// Proof created using `UnknownDiscreteLogInequalityProtocol`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct UnknownDiscreteLogInequalityProof<G: AffineRepr> {
    /// `c = (h * x - z) * r`
    #[serde_as(as = "ArkObjectBytes")]
    pub c: G,
    /// For proving knowledge of `alpha` and `beta` in `c = h * alpha - z * beta`
    pub sc_c: PokTwoDiscreteLogs<G>,
    /// For proving knowledge of `alpha` and `beta` in `0 = g * alpha - y * beta`
    pub sc_zero: PokTwoDiscreteLogs<G>,
}

impl<G: AffineRepr> UnknownDiscreteLogInequalityProtocol<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        value: G::ScalarField,
        g: &G,
        h: &G,
        y: &G,
        z: &G,
    ) -> Result<Self, SchnorrError> {
        let beta = G::ScalarField::rand(rng);
        let alpha = value * beta;
        let minus_z = z.into_group().neg();
        let minus_y = y.into_group().neg();
        let c = (*h * alpha + minus_z * beta).into_affine();
        if c.is_zero() {
            return Err(SchnorrError::ValueMustNotBeEqual);
        }
        let alpha_blinding = G::ScalarField::rand(rng);
        let beta_blinding = G::ScalarField::rand(rng);
        let sc_c = PokTwoDiscreteLogsProtocol::init(
            alpha,
            alpha_blinding,
            h,
            beta,
            beta_blinding,
            &minus_z.into_affine(),
        );
        let sc_zero = PokTwoDiscreteLogsProtocol::init(
            alpha,
            alpha_blinding,
            g,
            beta,
            beta_blinding,
            &minus_y.into_affine(),
        );
        Ok(Self { c, sc_c, sc_zero })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g: &G,
        h: &G,
        y: &G,
        z: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(
            &self.c,
            &self.sc_c.t,
            &self.sc_zero.t,
            g,
            h,
            y,
            z,
            writer,
        )
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> UnknownDiscreteLogInequalityProof<G> {
        let sc_c = mem::take(&mut self.sc_c).gen_proof(challenge);
        let sc_zero = mem::take(&mut self.sc_zero).gen_proof(challenge);
        UnknownDiscreteLogInequalityProof {
            c: self.c,
            sc_c,
            sc_zero,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        c: &G,
        t_c: &G,
        t_zero: &G,
        g: &G,
        h: &G,
        y: &G,
        z: &G,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        let zero = G::zero();
        let minus_z = z.into_group().neg().into_affine();
        let minus_y = y.into_group().neg().into_affine();
        c.serialize_compressed(&mut writer)?;
        PokTwoDiscreteLogsProtocol::compute_challenge_contribution(
            h,
            &minus_z,
            c,
            t_c,
            &mut writer,
        )?;
        PokTwoDiscreteLogsProtocol::compute_challenge_contribution(
            g,
            &minus_y,
            &zero,
            t_zero,
            &mut writer,
        )?;
        Ok(())
    }
}

impl<G: AffineRepr> UnknownDiscreteLogInequalityProof<G> {
    pub fn challenge_contribution<W: Write>(
        &self,
        g: &G,
        h: &G,
        y: &G,
        z: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        UnknownDiscreteLogInequalityProtocol::compute_challenge_contribution(
            &self.c,
            &self.sc_c.t,
            &self.sc_zero.t,
            g,
            h,
            y,
            z,
            writer,
        )
    }

    pub fn verify(
        &self,
        g: &G,
        h: &G,
        y: &G,
        z: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), SchnorrError> {
        if self.c.is_zero() {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        // alpha and beta are same in both protocols
        if self.sc_c.response1 != self.sc_zero.response1 {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        if self.sc_c.response2 != self.sc_zero.response2 {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        let zero = G::zero();
        let minus_z = z.into_group().neg().into_affine();
        let minus_y = y.into_group().neg().into_affine();
        if !self.sc_c.verify(&self.c, h, &minus_z, challenge) {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
        if !self.sc_zero.verify(&zero, g, &minus_y, challenge) {
            return Err(SchnorrError::InvalidProofOfEquality);
        }
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
    use dock_crypto_utils::{
        commitment::PedersenCommitmentKey,
        transcript::{MerlinTranscript, Transcript},
    };

    #[test]
    fn inequality_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");
        let value = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);
        let in_equal = Fr::rand(&mut rng);
        let randomness2 = Fr::rand(&mut rng);
        assert_ne!(value, in_equal);

        let comm = (comm_key.g * value + comm_key.h * randomness).into_affine();
        let comm2 = (comm_key.g * in_equal + comm_key.h * randomness2).into_affine();

        let protocol = DiscreteLogInequalityProtocol::new_for_inequality_with_public_value(
            &mut rng, value, randomness, &comm, &in_equal, &comm_key,
        )
        .unwrap();

        let mut prover_transcript = MerlinTranscript::new(b"test");
        protocol
            .challenge_contribution_for_public_inequality(
                &comm,
                &in_equal,
                &comm_key,
                &mut prover_transcript,
            )
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"chal");

        let proof = protocol.gen_proof(&challenge_prover);

        let mut verifier_transcript = MerlinTranscript::new(b"test");
        proof
            .challenge_contribution_for_public_inequality(
                &comm,
                &in_equal,
                &comm_key,
                &mut verifier_transcript,
            )
            .unwrap();
        let challenge_verifier = verifier_transcript.challenge_scalar(b"chal");

        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify_for_inequality_with_public_value(
                &comm,
                &in_equal,
                &challenge_verifier,
                &comm_key,
            )
            .unwrap();

        let protocol = DiscreteLogInequalityProtocol::new_for_inequality_with_committed_value(
            &mut rng,
            value,
            randomness,
            &comm,
            in_equal,
            randomness2,
            &comm2,
            &comm_key,
        )
        .unwrap();

        let mut prover_transcript = MerlinTranscript::new(b"test1");
        protocol
            .challenge_contribution_for_committed_inequality(
                &comm,
                &comm2,
                &comm_key,
                &mut prover_transcript,
            )
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"chal");

        let proof = protocol.gen_proof(&challenge_prover);

        let mut verifier_transcript = MerlinTranscript::new(b"test1");
        proof
            .challenge_contribution_for_committed_inequality(
                &comm,
                &comm2,
                &comm_key,
                &mut verifier_transcript,
            )
            .unwrap();
        let challenge_verifier = verifier_transcript.challenge_scalar(b"chal");

        proof
            .verify_for_inequality_with_committed_value(
                &comm,
                &comm2,
                &challenge_verifier,
                &comm_key,
            )
            .unwrap();
    }

    #[test]
    fn unknown_inequality_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let x = Fr::rand(&mut rng);
        let k = Fr::rand(&mut rng);
        assert_ne!(x, k);
        let g = G1Affine::rand(&mut rng);
        let h = G1Affine::rand(&mut rng);
        let y = (g * x).into_affine();
        let z = (h * k).into_affine();

        let wrong_z = (h * x).into_affine();
        assert!(
            UnknownDiscreteLogInequalityProtocol::new(&mut rng, x, &g, &h, &y, &wrong_z).is_err()
        );

        let mut prover_transcript = MerlinTranscript::new(b"test");
        let protocol =
            UnknownDiscreteLogInequalityProtocol::new(&mut rng, x, &g, &h, &y, &z).unwrap();
        protocol
            .challenge_contribution(&g, &h, &y, &z, &mut prover_transcript)
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"chal");
        let proof = protocol.gen_proof(&challenge_prover);

        let mut verifier_transcript = MerlinTranscript::new(b"test");
        proof
            .challenge_contribution(&g, &h, &y, &z, &mut verifier_transcript)
            .unwrap();
        let challenge_verifier = verifier_transcript.challenge_scalar(b"chal");
        proof.verify(&g, &h, &y, &z, &challenge_verifier).unwrap();

        // Check with equal discrete log should fail
        let mut verifier_transcript = MerlinTranscript::new(b"test");
        proof
            .challenge_contribution(&g, &h, &y, &wrong_z, &mut verifier_transcript)
            .unwrap();
        let challenge_verifier = verifier_transcript.challenge_scalar(b"chal");
        assert!(proof
            .verify(&g, &h, &y, &wrong_z, &challenge_verifier)
            .is_err());
    }
}
