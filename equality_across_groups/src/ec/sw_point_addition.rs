//! Proof of point addition on short Weierstrass curve. Is a variation of the protocol described in section 4 of the paper [ZKAttest Ring and Group Signatures for Existing ECDSA Keys](https://eprint.iacr.org/2021/1183)
//!
//! The paper describes a version where the 3 points, 2 being added and the resulting points are committed but this
//! implements the version where the resulting point isn't committed as that's what's required by the other protocols.
//!
//! Following is a description of the protocol:
//!
//! Proof that points `a + b = t` with coordinates `a = (ax, ay), b = (bx, by), t = (tx, ty)`. The prover and verifier both have
//! commitments to points `a` and `b` that is Pedersen commitments to each of the 4 coordinates, `ax, ay, bx, by` and both of them
//! know `t = (tx, ty)`. The prover also knows the openings of the 4 Pedersen commitments.
//!
//! The addition formula for points is:
//!
//! `tx = lambda^2 * (bx + ax)` and `ty = lambda * (ax - tx) - ay` where `lambda = (by - ay)/(bx - ax)`. Note that paper has a typo for `ty`'s formula.
//!
//! Since the verifier has Pedersen commitments to `a = (ax, ay), b = (bx, by)` and these are homomorphic,
//! verifier can create commitments to `(by - ay), (bx - ax), (bx + ax)` on its own.
//!
//! For proving correctness of the `x` coordinate, i.e. `tx`,
//!
//! The prover:
//!  - commits to `(bx - ax)^-1` and proves that its inverse of `(bx - ax)`
//!  - commits to `lambda` and proves that its product of `(by - ay)` and `(bx - ax)^-1`
//!  - commits to `lambda^2` and proves its square of `lambda`
//!  - shares the commitments of `lambda, lambda^2` and the opening of the commitment to `lambda^2 * (bx + ax)`. This opening is the `x` coordinate of the sum.
//!
//! The verifier:
//!  - creates commitment to `(bx - ax)` verifies proof of correctness of `(bx - ax)^-1` using inverse relation proof
//!  - creates commitment to `(by - ay)` and verifies proof of correctness of `lambda` using product relation proof
//!  - verifies proof of correctness of `lambda^2` using square relation proof
//!  - creates the commitment `lambda^2 * (bx + ax)` on its own and checks that the prover's given opening is indeed the opening.
//!
//! For proving correctness of the `y` coordinate, i.e. `ty` where `ty = lambda * (ax - tx) - ay = lambda * ax - lambda * tx - ay`
//!
//! The prover:
//! - commits to `lambda * ax` and proves that its product of `lambda` and `ax`
//! - shares the opening of the commitment to `lambda * ax - lambda * tx - ay`. This opening is the `y` coordinate of the sum.
//!
//! The verifier:
//!  - verifies proof of correctness of `lambda * ax` using product relation proof
//!  - creates the commitment `lambda * tx` on its own by multiplying commitment to `lambda` by `tx`
//!  - creates the commitment `lambda * ax - lambda * tx - ay` on its own and checks that the prover's given opening is indeed the opening.

use crate::{
    ec::commitments::{
        point_coords_as_scalar_field_elements, CommitmentWithOpening, PointCommitment,
        PointCommitmentWithOpening,
    },
    error::Error,
};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, marker::PhantomData, rand::RngCore, vec::Vec};
use dock_crypto_utils::{commitment::PedersenCommitmentKey, transcript::Transcript};
use schnorr_pok::product_relations::{
    InverseProof, InverseProtocol, ProductProof, ProductProtocol, SquareProof, SquareProtocol,
};

/// Proof of point addition when only the commitments to the points being added is known to the verifier but the verifier
/// knows the resulting point in plain.
/// `P` is the curve where the points live and `C` is the curve where commitments (to their coordinates) live.
#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PointAdditionProof<P: AffineRepr, C: AffineRepr> {
    /// Commitment to `(bx - ax)^-1`
    pub comm_bx_minus_ax_inv: C,
    /// Commitment to `lambda`
    pub comm_lambda: C,
    /// Commitment to `lambda^2`
    pub comm_lambda_sqr: C,
    /// Commitment to `lambda * ax`
    pub comm_lambda_ax: C,
    /// Proof of knowledge and correctness of `(bx - ax)^-1`
    pub bx_minus_ax_inv_proof: InverseProof<C>,
    /// Proof of knowledge and correctness of `lambda`
    pub lambda_proof: ProductProof<C>,
    /// Proof of knowledge and correctness of `lambda^2`
    pub lambda_sqr_proof: SquareProof<C>,
    /// Proof of knowledge and correctness of `lambda * ax`
    pub lambda_ax_proof: ProductProof<C>,
    /// Opening of the commitment to `lambda^2 * (bx + ax)`
    pub tx_opening: (C::ScalarField, C::ScalarField),
    /// Opening of the commitment to `lambda * ax - lambda * tx - ay`
    pub ty_opening: (C::ScalarField, C::ScalarField),
    _phantom: PhantomData<P>,
}

impl<P: AffineRepr, C: AffineRepr> PointAdditionProof<P, C> {
    /// Prove that `a + b = t`. `comm_a` and `comm_b` are commitments to `a` and `b` respectively.
    pub fn new<R: RngCore>(
        rng: &mut R,
        comm_a: PointCommitmentWithOpening<C>,
        comm_b: PointCommitmentWithOpening<C>,
        a: P,
        b: P,
        t: P,
        comm_key: &PedersenCommitmentKey<C>,
        mut transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<Self, Error> {
        Self::ensure_addition_possible(&a, &b, &t)?;
        if a + b != t.into_group() {
            return Err(Error::InvalidPointAddResult);
        }
        let (tx, ty) = point_coords_as_scalar_field_elements::<P, C>(&t)?;
        let comm_b_minus_a = &comm_b - &comm_a;

        let by_minus_ay = comm_b_minus_a.y;
        let bx_minus_ax = comm_b_minus_a.x;

        let bx_minus_ax_inv = bx_minus_ax.inverse().unwrap();
        let comm_bx_minus_ax_inv = CommitmentWithOpening::new(rng, bx_minus_ax_inv, comm_key);

        let lambda = by_minus_ay * bx_minus_ax_inv;
        let comm_lambda = CommitmentWithOpening::new(rng, lambda, comm_key);

        let lambda_sqr = lambda.square();
        let comm_lambda_sqr = CommitmentWithOpening::new(rng, lambda_sqr, comm_key);

        let lambda_ax = lambda * comm_a.x;
        let comm_lambda_ax = CommitmentWithOpening::new(rng, lambda_ax, comm_key);

        let bx_plus_ax = comm_b.x + comm_a.x;

        transcript.append(b"comm_bx_minus_ax_inv", &comm_bx_minus_ax_inv.comm);
        transcript.append(b"comm_lambda", &comm_lambda.comm);
        transcript.append(b"comm_lambda^2", &comm_lambda_sqr.comm);
        transcript.append(b"comm_lambda_ax", &comm_lambda_ax.comm);

        let bx_minus_ax_inv_prot = InverseProtocol::new(
            rng,
            &comm_b_minus_a.comm.x,
            bx_minus_ax,
            bx_minus_ax_inv,
            comm_b_minus_a.r_x,
            comm_bx_minus_ax_inv.randomness,
            comm_key,
        );
        bx_minus_ax_inv_prot.challenge_contribution(&mut transcript);

        let lambda_prot = ProductProtocol::<C>::new(
            rng,
            &comm_b_minus_a.comm.y,
            by_minus_ay,
            bx_minus_ax_inv,
            lambda,
            comm_b_minus_a.r_y,
            comm_bx_minus_ax_inv.randomness,
            comm_lambda.randomness,
            comm_key,
        );
        lambda_prot.challenge_contribution(&mut transcript);

        let lambda_sqr_prot = SquareProtocol::new(
            rng,
            &comm_lambda.comm,
            lambda,
            lambda_sqr,
            comm_lambda.randomness,
            comm_lambda_sqr.randomness,
            comm_key,
        );
        lambda_sqr_prot.challenge_contribution(&mut transcript);

        let lambda_ax_prot = ProductProtocol::<C>::new(
            rng,
            &comm_lambda.comm,
            lambda,
            comm_a.x,
            lambda_ax,
            comm_lambda.randomness,
            comm_a.r_x,
            comm_lambda_ax.randomness,
            comm_key,
        );
        lambda_ax_prot.challenge_contribution(&mut transcript);

        let challenge = transcript.challenge_scalar(b"challenge for SW point addition");

        let bx_minus_ax_inv_proof = bx_minus_ax_inv_prot.gen_proof(&challenge);
        let lambda_proof = lambda_prot.gen_proof(&challenge);
        let lambda_sqr_proof = lambda_sqr_prot.gen_proof(&challenge);
        let lambda_ax_proof = lambda_ax_prot.gen_proof(&challenge);

        let tx_opening = (
            lambda_sqr - bx_plus_ax,
            comm_lambda_sqr.randomness - (comm_b.r_x + comm_a.r_x),
        );
        debug_assert_eq!(tx, tx_opening.0);

        let ty_opening = (
            lambda_ax - (lambda * tx) - comm_a.y,
            comm_lambda_ax.randomness - (comm_lambda.randomness * tx) - comm_a.r_y,
        );
        debug_assert_eq!(ty, ty_opening.0);

        Ok(Self {
            comm_bx_minus_ax_inv: comm_bx_minus_ax_inv.comm,
            comm_lambda: comm_lambda.comm,
            comm_lambda_sqr: comm_lambda_sqr.comm,
            comm_lambda_ax: comm_lambda_ax.comm,
            bx_minus_ax_inv_proof,
            lambda_proof,
            lambda_sqr_proof,
            lambda_ax_proof,
            tx_opening,
            ty_opening,
            _phantom: PhantomData::default(),
        })
    }

    /// Check the proof that `a + b = t`
    /// Its assumed that verifier "trusts" that commitment to point `a` and `b` are `comm_a` and `comm_b` respectively
    pub fn verify(
        &self,
        comm_a: &PointCommitment<C>,
        comm_b: &PointCommitment<C>,
        t: &P,
        comm_key: &PedersenCommitmentKey<C>,
        mut transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<(), Error> {
        let comm_b_minus_a = comm_b - comm_a;

        let bx_plus_ax = comm_b.x + comm_a.x;

        let (tx, ty) = point_coords_as_scalar_field_elements::<P, C>(t)?;

        transcript.append(b"comm_bx_minus_ax_inv", &self.comm_bx_minus_ax_inv);
        transcript.append(b"comm_lambda", &self.comm_lambda);
        transcript.append(b"comm_lambda^2", &self.comm_lambda_sqr);
        transcript.append(b"comm_lambda_ax", &self.comm_lambda_ax);

        self.bx_minus_ax_inv_proof
            .challenge_contribution(&mut transcript);
        self.lambda_proof.challenge_contribution(&mut transcript);
        self.lambda_sqr_proof
            .challenge_contribution(&mut transcript);
        self.lambda_ax_proof.challenge_contribution(&mut transcript);

        let challenge = transcript.challenge_scalar(b"challenge for SW point addition");

        if !self.bx_minus_ax_inv_proof.verify(
            comm_b_minus_a.x,
            self.comm_bx_minus_ax_inv,
            &challenge,
            comm_key,
        ) {
            return Err(Error::InverseProofFailed);
        }

        if !self.lambda_proof.verify(
            comm_b_minus_a.y,
            self.comm_bx_minus_ax_inv,
            self.comm_lambda,
            &challenge,
            comm_key,
        ) {
            return Err(Error::LambdaProofFailed);
        }

        if !self.lambda_sqr_proof.verify(
            self.comm_lambda,
            self.comm_lambda_sqr,
            &challenge,
            comm_key,
        ) {
            return Err(Error::LambdaProofFailed);
        }

        if comm_key.commit_as_projective(&self.tx_opening.0, &self.tx_opening.1)
            != (self.comm_lambda_sqr.into_group() - bx_plus_ax)
        {
            return Err(Error::IncorrectTxOpening);
        }
        if tx != self.tx_opening.0 {
            return Err(Error::IncorrectTx);
        }
        if comm_key.commit_as_projective(&self.ty_opening.0, &self.ty_opening.1)
            != (self.comm_lambda_ax.into_group() - (self.comm_lambda.into_group() * tx) - comm_a.y)
        {
            return Err(Error::IncorrectTyOpening);
        }
        if ty != self.ty_opening.0 {
            return Err(Error::IncorrectTy);
        }
        Ok(())
    }

    pub fn ensure_addition_possible(a: &P, b: &P, t: &P) -> Result<(), Error> {
        if a.is_zero() || b.is_zero() || t.is_zero() {
            return Err(Error::PointAtInfinity);
        }
        if a == b {
            return Err(Error::CannotAddEqualPoints);
        }
        if a.x().unwrap() == b.x().unwrap() {
            return Err(Error::XCoordCantBeSame);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tom256::Affine as tomAff;
    use ark_ec::{CurveGroup, Group};
    use ark_secp256r1::Affine as secpAff;
    use ark_std::UniformRand;
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
    use rand_core::OsRng;
    use std::ops::Neg;

    #[test]
    fn point_addition() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<tomAff>::new::<Blake2b512>(b"test");

        for _ in 0..100 {
            let a = secpAff::rand(&mut rng);
            let b = secpAff::rand(&mut rng);
            let t = (a + b).into_affine();

            let comm_a =
                PointCommitmentWithOpening::<tomAff>::new::<_, secpAff>(&mut rng, &a, &comm_key)
                    .unwrap();
            let comm_b =
                PointCommitmentWithOpening::<tomAff>::new::<_, secpAff>(&mut rng, &b, &comm_key)
                    .unwrap();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"comm_a", &comm_a.comm);
            prover_transcript.append(b"comm_b", &comm_b.comm);
            prover_transcript.append(b"t", &t);
            let proof = PointAdditionProof::<secpAff, tomAff>::new(
                &mut rng,
                comm_a.clone(),
                comm_b.clone(),
                a,
                b,
                t,
                &comm_key,
                &mut prover_transcript,
            )
            .unwrap();

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"comm_a", &comm_a.comm);
            verifier_transcript.append(b"comm_b", &comm_b.comm);
            verifier_transcript.append(b"t", &t);
            proof
                .verify(
                    &comm_a.comm,
                    &comm_b.comm,
                    &t,
                    &comm_key,
                    &mut verifier_transcript,
                )
                .unwrap();

            // Verifying with incorrect sum fails
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            let random_point = secpAff::rand(&mut rng);
            assert!(proof
                .verify(
                    &comm_a.comm,
                    &comm_b.comm,
                    &random_point,
                    &comm_key,
                    &mut verifier_transcript,
                )
                .is_err());

            // Sum of a and -a should give error
            let minus_a = a.neg();
            let comm_minus_a = PointCommitmentWithOpening::<tomAff>::new::<_, secpAff>(
                &mut rng, &minus_a, &comm_key,
            )
            .unwrap();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            assert!(PointAdditionProof::<secpAff, tomAff>::new(
                &mut rng,
                comm_a.clone(),
                comm_minus_a.clone(),
                a,
                minus_a,
                secpAff::zero(),
                &comm_key,
                &mut prover_transcript,
            )
            .is_err());

            // Sum of a and a should give error
            let a_dbl = a.into_group().double().into_affine();
            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            assert!(PointAdditionProof::<secpAff, tomAff>::new(
                &mut rng,
                comm_a.clone(),
                comm_a.clone(),
                a,
                a,
                a_dbl,
                &comm_key,
                &mut prover_transcript,
            )
            .is_err());
        }
    }
}
