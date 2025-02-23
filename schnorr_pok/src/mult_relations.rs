//! Sigma protocols to prove:
//! - A committed value is the product of 2 other committed values
//! - A committed value is inverse of another committed value
//! - A committed value is square of another committed value
//!
//! The product protocol to prove `v_a * v_b = v_c` given Pedersen commitments to `v_a, v_b, v_c`, works as follows:
//! Public values:
//!  - Commitment key `(G, H)`
//!  - Commitments to `v_a, v_b, v_c` as `a = G * v_a + H * r_a`, `b = G * v_b + H * r_b` and `c = G * v_c + H * r_c`
//!
//! Private values:
//!  - `v_a, v_b, v_c, r_a, r_b, r_c`
//!
//! The prover proves knowledge of `v_a, v_b, v_c, r_a, r_b, r_c` while proving that `c = a * v_b + H * r` where `r = r_c - (r_a * v_b)`.
//! This uses the protocol from construction 2.3 of this [paper](https://eprint.iacr.org/2023/1595.pdf) and proven in Theorem 10 of
//! this [paper](https://eprint.iacr.org/2017/1132.pdf)
//!
//! For proving the inverse relation `v_a * v_a_inv = 1`, the above protocol can be used but a more efficient way is to prove
//! given commitments `a = G * v_a + H * r_a`, `a_inv = G * v_a_inv + H * r_a_inv` that `G = a * v_a_inv + H * r` where
//! `r = -(r_a * v_a_inv)`. This saves some commitments and responses.
//!
//! Similarly, for proving the square relation `v_a * v_a = {v_a}^2`, the above product protocol can be used but that will
//! have duplicate commitments and responses for `v_a` so a dedicated protocol is used where `a_sqr = G * {v_a}^2 + H * r_a_sqr`
//! is transformed to `a_sqr = a * v_a + H * {r_a_sqr - r_a*v_a}` and the Sigma protocol is run for this transformed
//! relation and `a = G * v_a + H * r_a`
//!
//! The prover follows the common pattern of `init`, `challenge_contribution` and `gen_proof` which correspond to the 3 steps of the
//! Sigma protocol with the verifier challenge generated with Fiat-Shamir. `challenge_contribution` assumes that the public commitments
//! and commitment key have already been included in the challenge.
//!

use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove that a committed value is the product of 2 other committed values, i.e `v_a * v_b = v_c`
/// `r_a, r_b, r_c` are the randomness in the commitments to `v_a, v_b, v_c` respectively.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ProductProtocol<G: AffineRepr> {
    pub v_a: G::ScalarField,
    pub v_b: G::ScalarField,
    pub v_c: G::ScalarField,
    pub r_a: G::ScalarField,
    pub r_b: G::ScalarField,
    pub r_c: G::ScalarField,
    pub j_a: G::ScalarField,
    pub j_b: G::ScalarField,
    pub k_a: G::ScalarField,
    pub k_b: G::ScalarField,
    pub k_c: G::ScalarField,
    pub t_a: G,
    pub t_b: G,
    pub t_c: G,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductProof<G: AffineRepr> {
    pub t_a: G,
    pub t_b: G,
    pub t_c: G,
    pub s_a: G::ScalarField,
    pub s_b: G::ScalarField,
    pub s_r_a: G::ScalarField,
    pub s_r_b: G::ScalarField,
    pub s_r_c: G::ScalarField,
}

/// Protocol to prove that a committed value is inverse of another committed value, i.e. `v_a * v_a_inv = 1`
/// `r_a, r_a_inv` are the randomness in the commitments to `v_a, v_a_inv` respectively.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct InverseProtocol<G: AffineRepr> {
    pub v_a: G::ScalarField,
    pub v_a_inv: G::ScalarField,
    pub r_a: G::ScalarField,
    pub r_a_inv: G::ScalarField,
    pub j_a: G::ScalarField,
    pub j_a_inv: G::ScalarField,
    pub k_a: G::ScalarField,
    pub k_a_inv: G::ScalarField,
    pub k_one: G::ScalarField,
    pub t_a: G,
    pub t_a_inv: G,
    pub t_one: G,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct InverseProof<G: AffineRepr> {
    pub t_a: G,
    pub t_a_inv: G,
    pub t_one: G,
    pub s_a: G::ScalarField,
    pub s_a_inv: G::ScalarField,
    pub s_r_a: G::ScalarField,
    pub s_r_a_inv: G::ScalarField,
    pub s_r_one: G::ScalarField,
}

/// Protocol to prove that a committed value is square of another committed value, i.e. `v_a * v_a = v_a_sqr`
/// `r_a, r_a_sqr` are the randomness in the commitments to `v_a, v_a_sqr` respectively.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SquareProtocol<G: AffineRepr> {
    pub v_a: G::ScalarField,
    pub v_a_sqr: G::ScalarField,
    pub r_a: G::ScalarField,
    pub r_a_sqr: G::ScalarField,
    pub j_a: G::ScalarField,
    pub k_a: G::ScalarField,
    pub k_a_sqr: G::ScalarField,
    pub t_a: G,
    pub t_a_sqr: G,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SquareProof<G: AffineRepr> {
    pub t_a: G,
    pub t_a_sqr: G,
    pub s_a: G::ScalarField,
    pub s_r_a: G::ScalarField,
    pub s_r_a_sqr: G::ScalarField,
}

impl<G: AffineRepr> ProductProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_b: G::ScalarField,
        v_c: G::ScalarField,
        r_a: G::ScalarField,
        r_b: G::ScalarField,
        r_c: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<Self, SchnorrError> {
        if (v_a * v_b) != v_c {
            return Err(SchnorrError::NotAProduct);
        }
        let j_a = G::ScalarField::rand(rng);
        let j_b = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_b = G::ScalarField::rand(rng);
        let k_c = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_b = comm_key.commit(&j_b, &k_b);
        let t_c = (a.mul(&j_b) + comm_key.h.mul(&k_c)).into_affine();
        Ok(Self {
            v_a,
            v_b,
            v_c,
            r_a,
            r_b,
            r_c,
            j_a,
            j_b,
            k_a,
            k_b,
            k_c,
            t_a,
            t_b,
            t_c,
        })
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_b.serialize_compressed(&mut writer)?;
        self.t_c.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> ProductProof<G> {
        let s_a = self.j_a + self.v_a * challenge;
        let s_b = self.j_b + self.v_b * challenge;
        let s_r_a = self.k_a + self.r_a * challenge;
        let s_r_b = self.k_b + self.r_b * challenge;
        let s_r_c = self.k_c + ((self.r_c - (self.r_a * self.v_b)) * challenge);
        ProductProof {
            t_a: self.t_a,
            t_b: self.t_b,
            t_c: self.t_c,
            s_a,
            s_b,
            s_r_a,
            s_r_b,
            s_r_c,
        }
    }
}

impl<G: AffineRepr> ProductProof<G> {
    pub fn verify(
        &self,
        a: G,
        b: G,
        c: G,
        challenge: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> bool {
        if comm_key.commit_as_projective(&self.s_a, &self.s_r_a)
            != (self.t_a.into_group() + a * challenge)
        {
            return false;
        }
        if comm_key.commit_as_projective(&self.s_b, &self.s_r_b)
            != (self.t_b.into_group() + b * challenge)
        {
            return false;
        }
        if (a * self.s_b + comm_key.h * self.s_r_c) != (self.t_c.into_group() + c * challenge) {
            return false;
        }
        true
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        a: G,
        b: G,
        c: G,
        challenge: &G::ScalarField,
        comm_key: PedersenCommitmentKey<G>,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        let minus_challenge = challenge.neg();
        rmc.add_3(
            comm_key.g,
            &self.s_a,
            comm_key.h,
            &self.s_r_a,
            a,
            &minus_challenge,
            self.t_a,
        );
        rmc.add_3(
            comm_key.g,
            &self.s_b,
            comm_key.h,
            &self.s_r_b,
            b,
            &minus_challenge,
            self.t_b,
        );
        rmc.add_3(
            a,
            &self.s_b,
            comm_key.h,
            &self.s_r_c,
            c,
            &minus_challenge,
            self.t_c,
        );
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_b.serialize_compressed(&mut writer)?;
        self.t_c.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> SquareProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_a_sqr: G::ScalarField,
        r_a: G::ScalarField,
        r_a_sqr: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<Self, SchnorrError> {
        if v_a.square() != v_a_sqr {
            return Err(SchnorrError::NotASquare);
        }
        let j_a = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_a_sqr = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_a_sqr = (a.mul(&j_a) + comm_key.h.mul(&k_a_sqr)).into_affine();
        Ok(Self {
            v_a,
            v_a_sqr,
            r_a,
            r_a_sqr,
            j_a,
            k_a,
            k_a_sqr,
            t_a,
            t_a_sqr,
        })
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_a_sqr.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> SquareProof<G> {
        let s_a = self.j_a + self.v_a * challenge;
        let s_r_a = self.k_a + self.r_a * challenge;
        let s_r_a_sqr = self.k_a_sqr + ((self.r_a_sqr - (self.r_a * self.v_a)) * challenge);
        SquareProof {
            t_a: self.t_a,
            t_a_sqr: self.t_a_sqr,
            s_a,
            s_r_a,
            s_r_a_sqr,
        }
    }
}

impl<G: AffineRepr> SquareProof<G> {
    pub fn verify(
        &self,
        a: G,
        a_sqr: G,
        challenge: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> bool {
        if comm_key.commit_as_projective(&self.s_a, &self.s_r_a)
            != (self.t_a.into_group() + a * challenge)
        {
            return false;
        }
        if (a * self.s_a + comm_key.h * self.s_r_a_sqr)
            != (self.t_a_sqr.into_group() + a_sqr * challenge)
        {
            return false;
        }
        true
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        a: G,
        a_sqr: G,
        challenge: &G::ScalarField,
        comm_key: PedersenCommitmentKey<G>,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        let minus_challenge = challenge.neg();
        rmc.add_3(
            comm_key.g,
            &self.s_a,
            comm_key.h,
            &self.s_r_a,
            a,
            &minus_challenge,
            self.t_a,
        );
        rmc.add_3(
            a,
            &self.s_a,
            comm_key.h,
            &self.s_r_a_sqr,
            a_sqr,
            &minus_challenge,
            self.t_a_sqr,
        );
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_a_sqr.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> InverseProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_a_inv: G::ScalarField,
        r_a: G::ScalarField,
        r_a_inv: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<Self, SchnorrError> {
        if (v_a * v_a_inv) != G::ScalarField::one() {
            return Err(SchnorrError::NotASquare);
        }
        let j_a = G::ScalarField::rand(rng);
        let j_a_inv = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_a_inv = G::ScalarField::rand(rng);
        let k_one = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_a_inv = comm_key.commit(&j_a_inv, &k_a_inv);
        let t_one = (a.mul(&j_a_inv) + comm_key.h.mul(&k_one)).into_affine();
        Ok(Self {
            v_a,
            v_a_inv,
            r_a,
            r_a_inv,
            j_a,
            j_a_inv,
            k_a,
            k_a_inv,
            k_one,
            t_a,
            t_a_inv,
            t_one,
        })
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_a_inv.serialize_compressed(&mut writer)?;
        self.t_one.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> InverseProof<G> {
        let s_a = self.j_a + self.v_a * challenge;
        let s_a_inv = self.j_a_inv + self.v_a_inv * challenge;
        let s_r_a = self.k_a + self.r_a * challenge;
        let s_r_a_inv = self.k_a_inv + self.r_a_inv * challenge;
        let s_r_one = self.k_one - ((self.r_a * self.v_a_inv) * challenge);
        InverseProof {
            t_a: self.t_a,
            t_a_inv: self.t_a_inv,
            t_one: self.t_one,
            s_a,
            s_a_inv,
            s_r_a,
            s_r_a_inv,
            s_r_one,
        }
    }
}

impl<G: AffineRepr> InverseProof<G> {
    pub fn verify(
        &self,
        a: G,
        a_inv: G,
        challenge: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> bool {
        if comm_key.commit_as_projective(&self.s_a, &self.s_r_a)
            != (self.t_a.into_group() + a * challenge)
        {
            return false;
        }
        if comm_key.commit_as_projective(&self.s_a_inv, &self.s_r_a_inv)
            != (self.t_a_inv.into_group() + a_inv * challenge)
        {
            return false;
        }
        if (a * self.s_a_inv + comm_key.h * self.s_r_one)
            != (self.t_one.into_group() + comm_key.g * challenge)
        {
            return false;
        }
        true
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        a: G,
        a_inv: G,
        challenge: &G::ScalarField,
        comm_key: PedersenCommitmentKey<G>,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        let minus_challenge = challenge.neg();
        rmc.add_3(
            comm_key.g,
            &self.s_a,
            comm_key.h,
            &self.s_r_a,
            a,
            &minus_challenge,
            self.t_a,
        );
        rmc.add_3(
            comm_key.g,
            &self.s_a_inv,
            comm_key.h,
            &self.s_r_a_inv,
            a_inv,
            &minus_challenge,
            self.t_a_inv,
        );
        rmc.add_3(
            a,
            &self.s_a_inv,
            comm_key.h,
            &self.s_r_one,
            comm_key.g,
            &minus_challenge,
            self.t_one,
        );
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.t_a.serialize_compressed(&mut writer)?;
        self.t_a_inv.serialize_compressed(&mut writer)?;
        self.t_one.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ff::{Field, One};
    use ark_std::UniformRand;
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
    use rand_core::OsRng;

    #[test]
    fn product_committed_values() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);

        for _ in 0..100 {
            let v_a = Fr::rand(&mut rng);
            let r_a = Fr::rand(&mut rng);
            let v_b = Fr::rand(&mut rng);
            let r_b = Fr::rand(&mut rng);
            let v_c = v_a * v_b;
            let r_c = Fr::rand(&mut rng);

            let a = comm_key.commit(&v_a, &r_a);
            let b = comm_key.commit(&v_b, &r_b);
            let c = comm_key.commit(&v_c, &r_c);

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"a", &a);
            prover_transcript.append(b"b", &b);
            prover_transcript.append(b"c", &c);
            let protocol =
                ProductProtocol::init(&mut rng, &a, v_a, v_b, v_c, r_a, r_b, r_c, &comm_key)
                    .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"b", &b);
            verifier_transcript.append(b"c", &c);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, b, c, &challenge, &comm_key));

            proof.verify_using_randomized_mult_checker(a, b, c, &challenge, comm_key, &mut checker);
        }

        assert!(checker.verify())
    }

    #[test]
    fn square_committed_values_using_product_proof() {
        let mut rng = OsRng::default();

        for _ in 0..100 {
            let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

            let v_a = Fr::rand(&mut rng);
            let r_a = Fr::rand(&mut rng);
            let v_a_sqr = v_a.square();
            let r_a_sqr = Fr::rand(&mut rng);

            let a = comm_key.commit(&v_a, &r_a);
            let a_sqr = comm_key.commit(&v_a_sqr, &r_a_sqr);

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"a", &a);
            prover_transcript.append(b"b", &a);
            prover_transcript.append(b"c", &a_sqr);
            let protocol = ProductProtocol::init(
                &mut rng, &a, v_a, v_a, v_a_sqr, r_a, r_a, r_a_sqr, &comm_key,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"b", &a);
            verifier_transcript.append(b"c", &a_sqr);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, a, a_sqr, &challenge, &comm_key));
        }
    }

    #[test]
    fn inverse_committed_values_using_product_proof() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

        for _ in 0..100 {
            let v_a = Fr::rand(&mut rng);
            let r_a = Fr::rand(&mut rng);
            let v_a_inv = v_a.inverse().unwrap();
            let r_a_inv = Fr::rand(&mut rng);
            assert_eq!(v_a * v_a_inv, Fr::one());
            let r_one = Fr::rand(&mut rng);

            let a = comm_key.commit(&v_a, &r_a);
            let a_inv = comm_key.commit(&v_a_inv, &r_a_inv);
            let one = comm_key.commit(&Fr::one(), &r_one);

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"a", &a);
            prover_transcript.append(b"b", &a_inv);
            prover_transcript.append(b"c", &one);
            let protocol = ProductProtocol::init(
                &mut rng,
                &a,
                v_a,
                v_a_inv,
                Fr::one(),
                r_a,
                r_a_inv,
                r_one,
                &comm_key,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"b", &a_inv);
            verifier_transcript.append(b"c", &one);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, a_inv, one, &challenge, &comm_key));
        }
    }

    #[test]
    fn square_committed_values() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);

        for _ in 0..100 {
            let v_a = Fr::rand(&mut rng);
            let r_a = Fr::rand(&mut rng);
            let v_a_sqr = v_a.square();
            let r_a_sqr = Fr::rand(&mut rng);

            let a = comm_key.commit(&v_a, &r_a);
            let a_sqr = comm_key.commit(&v_a_sqr, &r_a_sqr);

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"a", &a);
            prover_transcript.append(b"a^2", &a_sqr);
            let protocol =
                SquareProtocol::init(&mut rng, &a, v_a, v_a_sqr, r_a, r_a_sqr, &comm_key).unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"a^2", &a_sqr);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, a_sqr, &challenge, &comm_key));

            proof.verify_using_randomized_mult_checker(
                a,
                a_sqr,
                &challenge,
                comm_key,
                &mut checker,
            );
        }

        assert!(checker.verify())
    }

    #[test]
    fn inverse_committed_values() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);

        for _ in 0..100 {
            let v_a = Fr::rand(&mut rng);
            let r_a = Fr::rand(&mut rng);
            let v_a_inv = v_a.inverse().unwrap();
            let r_a_inv = Fr::rand(&mut rng);
            assert_eq!(v_a * v_a_inv, Fr::one());

            let a = comm_key.commit(&v_a, &r_a);
            let a_inv = comm_key.commit(&v_a_inv, &r_a_inv);

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"a", &a);
            prover_transcript.append(b"a_inv", &a_inv);
            let protocol =
                InverseProtocol::init(&mut rng, &a, v_a, v_a_inv, r_a, r_a_inv, &comm_key).unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"a_inv", &a_inv);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, a_inv, &challenge, &comm_key));

            proof.verify_using_randomized_mult_checker(
                a,
                a_inv,
                &challenge,
                comm_key,
                &mut checker,
            );
        }

        assert!(checker.verify())
    }
}
