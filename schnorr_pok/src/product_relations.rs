//! Protocols to prove:
//! - A committed value is the product of 2 other committed values
//! - A committed value is inverse of another committed value
//! - A committed value is square of another committed value
//!
//! The product protocol to prove `v_a * v_b = v_c` given Pedersen commitments to `v_a, v_b, v_c`, works as follows:
//! Public values:
//!  - Commitment key `(g, h)`
//!  - Commitments to `v_a, v_b, v_c` as `a = g * v_a + h * r_a`, `b = g * v_b + h * r_b` and `c = g * v_c + h * r_c`
//!
//! Private values:
//!  - `v_a, v_b, v_c, r_a, r_b, r_c`
//!
//! The prover proves knowledge of `v_a, v_b, v_c, r_a, r_b, r_c` using the usual sigma protocol (Schnorr) while
//! proving that `c = a * v_b + h * r` where `r = r_c - (r_a * v_b)`
//!
//! For proving the inverse relation `v_a * v_a_inv = 1`, the above protocol can be used but a more efficient way is to prove
//! given commitments `a = g * v_a + h * r_a`, `a_inv = g * v_a_inv + h * r_a_inv` that `g = a * v_a_inv + h * r` where
//! `r = -(r_a * v_a_inv)`. This saves some commitments and responses.
//!
//! Similarly, for proving the square relation `v_a * v_a = v_a_sqr`, the above product protocol can be used but that will
//! have duplicate commitments and responses for `v_a` so a dedicated protocol is used.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::commitment::PedersenCommitmentKey;

/// Protocol to prove that a committed value is the product of 2 other committed values - `v_a * v_b = v_c`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProductProtocol<G: AffineRepr> {
    pub v_a: G::ScalarField,
    pub v_b: G::ScalarField,
    pub v_c: G::ScalarField,
    pub r_a: G::ScalarField,
    pub r_b: G::ScalarField,
    pub r_c: G::ScalarField,
    pub j_a: G::ScalarField,
    pub j_b: G::ScalarField,
    pub j_c: G::ScalarField,
    pub k_a: G::ScalarField,
    pub k_b: G::ScalarField,
    pub k_c: G::ScalarField,
    pub k_c_2: G::ScalarField,
    pub t_a: G,
    pub t_b: G,
    pub t_c: G,
    pub t_c_2: G,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductProof<G: AffineRepr> {
    pub t_a: G,
    pub t_b: G,
    pub t_c: G,
    pub t_c_2: G,
    pub s_a: G::ScalarField,
    pub s_b: G::ScalarField,
    pub s_c: G::ScalarField,
    pub s_r_a: G::ScalarField,
    pub s_r_b: G::ScalarField,
    pub s_r_c: G::ScalarField,
    pub s_r_c_2: G::ScalarField,
}

/// Protocol to prove that a committed value is inverse of another committed value - `v_a * v_a_inv = 1`
#[derive(Clone, PartialEq, Eq, Debug)]
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

/// Protocol to prove that a committed value is square of another committed value - `v_a * v_a = v_a_sqr`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SquareProtocol<G: AffineRepr> {
    pub v_a: G::ScalarField,
    pub v_a_sqr: G::ScalarField,
    pub r_a: G::ScalarField,
    pub r_a_sqr: G::ScalarField,
    pub j_a: G::ScalarField,
    pub j_a_sqr: G::ScalarField,
    pub k_a: G::ScalarField,
    pub k_a_sqr: G::ScalarField,
    pub k_a_2: G::ScalarField,
    pub t_a: G,
    pub t_a_sqr: G,
    pub t_a_2: G,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SquareProof<G: AffineRepr> {
    pub t_a: G,
    pub t_a_sqr: G,
    pub t_a_2: G,
    pub s_a: G::ScalarField,
    pub s_a_sqr: G::ScalarField,
    pub s_r_a: G::ScalarField,
    pub s_r_a_sqr: G::ScalarField,
    pub s_r_a_2: G::ScalarField,
}

impl<G: AffineRepr> ProductProtocol<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_b: G::ScalarField,
        v_c: G::ScalarField,
        r_a: G::ScalarField,
        r_b: G::ScalarField,
        r_c: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        assert_eq!(v_a * v_b, v_c);
        let j_a = G::ScalarField::rand(rng);
        let j_b = G::ScalarField::rand(rng);
        let j_c = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_b = G::ScalarField::rand(rng);
        let k_c = G::ScalarField::rand(rng);
        let k_c_2 = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_b = comm_key.commit(&j_b, &k_b);
        let t_c = comm_key.commit(&j_c, &k_c);
        let t_c_2 = (a.mul(&j_b) + comm_key.h.mul(&k_c_2)).into_affine();
        Self {
            v_a,
            v_b,
            v_c,
            r_a,
            r_b,
            r_c,
            j_a,
            j_b,
            j_c,
            k_a,
            k_b,
            k_c,
            k_c_2,
            t_a,
            t_b,
            t_c,
            t_c_2,
        }
    }

    /// Assumes that a, b, c and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_b.serialize_compressed(&mut writer).unwrap();
        self.t_c.serialize_compressed(&mut writer).unwrap();
        self.t_c_2.serialize_compressed(&mut writer).unwrap();
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> ProductProof<G> {
        let s_a = self.j_a + self.v_a * challenge;
        let s_b = self.j_b + self.v_b * challenge;
        let s_c = self.j_c + self.v_c * challenge;
        let s_r_a = self.k_a + self.r_a * challenge;
        let s_r_b = self.k_b + self.r_b * challenge;
        let s_r_c = self.k_c + self.r_c * challenge;
        let s_r_c_2 = self.k_c_2 + ((self.r_c - (self.r_a * self.v_b)) * challenge);
        ProductProof {
            t_a: self.t_a,
            t_b: self.t_b,
            t_c: self.t_c,
            t_c_2: self.t_c_2,
            s_a,
            s_b,
            s_c,
            s_r_a,
            s_r_b,
            s_r_c,
            s_r_c_2,
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
        if comm_key.commit_as_projective(&self.s_c, &self.s_r_c)
            != (self.t_c.into_group() + c * challenge)
        {
            return false;
        }
        if (a * self.s_b + comm_key.h * self.s_r_c_2) != (self.t_c_2.into_group() + c * challenge) {
            return false;
        }
        true
    }

    /// Assumes that a, b, c and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_b.serialize_compressed(&mut writer).unwrap();
        self.t_c.serialize_compressed(&mut writer).unwrap();
        self.t_c_2.serialize_compressed(&mut writer).unwrap();
    }
}

impl<G: AffineRepr> SquareProtocol<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_a_sqr: G::ScalarField,
        r_a: G::ScalarField,
        r_a_sqr: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        assert_eq!(v_a.square(), v_a_sqr);
        let j_a = G::ScalarField::rand(rng);
        let j_a_sqr = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_a_sqr = G::ScalarField::rand(rng);
        let k_a_2 = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_a_sqr = comm_key.commit(&j_a_sqr, &k_a_sqr);
        let t_a_2 = (a.mul(&j_a) + comm_key.h.mul(&k_a_2)).into_affine();
        Self {
            v_a,
            v_a_sqr,
            r_a,
            r_a_sqr,
            j_a,
            j_a_sqr,
            k_a,
            k_a_sqr,
            k_a_2,
            t_a,
            t_a_sqr,
            t_a_2,
        }
    }

    /// Assumes that a, a^2 and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_a_sqr.serialize_compressed(&mut writer).unwrap();
        self.t_a_2.serialize_compressed(&mut writer).unwrap();
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> SquareProof<G> {
        let s_a = self.j_a + self.v_a * challenge;
        let s_a_sqr = self.j_a_sqr + self.v_a_sqr * challenge;
        let s_r_a = self.k_a + self.r_a * challenge;
        let s_r_a_sqr = self.k_a_sqr + self.r_a_sqr * challenge;
        let s_r_a_2 = self.k_a_2 + ((self.r_a_sqr - (self.r_a * self.v_a)) * challenge);
        SquareProof {
            t_a: self.t_a,
            t_a_sqr: self.t_a_sqr,
            t_a_2: self.t_a_2,
            s_a,
            s_a_sqr,
            s_r_a,
            s_r_a_sqr,
            s_r_a_2,
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
        if comm_key.commit_as_projective(&self.s_a_sqr, &self.s_r_a_sqr)
            != (self.t_a_sqr.into_group() + a_sqr * challenge)
        {
            return false;
        }
        if (a * self.s_a + comm_key.h * self.s_r_a_2)
            != (self.t_a_2.into_group() + a_sqr * challenge)
        {
            return false;
        }
        true
    }

    /// Assumes that a, a^2 and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_a_sqr.serialize_compressed(&mut writer).unwrap();
        self.t_a_2.serialize_compressed(&mut writer).unwrap();
    }
}

impl<G: AffineRepr> InverseProtocol<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        a: &G,
        v_a: G::ScalarField,
        v_a_inv: G::ScalarField,
        r_a: G::ScalarField,
        r_a_inv: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        assert_eq!(v_a * v_a_inv, G::ScalarField::one());
        let j_a = G::ScalarField::rand(rng);
        let j_a_inv = G::ScalarField::rand(rng);
        let k_a = G::ScalarField::rand(rng);
        let k_a_inv = G::ScalarField::rand(rng);
        let k_one = G::ScalarField::rand(rng);
        let t_a = comm_key.commit(&j_a, &k_a);
        let t_a_inv = comm_key.commit(&j_a_inv, &k_a_inv);
        let t_one = (a.mul(&j_a_inv) + comm_key.h.mul(&k_one)).into_affine();
        Self {
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
        }
    }

    /// Assumes that a, a^-1 and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_a_inv.serialize_compressed(&mut writer).unwrap();
        self.t_one.serialize_compressed(&mut writer).unwrap();
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

    /// Assumes that a, a^-1, c and commitment key are being included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) {
        self.t_a.serialize_compressed(&mut writer).unwrap();
        self.t_a_inv.serialize_compressed(&mut writer).unwrap();
        self.t_one.serialize_compressed(&mut writer).unwrap();
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
                ProductProtocol::new(&mut rng, &a, v_a, v_b, v_c, r_a, r_b, r_c, &comm_key);
            protocol.challenge_contribution(&mut prover_transcript);
            let challenge = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge);

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"a", &a);
            verifier_transcript.append(b"b", &b);
            verifier_transcript.append(b"c", &c);
            proof.challenge_contribution(&mut verifier_transcript);
            let challenge = verifier_transcript.challenge_scalar(b"challenge");
            assert!(proof.verify(a, b, c, &challenge, &comm_key));
        }
    }

    #[test]
    fn square_committed_values_using_product_proof() {
        let mut rng = OsRng::default();

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
        let protocol = ProductProtocol::new(
            &mut rng, &a, v_a, v_a, v_a_sqr, r_a, r_a, r_a_sqr, &comm_key,
        );
        protocol.challenge_contribution(&mut prover_transcript);
        let challenge = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge);

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key", &comm_key);
        verifier_transcript.append(b"a", &a);
        verifier_transcript.append(b"b", &a);
        verifier_transcript.append(b"c", &a_sqr);
        proof.challenge_contribution(&mut verifier_transcript);
        let challenge = verifier_transcript.challenge_scalar(b"challenge");
        assert!(proof.verify(a, a, a_sqr, &challenge, &comm_key));
    }

    #[test]
    fn inverse_committed_values_using_product_proof() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

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
        let protocol = ProductProtocol::new(
            &mut rng,
            &a,
            v_a,
            v_a_inv,
            Fr::one(),
            r_a,
            r_a_inv,
            r_one,
            &comm_key,
        );
        protocol.challenge_contribution(&mut prover_transcript);
        let challenge = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge);

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key", &comm_key);
        verifier_transcript.append(b"a", &a);
        verifier_transcript.append(b"b", &a_inv);
        verifier_transcript.append(b"c", &one);
        proof.challenge_contribution(&mut verifier_transcript);
        let challenge = verifier_transcript.challenge_scalar(b"challenge");
        assert!(proof.verify(a, a_inv, one, &challenge, &comm_key));
    }

    #[test]
    fn square_committed_values() {
        let mut rng = OsRng::default();

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
        prover_transcript.append(b"a^2", &a_sqr);
        let protocol = SquareProtocol::new(&mut rng, &a, v_a, v_a_sqr, r_a, r_a_sqr, &comm_key);
        protocol.challenge_contribution(&mut prover_transcript);
        let challenge = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge);

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key", &comm_key);
        verifier_transcript.append(b"a", &a);
        verifier_transcript.append(b"a^2", &a_sqr);
        proof.challenge_contribution(&mut verifier_transcript);
        let challenge = verifier_transcript.challenge_scalar(b"challenge");
        assert!(proof.verify(a, a_sqr, &challenge, &comm_key));
    }

    #[test]
    fn inverse_committed_values() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");

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
        let protocol = InverseProtocol::new(&mut rng, &a, v_a, v_a_inv, r_a, r_a_inv, &comm_key);
        protocol.challenge_contribution(&mut prover_transcript);
        let challenge = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge);

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key", &comm_key);
        verifier_transcript.append(b"a", &a);
        verifier_transcript.append(b"a_inv", &a_inv);
        proof.challenge_contribution(&mut verifier_transcript);
        let challenge = verifier_transcript.challenge_scalar(b"challenge");
        assert!(proof.verify(a, a_inv, &challenge, &comm_key));
    }
}
