//! Elgamal encryption

use crate::serde_utils::ArkObjectBytes;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(
    Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct SecretKey<F: PrimeField>(pub F);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<G: AffineRepr>(pub G);

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

impl<G: AffineRepr> PublicKey<G> {
    pub fn new(secret_key: &SecretKey<G::ScalarField>, gen: &G) -> Self {
        Self(gen.mul_bigint(secret_key.0.into_bigint()).into_affine())
    }
}

pub fn keygen<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    gen: &G,
) -> (SecretKey<G::ScalarField>, PublicKey<G>) {
    let sk = SecretKey::new(rng);
    let pk = PublicKey::new(&sk, gen);
    (sk, pk)
}

/// Elgamal encryption of a group element `m`
#[serde_as]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Ciphertext<G: AffineRepr> {
    /// `m + r * pk`
    #[serde_as(as = "ArkObjectBytes")]
    pub encrypted: G,
    /// Ephemeral public key `r * gen`
    #[serde_as(as = "ArkObjectBytes")]
    pub eph_pk: G,
}

impl<G: AffineRepr> Ciphertext<G> {
    /// Returns the ciphertext and randomness created for encryption
    pub fn new<R: RngCore>(
        rng: &mut R,
        msg: &G,
        public_key: &G,
        gen: &G,
    ) -> (Self, G::ScalarField) {
        let alpha = G::ScalarField::rand(rng);
        (
            Self::new_given_randomness(msg, &alpha, public_key, gen),
            alpha,
        )
    }

    /// Returns the ciphertext
    pub fn new_given_randomness(
        msg: &G,
        randomness: &G::ScalarField,
        public_key: &G,
        gen: &G,
    ) -> Self {
        let b = randomness.into_bigint();
        let enc1 = (public_key.mul_bigint(b) + msg).into_affine();
        Self {
            encrypted: enc1,
            eph_pk: gen.mul_bigint(b).into_affine(),
        }
    }

    pub fn decrypt(&self, secret_key: &G::ScalarField) -> G {
        (self.eph_pk.mul(secret_key).neg() + self.encrypted).into_affine()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng) {
            let gen = G::Group::rand(rng).into_affine();
            let (sk, pk) = keygen(rng, &gen);

            let msg = G::Group::rand(rng).into_affine();
            let (ciphertext, _) = Ciphertext::new(rng, &msg, &pk.0, &gen);
            assert_eq!(ciphertext.decrypt(&sk.0), msg);
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }
}
