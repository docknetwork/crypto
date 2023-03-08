//! Elgamal encryption as mentioned in Fig 1. of the Protego paper.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Mul, Neg};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::UniformRand;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuditorSecretKey<E: Pairing>(pub E::ScalarField);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuditorPublicKey<E: Pairing>(pub E::G1Affine);

impl<E: Pairing> Drop for AuditorSecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<E: Pairing> AuditorSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(E::ScalarField::rand(rng))
    }
}

impl<E: Pairing> AuditorPublicKey<E> {
    pub fn new(secret_key: &AuditorSecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(P1.mul_bigint(secret_key.0.into_bigint()).into_affine())
    }
}

/// Elgamal encryption of a user's public key `upk` for an auditor's public key `apk`
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<E: Pairing> {
    /// `upk + alpha * apk`
    pub enc1: E::G1Affine,
    /// Ephemeral public key `alpha * P1`
    pub enc2: E::G1Affine,
}

impl<E: Pairing> Ciphertext<E> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        upk: &E::G1Affine,
        apk: &E::G1Affine,
        P1: &E::G1Affine,
    ) -> (Self, E::ScalarField) {
        let alpha = E::ScalarField::rand(rng);
        let alpha_bi = alpha.into_bigint();
        let enc1 = (apk.mul_bigint(alpha_bi) + upk).into_affine();
        (
            Self {
                enc1,
                enc2: P1.mul_bigint(alpha_bi).into_affine(),
            },
            alpha,
        )
    }

    pub fn decrypt(&self, secret_key: &AuditorSecretKey<E>) -> E::G1Affine {
        (self.enc2.mul(secret_key.0).neg() + self.enc1).into_affine()
    }
}
