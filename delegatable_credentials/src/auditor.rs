//! Elgamal encryption as mentioned in Fig 1. of the Protego paper.

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::ops::Neg;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuditorSecretKey<E: PairingEngine>(pub E::Fr);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AuditorPublicKey<E: PairingEngine>(pub E::G1Affine);

impl<E: PairingEngine> Drop for AuditorSecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<E: PairingEngine> AuditorSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(E::Fr::rand(rng))
    }
}

impl<E: PairingEngine> AuditorPublicKey<E> {
    pub fn new(secret_key: &AuditorSecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(P1.mul(secret_key.0.into_repr()).into_affine())
    }
}

/// Elgamal encryption of a user's public key `upk` for an auditor's public key `apk`
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<E: PairingEngine> {
    /// `upk + alpha * apk`
    pub enc1: E::G1Affine,
    /// Ephemeral public key `alpha * P1`
    pub enc2: E::G1Affine,
}

impl<E: PairingEngine> Ciphertext<E> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        upk: &E::G1Affine,
        apk: &E::G1Affine,
        P1: &E::G1Affine,
    ) -> (Self, E::Fr) {
        let alpha = E::Fr::rand(rng);
        let enc1 = apk.mul(alpha).add_mixed(upk).into_affine();
        (
            Self {
                enc1,
                enc2: P1.mul(alpha).into_affine(),
            },
            alpha,
        )
    }

    pub fn decrypt(&self, secret_key: &AuditorSecretKey<E>) -> E::G1Affine {
        self.enc2
            .mul(secret_key.0)
            .neg()
            .add_mixed(&self.enc1)
            .into_affine()
    }
}
