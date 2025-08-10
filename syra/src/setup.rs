use crate::{
    error::SyraError,
    vrf::{Output, Proof},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::affine_group_element_from_byte_slices;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// System parameters
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SetupParams<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g: E::G1Affine,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g_hat: E::G2Affine,
}

/// System parameters with precomputation
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedSetupParams<E: Pairing> {
    pub g: E::G1Affine,
    pub g_hat: E::G2Affine,
    pub g_hat_prepared: E::G2Prepared,
    /// e(g, g_hat)
    pub pairing: PairingOutput<E>,
}

impl<E: Pairing> AsRef<E::G1Affine> for SetupParams<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.g
    }
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IssuerSecretKey<F: PrimeField>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub F,
);

/// Issuer's public key
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IssuerPublicKey<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub vk: E::G2Affine,
    // NOTE: w and w_hat don't need to be part of the issuer's public key. These could be agreed upon between each
    // pair of user and verifier and chosen such that they are random (hash string to group).
    // Or they could be made part of setup params by generating them transparently (hashing public strings to group elements).
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub w: E::G1Affine,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub w_hat: E::G2Affine,
}

/// Issuer's public key with precomputation
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedIssuerPublicKey<E: Pairing> {
    pub vk: E::G2Affine,
    // NOTE: w and w_hat don't need to be part of the issuer's public key. These could be agreed upon between each
    // pair of user and verifier and chosen such that they are random (hash string to group).
    // Or they could be made part of setup params by generating them transparently (hashing public strings to group elements).
    pub w: E::G1Affine,
    pub w_hat: E::G2Affine,
    pub vk_prepared: E::G2Prepared,
    pub w_hat_prepared: E::G2Prepared,
    /// e(w, vk)
    pub w_vk: PairingOutput<E>,
    /// e(w, g_hat)
    pub w_g_hat: PairingOutput<E>,
    /// -e(g, w_hat)
    pub minus_g_w_hat: PairingOutput<E>,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserSecretKey<E: Pairing>(
    pub Output<E>,
    /// (usk, usk_hat)
    pub Proof<E>,
);

/// User's secret key with precomputation
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedUserSecretKey<E: Pairing>(
    /// (usk, usk_hat)
    pub Proof<E>,
    /// usk_hat prepared
    pub E::G2Prepared,
);

impl<E: Pairing> SetupParams<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g = affine_group_element_from_byte_slices!(label, b" : g");
        let g_hat = affine_group_element_from_byte_slices!(label, b" : g_hat");
        Self { g, g_hat }
    }
}

impl<E: Pairing> From<SetupParams<E>> for PreparedSetupParams<E> {
    fn from(params: SetupParams<E>) -> Self {
        let g_hat_prepared = E::G2Prepared::from(params.g_hat);
        let pairing = E::pairing(params.g, params.g_hat);
        Self {
            g: params.g,
            g_hat: params.g_hat,
            g_hat_prepared,
            pairing,
        }
    }
}

impl<F: PrimeField> IssuerSecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

impl<F: PrimeField> AsRef<F> for IssuerSecretKey<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<E: Pairing> IssuerPublicKey<E> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        sk: &IssuerSecretKey<E::ScalarField>,
        params: &SetupParams<E>,
    ) -> Self {
        let vk = (params.g_hat * sk.0).into_affine();
        let w = E::G1Affine::rand(rng);
        let w_hat = E::G2Affine::rand(rng);
        Self { vk, w, w_hat }
    }
}

impl<E: Pairing> AsRef<E::G2Affine> for IssuerPublicKey<E> {
    fn as_ref(&self) -> &E::G2Affine {
        &self.vk
    }
}

impl<E: Pairing> PreparedIssuerPublicKey<E> {
    pub fn new(pk: IssuerPublicKey<E>, params: SetupParams<E>) -> Self {
        let vk_prepared = E::G2Prepared::from(pk.vk);
        let w_hat_prepared = E::G2Prepared::from(pk.w_hat);
        let w_prepared = E::G1Prepared::from(pk.w);
        let w_vk = E::pairing(w_prepared.clone(), vk_prepared.clone());
        let w_g_hat = E::pairing(w_prepared, E::G2Prepared::from(params.g_hat));
        let minus_g_w_hat = E::pairing(
            E::G1Prepared::from(params.g.into_group().neg()),
            w_hat_prepared.clone(),
        );
        Self {
            vk: pk.vk,
            w: pk.w,
            w_hat: pk.w_hat,
            vk_prepared,
            w_hat_prepared,
            w_vk,
            w_g_hat,
            minus_g_w_hat,
        }
    }
}

impl<E: Pairing> UserSecretKey<E> {
    pub fn new(
        user_id: E::ScalarField,
        issuer_sk: &IssuerSecretKey<E::ScalarField>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Self {
        let (out, proof) = Output::generate(user_id, issuer_sk.as_ref(), params);
        Self(out, proof)
    }

    pub fn verify(
        &self,
        user_id: E::ScalarField,
        issuer_pk: &IssuerPublicKey<E>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), SyraError> {
        self.1.verify(user_id, &self.0, issuer_pk.as_ref(), params)
    }
}

impl<E: Pairing> From<&UserSecretKey<E>> for PreparedUserSecretKey<E> {
    fn from(sk: &UserSecretKey<E>) -> Self {
        let usk_hat_prepared = E::G2Prepared::from(sk.1 .1);
        Self(sk.1.clone(), usk_hat_prepared)
    }
}
