use alloc::vec::Vec;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;

use ark_serialize::*;
use core::iter::once;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
#[cfg(feature = "serde")]
use utils::serde_utils::ArkObjectBytes;

use crate::{helpers::points, setup::SignatureParams};
use utils::join;

use super::SecretKey;

/// `PublicKey` used in the modified Pointcheval-Sanders signature scheme and PoKs.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub alpha_tilde: E::G2Affine,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    pub beta: Vec<E::G1Affine>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    pub beta_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> PublicKey<E> {
    /// Derives `PublicKey` from supplied secret key and params.
    pub fn new(
        SecretKey { x, y }: &SecretKey<E::ScalarField>,
        SignatureParams { g, g_tilde, .. }: &SignatureParams<E>,
    ) -> Self {
        let (alpha_tilde, beta, beta_tilde) = join!(
            g_tilde.mul_bigint(x.into_bigint()).into(),
            points(g, y),
            points(g_tilde, y)
        );

        PublicKey {
            alpha_tilde,
            beta,
            beta_tilde,
        }
    }

    /// Returns max amount of messages supported by this public key.
    pub fn supported_message_count(&self) -> usize {
        self.beta.len()
    }

    /// Returns `true` if the public key is valid, i.e don't have zero elements
    /// and have `beta` length equal to `beta_tilde` length.
    pub fn valid(&self) -> bool {
        self.beta.len() == self.beta_tilde.len()
            && !once(&self.alpha_tilde)
                .chain(&self.beta_tilde)
                .any(AffineRepr::is_zero)
            && !self.beta.iter().any(AffineRepr::is_zero)
    }
}

pub type PreparedPublicKey<E> = PublicKey<E>;
