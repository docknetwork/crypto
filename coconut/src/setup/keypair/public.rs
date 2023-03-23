use alloc::vec::Vec;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;

use dock_crypto_utils::serde_utils::ArkObjectBytes;

use ark_serialize::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{helpers::points, join, setup::SignatureParams};

use super::SecretKey;

/// `PublicKey` used in Pointcheval-Sanders signature scheme and PoKs.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) alpha_tilde: E::G2Affine,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub(crate) beta: Vec<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub(crate) beta_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> PublicKey<E> {
    /// Derives `PublicKey` from supplied seed and params.
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
}

pub type PreparedPublicKey<E> = PublicKey<E>;
