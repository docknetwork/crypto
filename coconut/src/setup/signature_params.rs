//! Parameters generated by a random oracle.
use alloc::vec::Vec;

use ark_ec::pairing::Pairing;
use ark_serialize::*;
use ark_std::cfg_into_iter;
use serde_with::serde_as;
use utils::{hashing_utils::affine_group_elem_from_try_and_incr, serde_utils::ArkObjectBytes};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use utils::{concat_slices, join};

/// Parameters generated by a random oracle.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SignatureParams<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g_tilde: E::G2Affine,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub h: Vec<E::G1Affine>,
}

impl<E: Pairing> SignatureParams<E> {
    /// Generates `g`, `g_tilde` and `h`. These params are shared between signer and all users.
    pub fn new<D: digest::Digest>(label: &[u8], message_count: usize) -> Self {
        let (g, g_tilde, h) = join!(
            affine_group_elem_from_try_and_incr::<_, D>(&concat_slices!(label, b" : g")),
            affine_group_elem_from_try_and_incr::<_, D>(&concat_slices!(label, b" : g_tilde")),
            cfg_into_iter!(0..message_count)
                .map(|i| concat_slices!(label, b" : h", i.to_be_bytes()))
                .map(|bytes| affine_group_elem_from_try_and_incr::<_, D>(&bytes))
                .collect()
        );

        Self { g, g_tilde, h }
    }

    /// Returns max amount of messages supported by this params.
    pub fn supported_message_count(&self) -> usize {
        self.h.len()
    }
}

pub type PreparedSignatureParams<E> = SignatureParams<E>;
