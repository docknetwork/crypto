use alloc::vec::Vec;

use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::helpers::{n_rand, rand, OwnedPairs};
use utils::owned_pairs;

/// Witnesses for `MessagesPoK`.
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    ZeroizeOnDrop,
    Zeroize,
)]
pub(super) struct MessagesPoKWitnesses<F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub o: F,
    #[serde_as(as = "OwnedPairs<ArkObjectBytes, ArkObjectBytes>")]
    pub o_m_pairs: OwnedPairs<F, F>,
}

impl<F: PrimeField> MessagesPoKWitnesses<F> {
    /// Captures `m` and generates random `o` along with a vector of `o` paired with the provided `m`.
    pub fn new<R: RngCore>(rng: &mut R, m: Vec<F>) -> Self {
        let o = rand(rng);
        let o_arr = n_rand(rng, m.len()).collect();
        let o_m_pairs = owned_pairs!(o_arr, m);

        Self { o, o_m_pairs }
    }
}
