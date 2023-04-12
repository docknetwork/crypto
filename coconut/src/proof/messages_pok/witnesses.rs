use alloc::vec::Vec;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::{aliases::CanonicalSerDe, serde_utils::*};

use crate::helpers::{n_rand, rand, OwnedPairs};
use utils::owned_pairs;

/// Witnesses for `MessagesPoK`.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub(super) struct MessagesPoKWitnesses<M: CanonicalSerDe, F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub o: F,
    #[serde_as(as = "OwnedPairs<ArkObjectBytes, ArkObjectBytes>")]
    pub o_m_pairs: OwnedPairs<F, M>,
}

impl<M: CanonicalSerDe, F: PrimeField> MessagesPoKWitnesses<M, F> {
    /// Captures `m` and generates random `o` along with a vector of `o` paired with the provided `m`.
    pub fn new<R: RngCore>(rng: &mut R, m: Vec<M>) -> Self {
        let o = rand(rng);
        let o_arr = n_rand(rng, m.len()).collect();
        let o_m_pairs = owned_pairs!(o_arr, m);

        Self { o, o_m_pairs }
    }
}
