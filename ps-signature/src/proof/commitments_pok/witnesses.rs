use alloc::vec::Vec;

use ark_ec::pairing::Pairing;
use ark_std::rand::RngCore;

use crate::{
    helpers::{n_rand, rand, OwnedPairs},
    owned_pairs,
};

/// Witnesses for `CommitmentsPoK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommitmentsPoKWitnesses<'a, E: Pairing> {
    pub o: E::ScalarField,
    pub o_m_pairs: OwnedPairs<E::ScalarField, &'a E::ScalarField>,
}

impl<'a, E: Pairing> CommitmentsPoKWitnesses<'a, E> {
    /// Captures `m` and generates random `o` along with a vector of `o` paired with the provided `m`.
    pub fn new<R: RngCore>(rng: &mut R, m: Vec<&'a E::ScalarField>) -> Self {
        let o = rand(rng);
        let o_arr = n_rand(rng, m.len()).collect();
        let o_m_pairs = owned_pairs!(o_arr, m);

        Self { o, o_m_pairs }
    }
}
