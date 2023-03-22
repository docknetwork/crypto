use alloc::vec::Vec;

use crate::helpers::rand;
use ark_ec::pairing::Pairing;

use ark_std::rand::RngCore;

/// Witnesses for `SignaturesPoK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignaturePoKWitnesses<'a, E: Pairing> {
    pub r: E::ScalarField,
    pub r_bar: E::ScalarField,
    pub msgs: Vec<&'a E::ScalarField>,
}

impl<'a, E: Pairing> SignaturePoKWitnesses<'a, E> {
    /// Generates `r` and `r_bar` and captures `msgs`.
    pub fn new<R: RngCore>(rng: &mut R, msgs: Vec<&'a E::ScalarField>) -> Self {
        let r = rand(rng);
        let r_bar = rand(rng);

        Self { r, r_bar, msgs }
    }
}
