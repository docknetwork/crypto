use alloc::vec::Vec;

use crate::helpers::rand;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::{aliases::CanonicalSerDe, serde_utils::*};

use ark_std::rand::RngCore;

/// Witnesses for `SignaturesPoK`.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub(crate) struct SignaturePoKWitnesses<M: CanonicalSerDe, F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub r: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_bar: F,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub msgs: Vec<M>,
}

impl<M: CanonicalSerDe, F: PrimeField> SignaturePoKWitnesses<M, F> {
    /// Generates `r` and `r_bar` and captures `msgs`.
    pub fn new<R: RngCore>(rng: &mut R, msgs: Vec<M>) -> Self {
        let r = rand(rng);
        let r_bar = rand(rng);

        Self { r, r_bar, msgs }
    }
}
