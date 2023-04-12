use alloc::vec::Vec;

use crate::helpers::rand;

use ark_ff::PrimeField;
use ark_serialize::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use ark_std::rand::RngCore;

/// Witnesses for `SignaturesPoK`.
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
pub(crate) struct SignaturePoKWitnesses<F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub r: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_bar: F,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub msgs: Vec<F>,
}

impl<F: PrimeField> SignaturePoKWitnesses<F> {
    /// Generates `r` and `r_bar` and captures `msgs`.
    pub fn new<R: RngCore>(rng: &mut R, msgs: Vec<F>) -> Self {
        let r = rand(rng);
        let r_bar = rand(rng);

        Self { r, r_bar, msgs }
    }
}
