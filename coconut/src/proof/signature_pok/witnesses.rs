use alloc::vec::Vec;

use crate::helpers::rand;

use ark_ff::PrimeField;
use ark_serialize::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
#[cfg(feature = "serde")]
use utils::serde_utils::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use ark_std::rand::RngCore;

/// Witnesses for `SignaturesPoK`.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, ZeroizeOnDrop, Zeroize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub(crate) struct SignaturePoKWitnesses<F: PrimeField> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub r: F,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub r_bar: F,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
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
