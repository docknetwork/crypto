use crate::{
    concat_slices, hashing_utils::affine_group_elem_from_try_and_incr, serde_utils::ArkObjectBytes,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// A Pedersen commitment key `(g, h)`. The Pedersen commitment will be `g * m + h * r` with opening `(m, r)`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PedersenCommitmentKey<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub h: G,
}

impl<G: AffineRepr> PedersenCommitmentKey<G> {
    /// Create a new commitment key
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g = affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : G"]);
        let h = affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : H"]);
        Self { g, h }
    }

    /// Commit to a message
    pub fn commit(&self, message: &G::ScalarField, randomness: &G::ScalarField) -> G {
        (self.g * message + self.h * randomness).into()
    }

    pub fn commit_as_projective(
        &self,
        message: &G::ScalarField,
        randomness: &G::ScalarField,
    ) -> G::Group {
        self.g * message + self.h * randomness
    }
}
