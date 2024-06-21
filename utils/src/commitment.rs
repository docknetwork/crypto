use crate::{
    concat_slices, hashing_utils::affine_group_elem_from_try_and_incr, msm::WindowTable,
    serde_utils::ArkObjectBytes,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, vec::Vec};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
        self.commit_as_projective(message, randomness).into()
    }

    /// Commit to a batch of messages and output commitments corresponding to each message.
    pub fn commit_to_a_batch(
        &self,
        messages: &[G::ScalarField],
        randomness: &[G::ScalarField],
    ) -> Vec<G> {
        assert_eq!(messages.len(), randomness.len());
        let g_table = WindowTable::new(messages.len(), self.g.into_group());
        let h_table = WindowTable::new(randomness.len(), self.h.into_group());
        G::Group::normalize_batch(
            &cfg_into_iter!(messages)
                .zip(cfg_into_iter!(randomness))
                .map(|(m_i, r_i)| g_table.multiply(m_i) + h_table.multiply(r_i))
                .collect::<Vec<_>>(),
        )
    }

    pub fn commit_as_projective(
        &self,
        message: &G::ScalarField,
        randomness: &G::ScalarField,
    ) -> G::Group {
        self.g * message + self.h * randomness
    }
}
