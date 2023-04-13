use alloc::vec::Vec;
use ark_ec::AffineRepr;
use ark_serialize::*;
use core::{cmp::Ordering, ops::Range};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use utils::{aliases::CanonicalSerDe, serde_utils::ArkObjectBytes};

use schnorr_pok::{
    error::SchnorrError, SchnorrChallengeContributor, SchnorrCommitment, SchnorrResponse,
};

use super::WithSchnorrAndBlindings;

/// Combines value with the `t` commitment from `SchnorrCommitment` **excluding blindings**.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "V: Serialize + DeserializeOwned")]
pub struct WithSchnorrResponse<G: AffineRepr, V: CanonicalSerDe> {
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: G,
    pub response: SchnorrResponse<G>,
    pub committed_message_indices: IndiceRange,
    pub value: V,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndiceRange(Range<usize>);
utils::impl_deref! { IndiceRange(Range<usize>) }

impl CanonicalSerialize for IndiceRange {
    fn serialized_size(&self, compress: Compress) -> usize {
        self.start.serialized_size(compress) + self.end.serialized_size(compress)
    }

    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.start.serialize_with_mode(&mut writer, compress)?;
        self.end.serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }
}

impl Valid for IndiceRange {
    fn check(&self) -> Result<(), SerializationError> {
        if self.start > self.end {
            Err(SerializationError::InvalidData)
        } else {
            Ok(())
        }
    }
}

impl CanonicalDeserialize for IndiceRange {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let start = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let end = usize::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(Self(start..end))
    }
}

impl<G, V> WithSchnorrResponse<G, V>
where
    G: AffineRepr,
    V: CanonicalSerDe + Clone,
{
    /// Combines value with the `SchnorrResponse` and omits blindings.
    pub fn new(
        response: SchnorrResponse<G>,
        &WithSchnorrAndBlindings {
            schnorr: SchnorrCommitment { t, .. },
            ref value,
        }: &WithSchnorrAndBlindings<G, V>,
        committed_message_indices: Range<usize>,
    ) -> Self {
        WithSchnorrResponse {
            response,
            commitment: t,
            value: value.clone(),
            committed_message_indices: IndiceRange(committed_message_indices),
        }
    }
}

impl<G, V> SchnorrChallengeContributor for WithSchnorrResponse<G, V>
where
    G: AffineRepr,
    V: CanonicalSerDe,
{
    /// The commitment's contribution to the overall challenge of the protocol.
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.value
            .serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;
        self.commitment
            .serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)
    }
}

impl<G, V> WithSchnorrResponse<G, V>
where
    G: AffineRepr,
    V: CanonicalSerDe,
{
    /// Get the response from post-challenge phase of the Schnorr protocol for the given
    /// message index `msg_idx`. Used when comparing message equality.
    /// It's the caller's responsibility to ensure that indices are unique.
    pub(crate) fn response_for_message(
        &self,
        msg_idx: usize,
        unique_revealed_msg_indices: impl IntoIterator<Item = usize>,
    ) -> Result<&G::ScalarField, SchnorrError> {
        let mut adjusted_msg_idx = msg_idx;

        let out_of_bounds = move || {
            SchnorrError::IndexOutOfBounds(
                msg_idx,
                self.committed_message_indices
                    .end
                    .saturating_sub(self.committed_message_indices.start),
            )
        };

        for idx in unique_revealed_msg_indices {
            match idx.cmp(&msg_idx) {
                Ordering::Equal => Err(SchnorrError::InvalidResponse)?,
                Ordering::Less => {
                    adjusted_msg_idx = adjusted_msg_idx.checked_sub(1).ok_or_else(out_of_bounds)?
                }
                _ => {}
            }
        }

        self.committed_message_indices
            .start
            .checked_add(adjusted_msg_idx)
            .ok_or_else(out_of_bounds)
            .and_then(|adjusted_msg_idx_with_applied_offset| {
                self.response
                    .get_response(adjusted_msg_idx_with_applied_offset)
            })
    }
}
