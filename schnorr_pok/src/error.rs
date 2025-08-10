// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkSerializationError;
#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SchnorrError {
    ExpectedSameSizeSequences(usize, usize),
    IndexOutOfBounds(usize, usize),
    InvalidResponse,
    #[cfg_attr(feature = "serde", serde(with = "ArkSerializationError"))]
    Serialization(SerializationError),
    ValueMustNotBeEqual,
    InvalidProofOfEquality,
    MissingBlindingAtIndex(usize),
    MissingResponseAtIndex(usize),
    FoundCommonIndexInOwnAndReceivedResponses(usize),
    NotAProduct,
    NotASquare,
    NotAnInverse,
}

impl From<SerializationError> for SchnorrError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
