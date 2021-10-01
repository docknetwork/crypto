// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
#[cfg(feature = "serde-support")]
use dock_crypto_utils::serde_utils::ArkSerializationError;
#[cfg(feature = "serde-support")]
use serde::Serialize;
#[cfg(feature = "serde-support")]
use serde_with::{serde, As};

#[derive(Debug)]
// #[cfg_attr(feature = "serde_support", serde_as)]
#[cfg_attr(feature = "serde_support", derive(Serialize))]
pub enum SchnorrError {
    ExpectedSameSizeSequences(usize, usize),
    IndexOutOfBounds(usize, usize),
    InvalidResponse,
    // #[serde(with = "ArkSerializationError")]
    #[cfg_attr(feature = "serde-support", serde(with = "As::ArkSerializationError"))]
    Serialization(SerializationError),
}

impl From<SerializationError> for SchnorrError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
