use ark_serialize::SerializationError;
use dock_crypto_utils::{
    serde_utils::ArkSerializationError,
    try_iter::{IndexIsOutOfBounds, InvalidPair},
};
use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum KVACError {
    NoMessageGiven,
    MessageCountIncompatibleWithMACParams(usize, usize),
    MessageIndicesMustBeUniqueAndSorted(InvalidPair<usize>),
    MessageIndexIsOutOfBounds(IndexIsOutOfBounds),
    CannotInvert0,
    InvalidMAC,
    InvalidMACProof,
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
    InvalidRandomizedMAC,
    InvalidKeyedProof,
    InvalidSchnorrProof,
    InvalidMsgIdxForResponse(usize),
}

impl From<InvalidPair<usize>> for KVACError {
    fn from(err: InvalidPair<usize>) -> Self {
        Self::MessageIndicesMustBeUniqueAndSorted(err)
    }
}

impl From<IndexIsOutOfBounds> for KVACError {
    fn from(err: IndexIsOutOfBounds) -> Self {
        Self::MessageIndexIsOutOfBounds(err)
    }
}

impl From<SchnorrError> for KVACError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<SerializationError> for KVACError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
