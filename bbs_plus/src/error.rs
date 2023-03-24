// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use dock_crypto_utils::{
    serde_utils::ArkSerializationError,
    try_iter::{IndexIsOutOfBounds, InvalidPair},
};
use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum BBSPlusError {
    CannotInvert0,
    NoMessageToSign,
    MessageCountIncompatibleWithSigParams(usize, usize),
    /// Signature's `A` is 0
    ZeroSignature,
    InvalidSignature,
    /// Pairing check failed during verification of proof of knowledge of signature
    PairingCheckFailed,
    /// 1st schnorr proof failed during verification of proof of knowledge of signature
    FirstSchnorrVerificationFailed,
    /// 2nd schnorr proof failed during verification of proof of knowledge of signature
    SecondSchnorrVerificationFailed,
    InvalidMsgIdxForResponse(usize),
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
    MessageIndicesMustBeUniqueAndSorted(InvalidPair<usize>),
    MessageIndexIsOutOfBounds(IndexIsOutOfBounds),
}

impl From<SchnorrError> for BBSPlusError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl<T> From<InvalidPair<(usize, T)>> for BBSPlusError {
    fn from(err: InvalidPair<(usize, T)>) -> Self {
        Self::MessageIndicesMustBeUniqueAndSorted(err.map(|(idx, _)| idx))
    }
}

impl From<IndexIsOutOfBounds> for BBSPlusError {
    fn from(err: IndexIsOutOfBounds) -> Self {
        Self::MessageIndexIsOutOfBounds(err)
    }
}

impl From<SerializationError> for BBSPlusError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
