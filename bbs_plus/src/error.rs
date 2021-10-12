// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use dock_crypto_utils::serde_utils::ArkSerializationError;
use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum BBSPlusError {
    NoMessageToSign,
    MessageCountIncompatibleWithSigParams(usize, usize),
    InvalidMessageIdx(usize),
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
}

impl From<SchnorrError> for BBSPlusError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<SerializationError> for BBSPlusError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
