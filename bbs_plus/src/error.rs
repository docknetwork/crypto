// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use schnorr_pok::error::SchnorrError;

#[derive(Debug)]
pub enum BBSPlusError {
    NoMessageToSign,
    MessageCountIncompatibleWithSigParams,
    InvalidMessageIdx,
    /// Signature's `A` is 0
    ZeroSignature,
    InvalidSignature,
    InvalidBlindingIdx,
    /// Pairing check failed during verification of proof of knowledge of signature
    PairingCheckFailed,
    /// 1st schnorr proof failed during verification of proof of knowledge of signature
    FirstSchnorrVerificationFailed,
    /// 2nd schnorr proof failed during verification of proof of knowledge of signature
    SecondSchnorrVerificationFailed,
    InvalidMsgIdxForResponse(usize),
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
