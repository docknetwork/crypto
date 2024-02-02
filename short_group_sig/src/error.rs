use ark_serialize::SerializationError;
use dock_crypto_utils::serde_utils::ArkSerializationError;
use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum ShortGroupSigError {
    ZeroSignature,
    InvalidSignature,
    SchnorrError(SchnorrError),
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    InvalidProof,
    InvalidMembershipCorrectnessProof,
}

impl From<SchnorrError> for ShortGroupSigError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<SerializationError> for ShortGroupSigError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
