use ark_serialize::SerializationError;
use dock_crypto_utils::serde_utils::ArkSerializationError;
use oblivious_transfer_protocols::error::OTError;
use schnorr_pok::error::SchnorrError;
use secret_sharing_and_dkg::error::SSError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum ShortGroupSigError {
    ZeroSignature,
    InvalidSignature,
    SchnorrError(SchnorrError),
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    InvalidProof,
    InvalidMembershipValidityProof,
    MissingResponsesNeededForPartialSchnorrProofVerification,
    NeedEitherPartialOrCompleteSchnorrResponse,
    NeedPartialSchnorrResponse,
    NeedCompleteSchnorrResponse,
    SSError(SSError),
    OTError(OTError),
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

impl From<SSError> for ShortGroupSigError {
    fn from(e: SSError) -> Self {
        Self::SSError(e)
    }
}

impl From<OTError> for ShortGroupSigError {
    fn from(e: OTError) -> Self {
        Self::OTError(e)
    }
}
