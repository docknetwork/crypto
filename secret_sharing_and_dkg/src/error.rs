use crate::common::{ParticipantId, ShareId};
use ark_serialize::SerializationError;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkSerializationError;
use schnorr_pok::error::SchnorrError;
#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SSError {
    InvalidThresholdOrTotal(ShareId, ShareId),
    BelowThreshold(ShareId, ShareId),
    InvalidShare,
    InvalidParticipantId(ParticipantId),
    AlreadyProcessedFromSender(ParticipantId),
    MissingSomeParticipants(ParticipantId),
    UnequalThresholdInReceivedShare(ShareId, ShareId),
    UnequalParticipantAndShareId(ParticipantId, ShareId),
    SenderIdSameAsReceiver(ParticipantId, ParticipantId),
    CannotRemoveSelf(ParticipantId),
    ParticipantNotAllowedInPhase2(ParticipantId),
    InvalidProofOfSecretKeyKnowledge,
    DoesNotSupportThreshold(ShareId),
    SchnorrError(SchnorrError),
    IdMismatchInComputationShareShareAndShareCommitment(ShareId, ShareId),
    IdMismatchInComputationShareAndItsProof(ShareId, ShareId),
    InvalidComputationShareProof(ShareId),
    UnequalNoOfProofsAndShares(usize, usize),
    UnequalNoOfProofsAndCommitments(usize, usize),
    XCordCantBeZero,
    InvalidProof,
    #[cfg_attr(feature = "serde", serde(with = "ArkSerializationError"))]
    Serialization(SerializationError),
    UnequalNoOfSharesAndPublicKeys(usize, usize),
    UnexpectedNumberOfResponses(usize, usize),
    MissingRound2MessageFrom(ParticipantId),
    InvalidNoOfCommitments(usize, usize),
}

impl From<SchnorrError> for SSError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<SerializationError> for SSError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
