use crate::common::{ParticipantId, ShareId};
use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
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
}

impl From<SchnorrError> for SSError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}
