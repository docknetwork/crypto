// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use dock_crypto_utils::{
    serde_utils::ArkSerializationError,
    try_iter::{IndexIsOutOfBounds, InvalidPair},
};
use oblivious_transfer_protocols::{error::OTError, ParticipantId};
use schnorr_pok::error::SchnorrError;
use secret_sharing_and_dkg::error::SSError;
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
    OTError(OTError),
    SenderIdCannotBeSameAsSelf(ParticipantId, ParticipantId),
    AlreadyHaveCommitmentFromParticipant(ParticipantId),
    MissingCommitmentFromParticipant(ParticipantId),
    IncorrectNoOfCommitments(usize, usize),
    MissingSharesFromParticipant(ParticipantId),
    AlreadyHaveSharesFromParticipant(ParticipantId),
    IncorrectNoOfShares(usize, usize),
    IncorrectCommitment,
    UnexpectedParticipant(ParticipantId),
    MissingOTReceiverFor(ParticipantId),
    MissingOTSenderFor(ParticipantId),
    NotAMultiplicationParty2(ParticipantId),
    NotAMultiplicationParty1(ParticipantId),
    UnexpectedMultiplicationParty1(ParticipantId),
    UnexpectedMultiplicationParty2(ParticipantId),
    IncorrectEByParticipant(ParticipantId),
    IncorrectSByParticipant(ParticipantId),
    ParticipantCannotBePresentInOthers(ParticipantId),
    NotABaseOTSender(ParticipantId),
    NotABaseOTReceiver(ParticipantId),
    AlreadyHaveSenderPubkeyFrom(ParticipantId),
    AlreadyHaveReceiverPubkeyFrom(ParticipantId),
    ReceiverNotReadyForChallengeFrom(ParticipantId),
    AlreadyHaveChallengesFrom(ParticipantId),
    SenderEitherNotReadyForResponseOrAlreadySentIt(ParticipantId),
    ReceiverEitherNotReadyForHashedKeysOrAlreadyVerifiedIt(ParticipantId),
    SSError(SSError),
}

impl From<SchnorrError> for BBSPlusError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<InvalidPair<usize>> for BBSPlusError {
    fn from(err: InvalidPair<usize>) -> Self {
        Self::MessageIndicesMustBeUniqueAndSorted(err)
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

impl From<OTError> for BBSPlusError {
    fn from(e: OTError) -> Self {
        Self::OTError(e)
    }
}

impl From<SSError> for BBSPlusError {
    fn from(e: SSError) -> Self {
        Self::SSError(e)
    }
}
