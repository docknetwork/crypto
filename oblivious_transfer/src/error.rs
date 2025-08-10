use crate::ParticipantId;
use schnorr_pok::error::SchnorrError;

#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum OTError {
    NeedNonZeroNumberOfOTs,
    OTShouldHaveAtLeast2Messages(u16),
    IncorrectNumberOfChoices(u16, u16),
    InvalidChoice,
    BaseOTKeySizeMustBeMultipleOf8(u16),
    SecurityParameterShouldBeMultipleOf8(u16),
    IncorrectReceiverPubKeySize(u16, u16),
    IncorrectSenderPubKeySize(u16, u16),
    NumberOfKeysExpectedToBe2(usize),
    NeedNonZeroNumberOfDerivedKeys,
    IncorrectNoOfChallenges(u16, u16),
    IncorrectNoOfBaseOTChoices(u16, u16),
    IncorrectNoOfResponses(u16, u16),
    InvalidResponseAtIndex(u16),
    InvalidHashedKeyAtIndex(u16),
    IncorrectMessageBatchSize(u16, u16),
    IncorrectNoOfMessages(u16),
    IncorrectOTExtensionConfig(u16, u32),
    MessageIsTooLong(usize),
    TooManyChoices(usize),
    MatrixSizeIsTooBig(u64),
    IncorrectNumberOfBaseOTKeys(u16, u16),
    IncorrectNumberOfOTExtensionChoices(usize, usize),
    IncorrectSizeForU(usize, usize),
    MissingConsistencyCheck(u16, u16),
    ConsistencyCheckFailed(u16, u16),
    IncorrectNoOfMessagesToEncrypt(usize, usize),
    IncorrectNoOfEncryptionsToDecrypt(usize, usize),
    IncorrectNoOfCorrelations(usize, usize),
    RandomLinearCombinationCheckSizeIncorrect(u16, u16),
    RandomLinearCombinationCheckFailed,
    IncorrectBatchSize(usize, usize),
    IncorrectRLCSize(usize, usize),
    IncorrectCorrelationTagSize(usize, usize),
    InvalidSchnorrProof,
    SchnorrError(SchnorrError),
    NotABaseOTSender(ParticipantId),
    NotABaseOTReceiver(ParticipantId),
    AlreadyHaveSenderPubkeyFrom(ParticipantId),
    SenderIdCannotBeSameAsSelf(ParticipantId, ParticipantId),
    AlreadyHaveReceiverPubkeyFrom(ParticipantId),
    ReceiverNotReadyForChallengeFrom(ParticipantId),
    AlreadyHaveChallengesFrom(ParticipantId),
    SenderEitherNotReadyForResponseOrAlreadySentIt(ParticipantId),
    ReceiverEitherNotReadyForHashedKeysOrAlreadyVerifiedIt(ParticipantId),
    MissingOTReceiverFor(ParticipantId),
    MissingOTSenderFor(ParticipantId),
    NotAMultiplicationParty2(ParticipantId),
    NotAMultiplicationParty1(ParticipantId),
    AlreadyHaveCommitmentFromParticipant(ParticipantId),
    IncorrectNoOfCommitments(usize, usize),
    IncorrectNoOfShares(usize, usize),
    MissingCommitmentFromParticipant(ParticipantId),
    AlreadyHaveSharesFromParticipant(ParticipantId),
    IncorrectCommitment,
    UnexpectedParticipant(ParticipantId),
    MissingSharesFromParticipant(ParticipantId),
    ParticipantCannotBePresentInOthers(ParticipantId),
}

impl From<SchnorrError> for OTError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}
