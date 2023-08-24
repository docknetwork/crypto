use schnorr_pok::error::SchnorrError;
use serde::Serialize;

#[derive(Debug, Serialize)]
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
    IncorrectOTExtensionConfig(u16, u64),
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
}

impl From<SchnorrError> for OTError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}
