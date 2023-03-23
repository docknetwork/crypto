use super::super::MessageUnpackingError;
use alloc::string::String;

// TODO replace by `SchnorrError` when it will derive `Eq`, `PartialEq`, `Clone`
type SchnorrError = String;

/// An error originated from `CommitmentsPoK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitmentsPoKError {
    MessageInputError(MessageUnpackingError),
    RevealedIndicesMustBeUniqueAndSorted {
        previous: usize,
        current: usize,
    },
    IncompatibleComJAndMessages {
        com_j_len: usize,
        messages_len: usize,
    },
    SchnorrResponsesNotEqual(usize),
    SchnorrResponsesHaveDifferentLength,
    ComProofGenerationFailed(SchnorrError),
    ComJProofGenerationFailed {
        error: SchnorrError,
        index: usize,
    },
    InvalidComProof(SchnorrError),
    InvalidComJProof {
        error: SchnorrError,
        index: usize,
    },
}

impl From<MessageUnpackingError> for CommitmentsPoKError {
    fn from(err: MessageUnpackingError) -> Self {
        Self::MessageInputError(err)
    }
}
