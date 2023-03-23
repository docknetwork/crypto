use super::super::MessageUnpackingError;
use alloc::string::String;

// TODO replace by `SchnorrError` when it will derive `Eq`, `PartialEq`, `Clone`
type SchnorrError = String;

/// An error originated from `MessagesPoK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessagesPoKError {
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

impl From<MessageUnpackingError> for MessagesPoKError {
    fn from(err: MessageUnpackingError) -> Self {
        Self::MessageInputError(err)
    }
}
