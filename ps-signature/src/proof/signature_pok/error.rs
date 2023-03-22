use super::super::MessageUnpackingError;
use alloc::string::String;

use crate::PSError;

// TODO replace by `SchnorrError` when it will derive `Eq`, `PartialEq`, `Clone`
type SchnorrError = String;

/// An error originated from `SignaturePoK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignaturePoKError {
    MessageInputError(MessageUnpackingError),
    RevealedIndicesMustBeUniqueAndSorted { previous: usize, current: usize },
    SchnorrError(SchnorrError),
    SignatureError(PSError),
}

impl From<MessageUnpackingError> for SignaturePoKError {
    fn from(err: MessageUnpackingError) -> Self {
        Self::MessageInputError(err)
    }
}
