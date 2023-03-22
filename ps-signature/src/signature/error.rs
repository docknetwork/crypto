use secret_sharing_and_dkg::common::ParticipantId;

use crate::helpers::{IndexIsOutOfBounds, InvalidPair};

/// An error originated from `Signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PSError {
    NoMessages,
    InvalidMessageCount { received: usize, expected: usize },
    MessageIndicesMustBeUniqueAndSorted(InvalidPair<usize>),
    ZeroSignature,
    MessageIndexIsOutOfBounds(IndexIsOutOfBounds),
    PairingCheckFailed,
}

impl From<IndexIsOutOfBounds> for PSError {
    fn from(err: IndexIsOutOfBounds) -> Self {
        Self::MessageIndexIsOutOfBounds(err)
    }
}

impl<T> From<InvalidPair<(usize, T)>> for PSError {
    fn from(err: InvalidPair<(usize, T)>) -> Self {
        Self::MessageIndicesMustBeUniqueAndSorted(err.map(|(idx, _)| idx))
    }
}

/// An error originated from `BlindSignature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindPSError {
    NoCommitmentsOrMessages,
    IndexIsOutOfBounds(IndexIsOutOfBounds),
    InvalidCommitmentsAndMessagesCount {
        received: Option<usize>,
        expected: usize,
    },
    BlindingIndicesMustBeUniqueAndSorted(InvalidPair<usize>),
    IncompatibleVerificationKey,
}

impl From<IndexIsOutOfBounds> for BlindPSError {
    fn from(err: IndexIsOutOfBounds) -> Self {
        Self::IndexIsOutOfBounds(err)
    }
}

impl<T> From<InvalidPair<(usize, T)>> for BlindPSError {
    fn from(err: InvalidPair<(usize, T)>) -> Self {
        Self::BlindingIndicesMustBeUniqueAndSorted(err.map(|(idx, _)| idx))
    }
}

/// An error originated from `AggregatedSignature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregatedPSError {
    NoSignatures,
    InvalidSigma1For(ParticipantId),
    ParticipantIdsMustBeUniqueAndSorted(InvalidPair<ParticipantId>),
    PSError(PSError),
}

impl<T> From<InvalidPair<(ParticipantId, T)>> for AggregatedPSError {
    fn from(err: InvalidPair<(ParticipantId, T)>) -> Self {
        Self::ParticipantIdsMustBeUniqueAndSorted(err.map(|(idx, _)| idx))
    }
}

impl From<PSError> for AggregatedPSError {
    fn from(error: PSError) -> Self {
        Self::PSError(error)
    }
}
