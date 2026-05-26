use ark_std::string::String;
use dock_crypto_utils::error::UtilsError;
#[cfg(feature = "serde")]
use serde::Serialize;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum BulletproofsPlusPlusError {
    UnexpectedLengthOfVectors(String),
    WeightedNormLinearArgumentVerificationFailed,
    ExpectedPowerOfTwo(String),
    ValueIncompatibleWithBase(String),
    IncorrectBounds(String),
    IncorrectNumberOfCommitments(usize, usize),
    UtilsError(UtilsError),
}

impl From<UtilsError> for BulletproofsPlusPlusError {
    fn from(e: UtilsError) -> Self {
        Self::UtilsError(e)
    }
}
