use ark_std::string::String;
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
}
