use ark_std::string::String;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum BulletproofsPlusPlusError {
    UnexpectedLengthOfVectors(String),
    WeightedNormLinearArgumentVerificationFailed,
    ExpectedPowerOfTwo(String),
    ValueIncompatibleWithBase(String),
    IncorrectBounds(String),
    IncorrectNumberOfCommitments(usize, usize),
}
