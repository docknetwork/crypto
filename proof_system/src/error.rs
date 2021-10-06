use ark_std::string::String;

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use bbs_plus::error::BBSPlusError;
use schnorr_pok::error::SchnorrError;
use vb_accumulator::error::VBAccumulatorError;

#[derive(Debug)]
pub enum ProofSystemError {
    UnequalWitnessAndStatementCount(usize, usize),
    WitnessIncompatibleWithStatement(usize, String, String),
    ProofIncompatibleWithStatement(usize, String, String),
    ProofIncompatibleWithProtocol(String),
    BBSPlusProtocolMessageAbsent(usize, usize),
    SubProtocolNotReadyToGenerateChallenge(usize),
    SubProtocolAlreadyInitialized(usize),
    SubProtocolNotReadyToGenerateProof(usize),
    /// This error indicates that some witnesses that were required to be equal are not equal
    WitnessResponseNotEqual(usize, usize),
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
    BBSPlusError(BBSPlusError),
    VBAccumError(VBAccumulatorError),
    InvalidProofSpec,
}

impl From<SchnorrError> for ProofSystemError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<BBSPlusError> for ProofSystemError {
    fn from(e: BBSPlusError) -> Self {
        Self::BBSPlusError(e)
    }
}

impl From<VBAccumulatorError> for ProofSystemError {
    fn from(e: VBAccumulatorError) -> Self {
        Self::VBAccumError(e)
    }
}

impl From<SerializationError> for ProofSystemError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
