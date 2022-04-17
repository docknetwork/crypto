use ark_serialize::SerializationError;
use ark_std::{collections::BTreeSet, fmt::Debug, string::String, vec::Vec};
use bbs_plus::error::BBSPlusError;
use legogroth16::error::Error as LegoGroth16Error;
use saver::error::SaverError;
use schnorr_pok::error::SchnorrError;
use vb_accumulator::error::VBAccumulatorError;

#[derive(Debug)]
pub enum ProofSystemError {
    UnequalWitnessAndStatementCount(usize, usize),
    WitnessIncompatibleWithStatement(usize, String, String),
    ProofIncompatibleWithStatement(usize, String, String),
    ProofIncompatibleWithBBSPlusProtocol,
    ProofIncompatibleWithSchnorrProtocol,
    ProofIncompatibleWithAccumulatorMembershipProtocol,
    ProofIncompatibleWithAccumulatorNonMembershipProtocol,
    ProofIncompatibleWithSaverProtocol,
    ProofIncompatibleWithBoundCheckProtocol,
    BBSPlusProtocolMessageAbsent(usize, usize),
    SubProtocolNotReadyToGenerateChallenge(usize),
    SubProtocolAlreadyInitialized(usize),
    SubProtocolNotReadyToGenerateProof(usize),
    InvalidSetupParamsIndex(usize),
    NeitherParamsNorRefGiven(usize),
    IncompatibleBBSPlusSetupParamAtIndex(usize),
    IncompatiblePedCommSetupParamAtIndex(usize),
    IncompatibleAccumulatorSetupParamAtIndex(usize),
    IncompatibleSaverSetupParamAtIndex(usize),
    IncompatibleBoundCheckSetupParamAtIndex(usize),
    /// This error indicates that some witnesses that were required to be equal are not equal
    WitnessResponseNotEqual(usize, usize),
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
    BBSPlusError(BBSPlusError),
    VBAccumError(VBAccumulatorError),
    InvalidProofSpec,
    InvalidStatement,
    /// Some of the witness equalities given for proof creation are invalid
    InvalidWitnessEqualities(Vec<(usize, usize)>),
    /// The proof did not satisfy all the witness equalities
    UnsatisfiedWitnessEqualities(Vec<BTreeSet<(usize, usize)>>),
    /// `StatementProof`s were missing for some `Statement`s
    UnsatisfiedStatements(usize, usize),
    InvalidStatementProofIndex(usize),
    SaverError(SaverError),
    SaverInequalChunkedCommitment,
    SaverInsufficientChunkedCommitmentResponses,
    SaverInequalChunkedCommitmentResponse,
    SaverSnarkProvingKeyNotProvided,
    SaverSnarkVerifyingKeyNotProvided,
    LegoGroth16Error(LegoGroth16Error),
    LegoGroth16InequalResponse,
    LegoGroth16ProvingKeyNotProvided,
    LegoGroth16VerifyingKeyNotProvided,
    BoundCheckMaxNotGreaterThanMin,
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

impl From<SaverError> for ProofSystemError {
    fn from(e: SaverError) -> Self {
        Self::SaverError(e)
    }
}

impl From<LegoGroth16Error> for ProofSystemError {
    fn from(e: LegoGroth16Error) -> Self {
        Self::LegoGroth16Error(e)
    }
}

impl From<SerializationError> for ProofSystemError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
