use ark_serialize::SerializationError;
use ark_std::{collections::BTreeSet, fmt::Debug, string::String, vec::Vec};
use bbs_plus::error::BBSPlusError;
use bulletproofs_plus_plus::error::BulletproofsPlusPlusError;
use dock_crypto_utils::try_iter::InvalidPair;
use kvac::error::KVACError;
use legogroth16::{circom::CircomError, error::Error as LegoGroth16Error};
use saver::error::SaverError;
use schnorr_pok::error::SchnorrError;
use smc_range_proof::prelude::SmcRangeProofError;
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
    BBSPlusProtocolInvalidMessageCount(usize, usize),
    SigProtocolInvalidBlindingIndex(usize),
    SigProtocolNonSequentialMessageIndices(InvalidPair<usize>),
    SigProtocolMessageIndicesMustStartFromZero(usize),
    PSProtocolInvalidMessageCount(usize, usize),
    PSProtocolNonSequentialMessageIndices(InvalidPair<usize>),
    PSProtocolInvalidBlindingIndex(usize),
    PSProtocolInvalidMessageIndex(usize, usize),
    PSProtocolMessageIndicesMustStartFromZero(usize),
    SubProtocolNotReadyToGenerateChallenge(usize),
    SubProtocolAlreadyInitialized(usize),
    SubProtocolNotReadyToGenerateProof(usize),
    InvalidSetupParamsIndex(usize),
    TooManyCiphertexts(usize),
    NeitherParamsNorRefGiven(usize),
    IncompatibleBBSPlusSetupParamAtIndex(usize),
    IncompatiblePSSetupParamAtIndex(usize),
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
    /// `Statement`s were missing for some `StatementProof`s
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
    IncompatibleR1CSSetupParamAtIndex(usize),
    CircomError(CircomError),
    R1CSInsufficientPrivateInputs(usize, usize),
    InvalidWitnessEquality,
    /// Witness is being used a zero knowledge proof (bound check, accumulator, etc) while also being
    /// revealed. This shouldn't be the case, ever.
    WitnessAlreadyBeingRevealed(usize, usize),
    SnarckpackSrsNotProvided,
    NotASaverStatementProof,
    RandomizedPairingCheckFailed,
    SameStatementIdsFoundInMultipleAggregations(Vec<usize>),
    NoAggregateGroth16ProofFound,
    InvalidNumberOfAggregateGroth16Proofs(usize, usize),
    NotFoundAggregateGroth16ProofForRequiredStatements(usize, BTreeSet<usize>),
    NoAggregateLegoGroth16ProofFound,
    InvalidNumberOfAggregateLegoGroth16Proofs(usize, usize),
    NotFoundAggregateLegoGroth16ProofForRequiredStatements(usize, BTreeSet<usize>),
    PSSignaturePoKError(coconut_crypto::SignaturePoKError),
    UnsupportedValue(String),
    /// For an arbitrary range proof, the response of both Schnorr protocols should be same
    DifferentResponsesForSchnorrProtocolInBpp(usize),
    BulletproofsPlusPlus(BulletproofsPlusPlusError),
    SetMembershipBasedRangeProof(SmcRangeProofError),
    SmcParamsNotProvided,
    SchnorrProofContributionFailed(u32, SchnorrError),
    BBSPlusProofContributionFailed(u32, BBSPlusError),
    BBSProofContributionFailed(u32, BBSPlusError),
    VBAccumProofContributionFailed(u32, VBAccumulatorError),
    SaverProofContributionFailed(u32, SaverError),
    LegoSnarkProofContributionFailed(u32, LegoGroth16Error),
    PSProofContributionFailed(u32, coconut_crypto::SignaturePoKError),
    BulletproofsPlusPlusProofContributionFailed(u32, BulletproofsPlusPlusError),
    SmcRangeProofContributionFailed(u32, SmcRangeProofError),
    DetachedVBAccumProofContributionFailed(u32, VBAccumulatorError),
    IncorrectEncryptedAccumulator,
    KBAccumProofContributionFailed(u32, VBAccumulatorError),
    KVACError(KVACError),
    BDDT16KVACProtocolInvalidMessageCount(usize, usize),
    BDDT16KVACProofContributionFailed(u32, KVACError),
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

impl From<CircomError> for ProofSystemError {
    fn from(e: CircomError) -> Self {
        Self::CircomError(e)
    }
}

impl From<coconut_crypto::SignaturePoKError> for ProofSystemError {
    fn from(e: coconut_crypto::SignaturePoKError) -> Self {
        Self::PSSignaturePoKError(e)
    }
}

impl From<BulletproofsPlusPlusError> for ProofSystemError {
    fn from(e: BulletproofsPlusPlusError) -> Self {
        Self::BulletproofsPlusPlus(e)
    }
}

impl From<SmcRangeProofError> for ProofSystemError {
    fn from(e: SmcRangeProofError) -> Self {
        Self::SetMembershipBasedRangeProof(e)
    }
}

impl From<KVACError> for ProofSystemError {
    fn from(e: KVACError) -> Self {
        Self::KVACError(e)
    }
}
