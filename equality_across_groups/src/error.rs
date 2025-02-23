use ark_serialize::SerializationError;
use bulletproofs_plus_plus::error::BulletproofsPlusPlusError;
use schnorr_pok::error::SchnorrError;

#[derive(Debug)]
pub enum Error {
    WitnessBiggerThanExpected,
    WitnessBiggerThan64Bit,
    ZOutOfRangeForRep(usize),
    SchnorrCheckFailedForRep(usize),
    MissingRangeProof,
    BulletproofsPlusPlusGeneratorsDontMatchCommitmentKey,
    RecreatedCommitmentsDontMatch,
    /// Scalar field of committing group should have same size as base field of curve whose point is being committed
    ScalarFieldBaseFieldMismatch,
    CannotCommitToExtensionOfDegree(u64),
    PointAtInfinity,
    CannotAddEqualPoints,
    XCoordCantBeSame,
    InvalidPointAddResult,
    InverseProofFailed,
    LambdaProofFailed,
    TxProofFailed,
    TyProofFailed,
    IncorrectTxOpening,
    IncorrectTx,
    IncorrectTyOpening,
    IncorrectTy,
    InsufficientNumberOfRepetitions(usize, usize),
    InsufficientChallengeSize(usize, usize),
    ExpectedEvenButFoundOddAtRep(usize),
    ExpectedOddButFoundEvenAtRep(usize),
    // TODO: Rename
    IncorrectA1OpeningAtIndex(usize),
    IncorrectPointOpeningAtIndex(usize),
    IncorrectScalarOpeningAtIndex(usize),
    EcdsaSigResponseNotInvertible,
    InvalidTransformedEcdsaSig,
    BulletproofsPlusPlus(BulletproofsPlusPlusError),
    Schnorr(SchnorrError),
    Serialization(SerializationError),
}

impl From<BulletproofsPlusPlusError> for Error {
    fn from(e: BulletproofsPlusPlusError) -> Self {
        Self::BulletproofsPlusPlus(e)
    }
}

impl From<SchnorrError> for Error {
    fn from(e: SchnorrError) -> Self {
        Self::Schnorr(e)
    }
}

impl From<SerializationError> for Error {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
