use bulletproofs_plus_plus::error::BulletproofsPlusPlusError;

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
    IncorrectTxOpening,
    IncorrectTx,
    IncorrectTyOpening,
    IncorrectTy,
    InsufficientNumberOfRepetitions(usize, usize),
    ExpectedEvenButFoundOddAtRep(usize),
    ExpectedOddButFoundEvenAtRep(usize),
    // TODO: Rename
    IncorrectA1OpeningAtIndex(usize),
    IncorrectPointOpeningAtIndex(usize),
    IncorrectScalarOpeningAtIndex(usize),
    EcdsaSigResponseNotInvertible,
    InvalidTransformedEcdsaSig,
    BulletproofsPlusPlusError(BulletproofsPlusPlusError),
}

impl From<BulletproofsPlusPlusError> for Error {
    fn from(e: BulletproofsPlusPlusError) -> Self {
        Self::BulletproofsPlusPlusError(e)
    }
}
