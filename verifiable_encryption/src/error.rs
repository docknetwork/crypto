use ark_serialize::SerializationError;

#[derive(Debug)]
pub enum VerifiableEncryptionError {
    InvalidProof,
    DecryptionFailed,
    CiphertextNotFound(u16),
    ShareNotFound(u16),
    UnexpectedNumberOfTreeOpenings(usize, usize),
    UnexpectedTreeOpeningSize(usize, usize),
    UnexpectedCommitmentKeySize(usize, usize),
    UnexpectedNumberOfCommitments(usize, usize),
    UnexpectedNumberOfCiphertexts(usize, usize),
    UnexpectedNumberOfSharesAndEncRands(usize, usize),
    UnexpectedNumberOfHelperData(usize, usize),
    InequalNumberOfCiphertextsAndWitnesses(usize, usize),
    InequalNumberOfDeltaForWitnesses(usize, usize),
    InequalNumberOfDeltas(usize, usize),
    InequalNumberOfSharesAndWitnesses(usize, usize),
    IncompatibleRandomnessSize,
    SubsetSizeGreaterThenExpected(usize, usize),
    Serialization(SerializationError),
}

impl From<SerializationError> for VerifiableEncryptionError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
