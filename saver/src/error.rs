use ark_relations::r1cs::SynthesisError;
use legogroth16::error::Error as LegoGroth16Error;

#[derive(Clone, Debug)]
pub enum SaverError {
    UnexpectedBase(u8),
    InvalidDecomposition,
    LegoGroth16Error(LegoGroth16Error),
    SynthesisError(SynthesisError),
    AtLeastOneNonNoneRequired,
    VectorShorterThanExpected(usize, usize),
    MalformedEncryptionKey(usize, usize),
    MalformedDecryptionKey(usize, usize),
    IncompatibleEncryptionKey(usize, usize),
    IncompatibleDecryptionKey(usize, usize),
    InvalidProof,
    InvalidCommitment,
    InvalidDecryption,
    CouldNotFindDiscreteLog,
    InvalidPairingPowers,
    PairingCheckFailed,
}

impl From<SynthesisError> for SaverError {
    fn from(e: SynthesisError) -> Self {
        Self::SynthesisError(e)
    }
}

impl From<LegoGroth16Error> for SaverError {
    fn from(e: LegoGroth16Error) -> Self {
        Self::LegoGroth16Error(e)
    }
}
