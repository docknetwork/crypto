use ark_relations::r1cs::SynthesisError;
use legogroth16::error::Error as LegoGroth16Error;

#[derive(Clone, Debug)]
pub enum Error {
    UnexpectedBase(u8),
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
}

impl From<SynthesisError> for Error {
    fn from(e: SynthesisError) -> Self {
        Self::SynthesisError(e)
    }
}

impl From<LegoGroth16Error> for Error {
    fn from(e: LegoGroth16Error) -> Self {
        Self::LegoGroth16Error(e)
    }
}
