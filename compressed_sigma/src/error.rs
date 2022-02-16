use ark_serialize::SerializationError;
use ark_std::fmt::Debug;

#[derive(Debug)]
pub enum CompSigmaError {
    InvalidResponse,
    VectorTooShort,
    VectorLenMismatch,
    UncompressedNotPowerOf2,
    Serialization(SerializationError),
    WrongRecursionLevel,
    FaultyParameterSize,
}

impl From<SerializationError> for CompSigmaError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
