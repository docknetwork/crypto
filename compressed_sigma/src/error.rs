use ark_serialize::SerializationError;
use ark_std::fmt::Debug;

#[derive(Debug)]
pub enum CompSigmaError {
    InvalidResponse,
    Serialization(SerializationError),
    VectorTooShort,
    VectorLenMismatch,
}

impl From<SerializationError> for CompSigmaError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
