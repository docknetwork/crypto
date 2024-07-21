use ark_serialize::SerializationError;

#[derive(Debug)]
pub enum SyraError {
    InvalidProof,
    Serialization(SerializationError),
}

impl From<SerializationError> for SyraError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
