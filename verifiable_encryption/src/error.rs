use ark_serialize::SerializationError;

#[derive(Debug)]
pub enum VerifiableEncryptionError {
    InvalidProof,
    DecryptionFailed,
    CiphertextNotFound(u16),
    ShareNotFound(u16),
    Serialization(SerializationError),
}

impl From<SerializationError> for VerifiableEncryptionError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
