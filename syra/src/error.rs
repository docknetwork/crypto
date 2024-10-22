use ark_serialize::SerializationError;
use short_group_sig::error::ShortGroupSigError;

#[derive(Debug)]
pub enum SyraError {
    InvalidProof,
    ShortGroupSigError(ShortGroupSigError),
    Serialization(SerializationError),
}

impl From<ShortGroupSigError> for SyraError {
    fn from(e: ShortGroupSigError) -> Self {
        Self::ShortGroupSigError(e)
    }
}

impl From<SerializationError> for SyraError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
