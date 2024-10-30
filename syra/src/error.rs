use ark_serialize::SerializationError;
use schnorr_pok::error::SchnorrError;
use short_group_sig::error::ShortGroupSigError;

#[derive(Debug)]
pub enum SyraError {
    InvalidProof,
    SchnorrError(SchnorrError),
    ShortGroupSigError(ShortGroupSigError),
    Serialization(SerializationError),
}

impl From<SchnorrError> for SyraError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
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
