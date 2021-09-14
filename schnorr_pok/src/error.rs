// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;

#[derive(Debug)]
pub enum SchnorrError {
    ExpectedSameSizeSequences(usize, usize),
    IndexOutOfBounds(usize, usize),
    InvalidResponse,
    Serialization(SerializationError),
}

impl From<SerializationError> for SchnorrError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
