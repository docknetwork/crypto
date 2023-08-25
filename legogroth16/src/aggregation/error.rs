use ark_serialize::SerializationError;
use ark_std::string::{String, ToString};

#[derive(Debug, Clone, PartialEq)]
pub enum AggregationError {
    InsufficientKeyLength(usize),
    PublicInputsTooLarge(usize),
    TooManyProofs(usize),
    InvalidKeyLength,
    InvalidProof(String),
    MalformedVerifyingKey,
    Serialization(String),
    InvalidSRS(String),
}

impl From<SerializationError> for AggregationError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e.to_string())
    }
}
