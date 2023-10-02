use ark_serialize::SerializationError;
use ark_std::string::String;

#[derive(Debug)]
pub enum SmcRangeProofError {
    ZeroSignature,
    InvalidSignature,
    InvalidSetMembershipSetup,
    CannotFindElementInSet,
    InvalidSetMembershipProof,
    InvalidRangeProof,
    UnsupportedBase(u16, u16),
    InvalidRange(u64, u16),
    IncorrectBounds(String),
    Serialization(SerializationError),
}

impl From<SerializationError> for SmcRangeProofError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}
