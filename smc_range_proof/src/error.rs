use ark_serialize::SerializationError;
use ark_std::string::String;
use schnorr_pok::error::SchnorrError;
use short_group_sig::error::ShortGroupSigError;

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
    ShortGroupSig(ShortGroupSigError),
    Schnorr(SchnorrError),
    ProofShorterThanExpected(usize, usize),
}

impl From<SerializationError> for SmcRangeProofError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

impl From<ShortGroupSigError> for SmcRangeProofError {
    fn from(e: ShortGroupSigError) -> Self {
        Self::ShortGroupSig(e)
    }
}

impl From<SchnorrError> for SmcRangeProofError {
    fn from(e: SchnorrError) -> Self {
        Self::Schnorr(e)
    }
}
