use ark_serialize::SerializationError;
use schnorr_pok::error::SchnorrError;

#[derive(Debug)]
pub enum DelegationError {
    InsufficientSetCommitmentSRSSize(usize, usize),
    InvalidOpening,
    NotASubset,
    ShouldNotContainTrapdoor,
    InvalidWitness,
    NeedNonZeroSize,
    MessageCountIncompatibleWithKey(usize, usize),
    InvalidSignature,
    InvalidSignatureRequest,
    InvalidRevocationRequest,
    KeyDoesNotSupportRevocation,
    AccumulatorPublicParamsNotProvided,
    AccumulatorPublicKeyNotProvided,
    AccumulatorNotProvided,
    NeedUserSecretKey,
    NeedUserPublicKey,
    NeedAuditorPublicKey,
    NeedAccumulator,
    NeedWitness,
    IssuerKeyDoesNotSupportAuditableSignature,
    InvalidCredentialShow,
    InvalidAuditShow,
    InvalidRevocationShow,
    AlreadyAMember,
    IncompatiblePublicKey,
    UnequalSizeOfSequence(usize, usize),
    InvalidOneOfNProof,
    TooManyAttributes(usize),
    TooManyCommitments(usize),
    TooManyWitnesses(usize),
    NeedSameNoOfCommitmentsAndSubsets(usize, usize),
    CannotCreateUpdateKeyOfRequiredSizeFromSecretKey(usize, usize),
    InvalidUpdateKeyIndex(usize, usize),
    UnsupportedIndexInUpdateKey(usize, usize, usize),
    UnsupportedNoOfAttributesInUpdateKey(usize, usize),
    InvalidUpdateKey,
    InvalidSchnorrProof,
    SchnorrError(SchnorrError),
    Serialization(SerializationError),
}

impl From<SerializationError> for DelegationError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

impl From<SchnorrError> for DelegationError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}
