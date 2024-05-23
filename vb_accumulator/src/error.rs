// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

#![allow(non_camel_case_types)]

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use dock_crypto_utils::serde_utils::ArkSerializationError;
use kvac::error::KVACError;
use oblivious_transfer_protocols::error::OTError;
use schnorr_pok::error::SchnorrError;
use secret_sharing_and_dkg::error::SSError;
use serde::Serialize;
use short_group_sig::error::ShortGroupSigError;

#[derive(Debug, Serialize)]
pub enum VBAccumulatorError {
    /// Element not allowed in the accumulator
    ProhibitedElement,
    /// No more elements can be added in the accumulator
    AccumulatorFull,
    /// The batch of updates if applied will make the accumulator larger than its max size.
    BatchExceedsAccumulatorCapacity,
    /// Element is already present in the accumulator
    ElementPresent,
    /// Element is already absent in the accumulator
    ElementAbsent,
    NewElementSameAsCurrent,
    NeedSameNoOfElementsAndWitnesses,
    CannotBeZero,
    SigmaResponseInvalid,
    RhoResponseInvalid,
    DeltaSigmaResponseInvalid,
    DeltaRhoResponseInvalid,
    PairingResponseInvalid,
    E_d_ResponseInvalid,
    E_d_inv_ResponseInvalid,
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
    InvalidMembershipCorrectnessProof,
    InvalidNonMembershipCorrectnessProof,
    IncorrectRandomizedWitness,
    InvalidWitness,
    ShortGroupSigError(ShortGroupSigError),
    MismatchBetweenSignatureAndAccumulatorValue,
    KVACError(KVACError),
    SSError(SSError),
    OTError(OTError),
}

impl From<SchnorrError> for VBAccumulatorError {
    fn from(e: SchnorrError) -> Self {
        Self::SchnorrError(e)
    }
}

impl From<SerializationError> for VBAccumulatorError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

impl From<ShortGroupSigError> for VBAccumulatorError {
    fn from(e: ShortGroupSigError) -> Self {
        Self::ShortGroupSigError(e)
    }
}

impl From<KVACError> for VBAccumulatorError {
    fn from(e: KVACError) -> Self {
        Self::KVACError(e)
    }
}

impl From<SSError> for VBAccumulatorError {
    fn from(e: SSError) -> Self {
        Self::SSError(e)
    }
}

impl From<OTError> for VBAccumulatorError {
    fn from(e: OTError) -> Self {
        Self::OTError(e)
    }
}
