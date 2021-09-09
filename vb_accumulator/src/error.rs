// TODO: At some point this should be replaced with crates anyhow and thiserror but thiserror is no_std compatible at the moment.

#![allow(non_camel_case_types)]

use ark_serialize::SerializationError;
use ark_std::fmt::Debug;
use schnorr_pok::error::SchnorrError;

#[derive(Debug)]
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
    Serialization(SerializationError),
    SchnorrError(SchnorrError),
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
