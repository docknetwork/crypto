#[cfg(feature = "aggregation")]
use crate::aggregation::error::AggregationError;
#[cfg(feature = "circom")]
use crate::circom::error::CircomError;

use crate::link::error::LinkError;
use ark_relations::r1cs::SynthesisError;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    SynthesisError(SynthesisError),
    LinkError(LinkError),
    VectorLongerThanExpected(usize, usize),
    InvalidProof,
    InvalidLinkCommitment,
    InvalidWitnessCommitment,
    InsufficientWitnessesForCommitment(usize, usize),
    #[cfg(feature = "circom")]
    CircomError(CircomError),
    #[cfg(feature = "aggregation")]
    AggregationError(AggregationError),
}

impl From<SynthesisError> for Error {
    fn from(e: SynthesisError) -> Self {
        Self::SynthesisError(e)
    }
}

impl From<LinkError> for Error {
    fn from(e: LinkError) -> Self {
        Self::LinkError(e)
    }
}

#[cfg(feature = "circom")]
impl From<CircomError> for Error {
    fn from(e: CircomError) -> Self {
        Self::CircomError(e)
    }
}

#[cfg(feature = "aggregation")]
impl From<AggregationError> for Error {
    fn from(e: AggregationError) -> Self {
        Self::AggregationError(e)
    }
}
