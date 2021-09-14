#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Dynamic Positive and Universal accumulators according to the paper: "Dynamic Universal Accumulator with Batch Update over Bilinear Groups" <https://eprint.iacr.org/2020/777>
//! Provides a dynamic positive accumulator [`PositiveAccumulator`], that supports membership proofs
//! Provides a dynamic universal accumulator [`UniversalAccumulator`], that supports membership and non-membership proofs
//! Provides a zero knowledge proof of membership and non-membership in the accumulators with [`ProofProtocol`].
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.
//!
//! [`PositiveAccumulator`]: crate::positive::PositiveAccumulator
//! [`UniversalAccumulator`]: crate::universal::UniversalAccumulator
//! [`ProofProtocol`]: crate::proofs::ProofProtocol

#[macro_use]
pub mod utils;
pub mod batch_utils;
pub mod error;
pub mod persistence;
pub mod positive;
pub mod proofs;
pub mod setup;
pub mod universal;
pub mod witness;

pub mod prelude {
    pub use crate::batch_utils::Omega;
    pub use crate::error::VBAccumulatorError;
    pub use crate::positive::{Accumulator, PositiveAccumulator};
    pub use crate::proofs::*;
    pub use crate::setup::*;
    pub use crate::universal::UniversalAccumulator;
    pub use crate::witness::{MembershipWitness, NonMembershipWitness, Witness};
}

#[cfg(test)]
#[macro_use]
pub mod tests {
    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ident, $obj: expr) => {
            let mut serz = vec![];
            $obj.serialize(&mut serz).unwrap();
            assert_eq!($obj_type::deserialize(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_unchecked(&mut serz).unwrap();
            assert_eq!($obj_type::deserialize_unchecked(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_uncompressed(&mut serz).unwrap();
            assert_eq!(
                $obj_type::deserialize_uncompressed(&serz[..]).unwrap(),
                $obj
            );
        };
    }
}
