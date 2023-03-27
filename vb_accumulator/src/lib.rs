#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Dynamic Positive and Universal accumulators according to the paper: [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
//! Provides
//! - a dynamic positive accumulator [`PositiveAccumulator`], that supports membership proofs.
//! - a dynamic universal accumulator [`UniversalAccumulator`], that supports membership and non-membership proofs.
//! - a zero knowledge proof of membership and non-membership in the accumulators with [`ProofProtocol`].
//!
//! Allows
//! - single and batch updates (additions, removals or both) to the accumulators.
//! - single and batch updates to the witness.
//!
//! Both accumulators implement that trait [`Accumulator`] that contains the common functionality.
//! Both [`MembershipWitness`] and [`NonMembershipWitness`] can be updated either using secret key or using public
//! info published by accumulator manager called [`Omega`].
//! Most of the update logic is in the trait [`Witness`] which is implemented by both [`MembershipWitness`]
//! and [`NonMembershipWitness`].
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.
//!
//! [`Accumulator`]: crate::positive::Accumulator
//! [`PositiveAccumulator`]: crate::positive::PositiveAccumulator
//! [`UniversalAccumulator`]: crate::universal::UniversalAccumulator
//! [`MembershipWitness`]: crate::witness::MembershipWitness
//! [`NonMembershipWitness`]: crate::witness::NonMembershipWitness
//! [`Witness`]: crate::witness::Witness
//! [`Omega`]: crate::batch_utils::Omega
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
pub mod universal_init_constants;
pub mod witness;

pub mod prelude {
    pub use crate::{
        batch_utils::Omega,
        error::VBAccumulatorError,
        positive::{Accumulator, PositiveAccumulator},
        proofs::*,
        setup::*,
        universal::UniversalAccumulator,
        witness::{MembershipWitness, NonMembershipWitness, Witness},
    };
}

#[cfg(test)]
#[macro_use]
pub mod tests {
    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ty, $obj: expr) => {
            let mut serz = vec![];
            CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
            let deserz: $obj_type =
                CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            let mut serz = vec![];
            $obj.serialize_uncompressed(&mut serz).unwrap();
            let deserz: $obj_type =
                CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            // Test JSON serialization
            let ser = serde_json::to_string(&$obj).unwrap();
            let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
            assert_eq!($obj, deser);

            // Test Message Pack serialization
            let ser = rmp_serde::to_vec_named(&$obj).unwrap();
            let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
            assert_eq!($obj, deser);
        };
    }
}
