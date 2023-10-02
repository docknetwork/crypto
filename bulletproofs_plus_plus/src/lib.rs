#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

pub mod error;
pub mod range_proof_arbitrary_range;
pub mod rangeproof;
pub mod setup;
pub mod util;
pub mod weighted_norm_linear_argument;

pub mod prelude {
    pub use crate::{
        error::BulletproofsPlusPlusError,
        range_proof_arbitrary_range::ProofArbitraryRange,
        rangeproof::{Proof, Prover},
        setup::SetupParams,
    };
}
