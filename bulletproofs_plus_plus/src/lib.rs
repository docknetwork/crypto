#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

pub mod error;
pub mod range_proof;
pub mod range_proof_arbitrary_range;
pub mod setup;
pub mod util;
pub mod weighted_norm_linear_argument;

pub mod prelude {
    pub use crate::{
        error::BulletproofsPlusPlusError,
        range_proof::{Proof, Prover},
        range_proof_arbitrary_range::ProofArbitraryRange,
        setup::SetupParams,
    };
}
