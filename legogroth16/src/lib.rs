//! An implementation of the LegoGroth16 zkSNARK, the [`LegoSNARK`] variant of [`Groth16`] zkSNARK proof system.
//!
//! [`LegoSNARK`]: https://eprint.iacr.org/2019/142.pdf
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

// #[macro_use]
// extern crate bench_utils;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub(crate) mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the LegoGroth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the LegoGroth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the LegoGroth16 zkSNARK construction.
pub mod verifier;

pub mod link;

pub mod error;

/// Create and verify proofs for Circom programs
#[cfg(feature = "circom")]
pub mod circom;

#[cfg(feature = "aggregation")]
pub mod aggregation;

/// Constraints for the LegoGroth16 verifier.
// Cannot yet create a LegoGroth16 gadget (for recursive proof) so commenting it out.
// #[cfg(feature = "r1cs")]
// pub mod constraints;

pub type Result<T> = core::result::Result<T, error::Error>;

pub use self::{data_structures::*, generator::*, prover::*, r1cs_to_qap::*, verifier::*};
use ark_std::vec::Vec;

#[cfg(test)]
pub mod tests;
