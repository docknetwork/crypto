//! # Threshold anonymous credentials using Coconut
//!
//! - Based on the paper [Security Analysis of Coconut, an Attribute-Based Credential Scheme with Threshold Issuance](https://eprint.iacr.org/2022/011).
//! - Contains a modified implementation of PS (Pointcheval-Sanders) signature, as described in the above paper.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod helpers;
pub mod proof;
pub mod setup;
pub mod signature;

#[cfg(test)]
mod tests;

pub use proof::*;
pub use setup::{keygen, PublicKey, SecretKey};
pub use signature::*;
