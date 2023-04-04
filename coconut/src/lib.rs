//! Threshold anonymous credentials based on the paper [Security Analysis of Coconut, an Attribute-Based Credential Scheme with Threshold Issuance](https://eprint.iacr.org/2022/011).
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
