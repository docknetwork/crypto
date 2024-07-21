#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Implements the protocol from the paper [SyRA: Sybil-Resilient Anonymous Signatures with Applications to Decentralized Identity](https://eprint.iacr.org/2024/379)
//!
//! This will be used to generate pseudonym for low-entropy user attributes. The issuer will create "signature" for a unique user attribute and user uses this "signature" to create the pseudonym.

mod error;
pub mod pseudonym;
pub mod setup;
pub mod vrf;
