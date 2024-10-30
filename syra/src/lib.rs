#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Implements the protocol from the paper [SyRA: Sybil-Resilient Anonymous Signatures with Applications to Decentralized Identity](https://eprint.iacr.org/2024/379)
//!
//! This will be used to generate pseudonym for low-entropy user attributes. The issuer will create "signature" for a
//! unique user attribute and user uses this "signature" to create the pseudonym.
//!
//! Also implements the threshold issuance of SyRA signatures
//!
//! A more efficient protocol generating pseudonym and corresponding proof of knowledge is implemented in the module [pseudonym_alt](./src/pseudonym_alt.rs)

pub mod error;
pub mod pseudonym;
pub mod pseudonym_alt;
pub mod setup;
pub mod threshold_issuance;
pub mod vrf;
