#![cfg_attr(not(feature = "std"), no_std)]

//! # Verifiable encryption schemes
//!
//! Verifiable encryption of discrete log(s) from the paper [Verifiable Encryption from MPC-in-the-Head](https://eprint.iacr.org/2021/1704.pdf).
//!
//! Adapted to allow encrypting messages of a generalized Pedersen commitment and some other optimizations. See the [corresponding module](src/tz_21) for more details.

pub mod error;
pub mod tz_21;
