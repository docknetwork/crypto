#![cfg_attr(not(feature = "std"), no_std)]

//! Implements Keyed-Verification Anonymous Credentials (KVAC) schemes from the following papers.
//! KVACs are supposed to be verified by the issuer only (or anyone who shares the issuer's key)
//!
//! 1. [Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials](https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20) is [here](./src/bbdt_2016)
//! 2. [Fast Keyed-Verification Anonymous Credentials on Standard Smart Cards](https://eprint.iacr.org/2019/460) is [here](./src/cddh_2019)

pub mod bddt_2016;
pub mod cddh_2019;
