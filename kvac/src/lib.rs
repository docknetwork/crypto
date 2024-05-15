#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Implements Keyed-Verification Anonymous Credentials (KVAC) schemes from the following papers.
//! KVACs are supposed to be verified by the issuer only (or anyone who shares the issuer's key)
//!
//! 1. [Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials](https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20) is implemented [here](./src/bbdt_2016)
//! 2. [Fast Keyed-Verification Anonymous Credentials on Standard Smart Cards](https://eprint.iacr.org/2019/460) is specified [here](./src/cddh_2019) but is pending implementation.
//!
//! Both implementations support additional verification methods that allow joint verification of proof of possession of credentials where one
//! of the verifier is the issuer who knows the secret key and another verifier does not know secret key but learns the revealed attributes which
//! are not shared with the issuer. This lets us build for a use-case where issuer wants to allow anytime its issued credential is used
//! (eg. to get paid by the verifier) while still not harming the user's privacy as it doesn't learn any revealed attributes. The first
//! verifier, i.e. the issuer can also provide a proof of validity or invalidity to the second verifier.

pub mod bddt_2016;
pub mod cddh_2019;
pub mod error;
