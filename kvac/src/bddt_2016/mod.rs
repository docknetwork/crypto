//! Implements KVAC from [Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials](https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20)
//! An alternate implementation of proof of knowledge of MAC is added which is adapted from the protocol to prove knowledge of
//! BBS+ signatures described in section 4.5 of the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
//! In addition it supports generating proof of validity or invalidity of keyed-proofs, i.e. the proof verifying which requires the knowledge of
//! secret key.

pub mod keyed_proof;
pub mod mac;
pub mod proof;
pub mod proof_cdh;
pub mod setup;
