#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! # Verifiable encryption using SAVER
//! Implementation based on [`SAVER`]. Implemented
//! - using [`Groth16`]
//! - as well as [`LegoGroth16`].
//!
//! The basic idea of the verifiable encryption construction is to split the message to be encrypted (a field element) into small chunks
//! of say `b` bits and encrypt each chunk in an exponent variant of Elgamal encryption. For decryption, discrete log problem in the
//! extension field (`F_{q^k}`) is solved with brute force where the discrete log is of at most `b` bits so `2^b - 1` iterations.
//! The SNARK (Groth16) is used for prove that each chunk is of at most `b` bits, thus a range proof.
//!
//! The encryption outputs a commitment in addition to the ciphertext. For an encryption of message `m`, the commitment `psi` is of the following form:
//!
//! ```text
//! psi = m_1*Y_1 + m_2*Y_2 + ... + m_n*Y_n + r*P_2
//! ```
//!
//! `m_i` are the bit decomposition of the original message `m` such that `m_1*{b^{n-1}} + m_2*{b^{n-2}} + .. + m_n` (big-endian) with `b` being the radix in which `m` is decomposed and `r` is the randomness of the commitment. eg if `m` = 325 and `m` is decomposed in 4-bit chunks, `b` is 16 (2^4) and decomposition is [1, 4, 5] as `325 = 1 * 16^2 + 4 * 16^1 + 5 * 16^0`.
//!
//! ## Getting a commitment to the full message from commitment to the decomposition.
//!
//! To use the ciphertext commitment for equality of a committed message using a Schnorr protocol, the commitment must be transformed
//! to a commitment to the full (non-decomposed) message. This is implemented with [`ChunkedCommitment`] and its docs describe the process.
//!
//! ## Use with BBS+ signature
//!
//! See the tests.rs file
//!
//! [`SAVER`]: https://eprint.iacr.org/2019/1270
//! [`Groth16`]: crate::saver_groth16
//! [`LegoGroth16`]: crate::saver_legogroth16
//! [`ChunkedCommitment`]: crate::commitment::ChunkedCommitment

#[macro_use]
pub mod utils;
pub mod circuit;
pub mod commitment;
#[macro_use]
pub mod encryption;
pub mod error;
#[macro_use]
pub mod keygen;
pub mod saver_groth16;
pub mod saver_legogroth16;
pub mod setup;
#[cfg(test)]
pub mod tests;

pub type Result<T> = core::result::Result<T, error::SaverError>;

pub mod prelude {
    pub use crate::{
        commitment::ChunkedCommitment,
        error::SaverError,
        keygen::{
            keygen, DecryptionKey, EncryptionKey, PreparedDecryptionKey, PreparedEncryptionKey,
            SecretKey,
        },
        saver_groth16::{
            create_proof, generate_srs, verify_proof, PreparedVerifyingKey, ProvingKey,
            VerifyingKey,
        },
        setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens, PreparedEncryptionGens},
    };
}
