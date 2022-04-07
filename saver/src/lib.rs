#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

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
    pub use crate::commitment::ChunkedCommitment;
    pub use crate::error::SaverError;
    pub use crate::keygen::{
        keygen, DecryptionKey, EncryptionKey, PreparedDecryptionKey, PreparedEncryptionKey,
        SecretKey,
    };
    pub use crate::saver_groth16::{
        create_proof, generate_srs, verify_proof, PreparedVerifyingKey, ProvingKey, VerifyingKey,
    };
    pub use crate::setup::{
        setup_for_groth16, ChunkedCommitmentGens, EncryptionGens, PreparedEncryptionGens,
    };
}
