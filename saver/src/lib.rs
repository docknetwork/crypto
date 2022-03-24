#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

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
pub mod utils;

pub type Result<T> = core::result::Result<T, error::SaverError>;
