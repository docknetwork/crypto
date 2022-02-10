#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

#[macro_use]
pub mod utils;
pub mod amortized_homomorphism;
pub mod amortized_homomorphisms;
pub mod amortized_linear_form;
pub mod compressed_homomorphism;
pub mod compressed_linear_form;
pub mod error;
#[macro_use]
pub mod partial_knowledge;
pub mod sponge;
pub mod transforms;
