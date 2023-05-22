#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

pub mod error;

pub mod base_ot;
pub mod ot_based_multiplication;
pub mod ot_extensions;

pub mod configs;

mod aes_prng;
pub mod util;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

pub type Key = Vec<u8>;
pub type Bit = bool;
pub type Message = Vec<u8>;

/// A bit matrix stored in row-major order
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BitMatrix(pub Vec<u8>);

pub type ParticipantId = u16;
