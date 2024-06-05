//! A collection of utilities used by our other crypto libraries. Some examples are Pedersen commitment,
//! Elgamal encryption, some finite field utilities like inner product, weighted inner product, hadamard product,
//! etc, multiscalar multiplication (MSM) like Fixed Base MSM, polynomial utilities like multiplying polynomials,
//! creating polynomial from roots, etc, efficient way of checking several pairing relations in a single multi-pairing.
//!

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

pub mod aliases;
pub mod extend_some;
// TODO: Feature gate this
#[macro_use]
pub mod serde_utils;
pub mod ecies;

/// Elgamal encryption
pub mod elgamal;

/// Finite field utilities like inner product, weighted inner product, hadamard product, etc
#[macro_use]
pub mod ff;

/// Pedersen commitment
pub mod commitment;

/// Hashing utilities like hashing arbitrary bytes to field element or group element
pub mod hashing_utils;
pub mod iter;
pub mod macros;
pub mod misc;
/// Multiscalar multiplication (MSM) like Fixed Base MSM
pub mod msm;
pub mod owned_pairs;
pub mod pairs;
/// Polynomial utilities like multiplying polynomials, creating polynomial from roots, etc
pub mod poly;
/// An efficient way to check several equality relations involving pairings by combining the relations
/// in a random linear combination and doing a multi-pairing check. Relies on Schwartz–Zippel lemma.
pub mod randomized_pairing_check;
pub mod signature;
/// Solving discrete log using Baby Step Giant Step
pub mod solve_discrete_log;
pub mod transcript;
pub mod try_iter;
