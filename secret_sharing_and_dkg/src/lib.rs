#![cfg_attr(not(feature = "std"), no_std)]

//! # Secret sharing and distributed key generation
//!
//! Implements Secret Sharing (SS), Verifiable Secret Sharing (VSS), Distributed Verifiable Secret Sharing (DVSS), Distributed
//! Key Generation (DKG) and Publicly Verifiable Secret Sharing (PVSS) algorithms. DVSS and DKG do not require a trusted dealer.
//! Also implements a distributed discrete log check.
//!
//!
//! 1. [Shamir secret sharing (Requires a trusted dealer)](./src/shamir_ss.rs)
//! 1. [Pedersen Verifiable Secret Sharing](./src/pedersen_vss.rs)
//! 1. [Pedersen Distributed Verifiable Secret Sharing](./src/pedersen_dvss.rs)
//! 1. [Feldman Verifiable Secret Sharing](./src/feldman_vss.rs)
//! 1. [Feldman Distributed Verifiable Secret Sharing](./src/feldman_dvss_dkg.rs)
//! 1. [Gennaro DKG from the paper Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](./src/gennaro_dkg.rs)
//! 1. [Distributed Key Generation from FROST](./src/frost_dkg.rs)
//! 1. [Distributed discrete log (DLOG) check](./src/distributed_dlog_check)
//! 1. [Publicly Verifiable Secret Sharing](./src/baghery_pvss)
//!

pub mod abcp_dkg;
pub mod baghery_feldman_vss;
pub mod baghery_pvss;
pub mod common;
pub mod distributed_dlog_check;
pub mod error;
pub mod feldman_dvss_dkg;
pub mod feldman_vss;
pub mod frost_dkg;
pub mod gennaro_dkg;
pub mod pedersen_dvss;
pub mod pedersen_vss;
pub mod shamir_ss;
