#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! # Short group signatures
//!
//! 1. BB and Weak-BB signatures and proof of knowledge of weak-BB signature as described in the paper [Short Signatures Without Random Oracles](https://eprint.iacr.org/2004/171)
//! 2. Proof of knowledge of BB signature adapted from the paper [Proof-of-Knowledge of Representation of Committed Value and Its Applications](https://link.springer.com/chapter/10.1007/978-3-642-14081-5_22)
//! 3. An optimized implementation of proof of knowledge of weak-BB signature taken from the paper [Scalable Revocation Scheme for Anonymous Credentials Based on n-times Unlinkable Proofs](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf). This does not require the prover to do pairings
//! 4. Similar to weak-BB, proof of knowledge of BB signature that does not require the prover to do pairings.
//! 5. A keyed-verification protocol for proving knowledge of weak-BB signature. Here the verifier is assumed to have the secret key and the protocol does not require pairings.

extern crate alloc;

pub mod bb_sig;
pub mod bb_sig_pok;
pub mod bb_sig_pok_cdh;
pub mod common;
pub mod error;
pub mod weak_bb_sig;
pub mod weak_bb_sig_pok;
pub mod weak_bb_sig_pok_cdh;
pub mod weak_bb_sig_pok_kv;
