//! Verifiable encryption of discrete log(s) from the paper [Verifiable Encryption from MPC-in-the-Head](https://eprint.iacr.org/2021/1704.pdf)
//! Implements the following 2 schemes from the paper
//!
//! 1. DKG in the head, described in Protocol 4
//! 2. Robust DKG in the head, described in Protocol 5
//!
//! Started of from [this](https://github.com/akiratk0355/verenc-mpcith/tree/main/dkgith/src) reference implementation in the paper
//!
//! Both are generalized such that the encryption is of not just a single discrete log but multiple witnesses,
//! thus allowing to encrypt messages of a generalized Pedersen commitment. eg. given a generalized Pedersen
//! commitment `Y = G_1 * x_1 + G_2 * x_2 + ... G_n * x_n`, prover encrypts `x_1, x_2, ..., x_n` while
//! proving that those are opening of the commitment `Y`.
//!
//! For both schemes, a variation is included where multiple witnesses are encrypted using a more efficient
//! version of Elgamal encryption, called batched-Elgamal where a single shared secret is generated when
//! encrypting multiple messages and that shared secret is combined with a counter to generate a unique OTP
//! for each message.
//!
//! More docs in the corresponding modules.

#[macro_use]
pub mod util;

pub mod dkgith;
pub mod dkgith_batched_elgamal;
pub mod rdkgith;
pub mod rdkgith_batched_elgamal;
pub mod seed_tree;
