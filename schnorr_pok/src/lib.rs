#![cfg_attr(not(feature = "std"), no_std)]

//! The crate's name is `schnorr_pok`, but it implements several Sigma protocols.
//!
//! Proof of knowledge of a discrete log using Schnorr protocol and similar proof of knowledge for the
//! opening of a Pedersen commitment in [`discrete_log`].
//!
//! Protocol for proving knowledge of opening of a generalized Pedersen commitment (`C = G * a + H * b + J * c + ...`) in [`pok_generalized_pedersen`]
//!
//! Proof of knowledge of discrete log in pairing groups, i.e. given prover and verifier
//! both know (`A1`, `Y1`), and prover additionally knows `B1`, prove that `e(A1, B1) = Y1`. Similarly,
//! proving `e(A2, B2) = Y2` when only prover knows `A2` but both know (`B2`, `Y2`). See [`discrete_log_pairing`].
//!
//! Proof of **inequality of discrete log** (a value committed in a Pedersen commitment),
//! either with a public value or with another discrete log in [`Inequality`]. eg. Given a message `m`,
//! its commitment `C = G * m + H * r` and a public value `v`, proving that `m` ≠ `v`. Or given 2 messages
//! `m1` and `m2` and their commitments `C1 = G * m1 + H * r1` and `C2 = G * m2 + H * r2`, proving `m1` ≠ `m2`
//!
//! Also implements the proof of **inequality of discrete log** when only one of the discrete log is known to
//! the prover in [`Inequality`]. i.e. given `Y = G * x` and `Z = H * k`, prover and verifier know `G`, `H`, `Y` and `Z` and
//! prover additionally knows `x` but not `k`.
//!
//!
//! Following sigma protocols are for product, square and inverse of a discrete log in [`Product`]:
//! - Proving product relation among values committed in a Pedersen commitment
//! - Proving square relation among values committed in a Pedersen commitment
//! - Proving inverse relation among values committed in a Pedersen commitment
//!
//! Also implements partial Schnorr proof where response for some witnesses is not generated. This is useful
//! when several Schnorr protocols are executed together, and they share some witnesses. The response for the common
//! witnesses will be generated in one Schnorr proof while the other protocols will generate partial Schnorr
//! proofs where responses for common witnesses will be missing. This means that duplicate Schnorr responses
//! for the common witnesses are not generated.
//!
//! In all the protocols, the prover follows the pattern of `init`, `challenge_contribution` and `gen_proof` which correspond to the
//! 3 steps of the Sigma protocol with the verifier challenge generated with Fiat-Shamir. `challenge_contribution` adds that protocol's
//! generated public commitments to the transcript. The verifier also has its own `challenge_contribution` to add the public commitments
//! to the transcript.
//!
//! More documentation for each protocol is in their corresponding module.
//!
//! [`discrete_log`]: crate::discrete_log
//! [`pok_generalized_pedersen`]: crate::pok_generalized_pedersen
//! [`discrete_log_pairing`]: crate::discrete_log_pairing
//! [`Inequality`]: crate::inequality
//! [`Product`]: crate::mult_relations

pub mod discrete_log;
pub mod discrete_log_pairing;
pub mod error;
pub mod inequality;
pub mod mult_relations;
pub mod partial;
pub mod pok_generalized_pedersen;

pub use pok_generalized_pedersen::{
    compute_random_oracle_challenge, SchnorrChallengeContributor, SchnorrCommitment,
    SchnorrResponse,
};
