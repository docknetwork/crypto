#![cfg_attr(not(feature = "std"), no_std)]

//! The goal of this crate is to allow creating and combining zero knowledge proofs by executing several
//! protocols as sub-protocols.
//! The idea is to represent each relation to be proved as a [`Statement`], and any relations between
//! [`Statement`]s as a [`MetaStatement`]. Both of these types contain public (known to both prover
//! and verifier) information and are contained in a [`ProofSpec`] whose goal is to unambiguously
//! define what needs to be proven. The prover then uses a [`Witness`] per [`Statement`] and creates a
//! [`StatementProof`] per [`Statement`]. All [`StatementProof`]s are grouped together in a [`Proof`]
//! and the verifier then uses the [`ProofSpec`] and [`Proof`] to verify the proof. Currently it is
//! assumed that there is one [`StatementProof`] per [`Statement`] and one [`Witness`] per [`Statement`]
//! and [`StatementProof`]s appear in the same order in [`Proof`] as [`Statement`]s do in [`ProofSpec`].
//! [`Statement`], [`Witness`] and [`StatementProof`] are enums whose variants will be entities from different
//! protocols. Each of these protocols are variants of the enum [`SubProtocol`].
//! Currently supports proof of knowledge of BBS+ signature, accumulator membership, accumulator
//! non-membership, and Pedersen commitment pre-image. The tests show how to create a proof that combines
//! several proofs of knowledge.
//! BBS+ signature and prove equality between the messages and also proof that combines proof of knowledge of
//! BBS+ signature, accumulator membership,accumulator non-membership, and Pedersend commitment pre-image.
//! See tests for examples.
//!
//!
//! *Note*: This design is largely inspired from my work at Hyperledger Ursa.
//!
//! *Note*: The design is tentative and will likely change as more protocols are integrated.
//!
//! [`Statement`]: crate::statement::Statement
//! [`MetaStatement`]: crate::statement::MetaStatement
//! [`ProofSpec`]: crate::proof::ProofSpec
//! [`Witness`]: crate::witness::Witness
//! [`StatementProof`]: crate::proof::StatementProof
//! [`Proof`]: crate::proof::Proof
//! [`SubProtocol`]: crate::sub_protocols::SubProtocol

#[macro_use]
pub mod util;
pub mod error;
pub mod proof;
pub mod statement;
pub mod sub_protocols;
pub mod witness;
#[cfg(test)]
#[macro_use]
mod test_utils;

pub mod prelude {
    pub use crate::error::ProofSystemError;
    pub use crate::proof::*;
    pub use crate::statement::*;
    pub use crate::sub_protocols::*;
    pub use crate::witness::*;
}
