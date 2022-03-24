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
//! non-membership, and Pedersen commitment opening. The tests show how to create a proof that combines
//! several proofs of knowledge.
//! BBS+ signature and prove equality between the messages and also proof that combines proof of knowledge of
//! BBS+ signature, accumulator membership, accumulator non-membership, and Pedersen commitment opening.
//! See following tests for examples:
//!
//! - test `pok_of_3_bbs_plus_sig_and_message_equality` proves knowledge of 3 BBS+ signatures and also that certain
//!   messages are equal among them without revealing them.
//! - test `pok_of_bbs_plus_sig_and_accumulator` proves knowledge of a BBS+ signature and also that certain messages
//!   are present and absent in the 2 accumulators respectively.
//! - test `pok_of_knowledge_in_pedersen_commitment_and_BBS_plus_sig` proves knowledge of a BBS+ signature and opening
//!   of a Pedersen commitment.
//! - test `requesting_partially_blind_BBS_plus_sig` shows how to request a blind BBS+ signature by proving opening of
//!   a Pedersen commitment.
//! - test `verifier_local_linkability` shows how a verifier can link separate proofs from a prover (with prover's
//!   permission) and assign a unique identifier to the prover without learning any message from the BBS+ signature.
//!   Also this identifier cannot be linked across different verifiers (intentional by the prover).  
//!
//! *Note*: This design is largely inspired from my work at Hyperledger Ursa.
//!
//! *Note*: The design is tentative and will likely change as more protocols are integrated.
//!
//! [`Statement`]: crate::statement::Statement
//! [`MetaStatement`]: crate::meta_statement::MetaStatement
//! [`ProofSpec`]: crate::proof_spec::ProofSpec
//! [`Witness`]: crate::witness::Witness
//! [`StatementProof`]: crate::statement_proof::StatementProof
//! [`Proof`]: crate::proof::Proof
//! [`SubProtocol`]: crate::sub_protocols::SubProtocol

#[macro_use]
pub mod util;
pub mod error;
pub mod meta_statement;
pub mod proof;
pub mod proof_spec;
pub mod statement;
pub mod statement_proof;
pub mod sub_protocols;
pub mod witness;

#[cfg(test)]
#[macro_use]
pub mod test_utils;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bound;
#[cfg(test)]
mod tests_saver;

pub mod prelude {
    pub use crate::error::ProofSystemError;
    pub use crate::meta_statement::*;
    pub use crate::proof::*;
    pub use crate::proof_spec::*;
    pub use crate::statement::*;
    pub use crate::statement_proof::*;
    pub use crate::sub_protocols::*;
    pub use crate::witness::*;
}
