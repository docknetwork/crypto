#![cfg_attr(not(feature = "std"), no_std)]

//! The goal of this crate is to allow creating and combining zero knowledge proofs by executing several
//! protocols as sub-protocols.
//! The idea is to represent each relation to be proved as a [`Statement`], and any relations between
//! [`Statement`]s as a [`MetaStatement`]. Both of these types contain public (known to both prover
//! and verifier) information and are contained in a [`ProofSpec`] whose goal is to unambiguously
//! define what needs to be proven. Some [`Statement`]s are specific to either the prover or the verifier
//! as those protocols require prover and verifier to use different public parameters. An example is Groth16
//! based SNARK protocols where the prover needs to have a proving key and the verifier needs to
//! have a verifying key. Both the prover and verifier can know both the proving and verifying key but
//! they don't need to. Thus for such protocols, there are different [`Statement`]s for prover and verifier,
//! like [`SaverProver`] and [`SaverVerifier`] are statements for prover and verifier respectively,
//! executing SAVER protocol.
//! Several [`Statement`]s might need same public parameters like proving knowledge of several BBS+
//! from the same signer, or verifiable encryption of several messages for the same decryptor. Its not
//! very efficient to pass the same parameters to each [`Statement`] especially when using this code's WASM
//! bindings as the same values will be serialized and deserialized every time. To avoid this, caller can
//! put all such public parameters as [`SetupParams`] in an array and then reference those by their index
//! while creating an [`Statement`]. This array of [`SetupParams`] is then included in the [`ProofSpec`]
//! and used by the prover and verifier during proof creation and verification respectively.
//!
//! After creating the [`ProofSpec`], the prover uses a [`Witness`] per [`Statement`] and creates a
//! corresponding [`StatementProof`]. All [`StatementProof`]s are grouped together in a [`Proof`].
//! The verifier also creates its [`ProofSpec`] and uses it to verify the given proof. Currently it is
//! assumed that there is one [`StatementProof`] per [`Statement`] and one [`Witness`] per [`Statement`]
//! and [`StatementProof`]s appear in the same order in [`Proof`] as [`Statement`]s do in [`ProofSpec`].
//!
//! [`Statement`], [`Witness`] and [`StatementProof`] are enums whose variants will be entities from different
//! protocols. Each of these protocols are variants of the enum [`SubProtocol`]. [`SubProtocol`]s can internally
//! call other [`SubProtocol`]s, eg [`SaverProtocol`] invokes several [`SchnorrProtocol`]s
//!
//! Currently supports
//! - proof of knowledge of a BBS+ signature and signed messages
//! - proof of knowledge of multiple BBS+ signature and equality of certain messages
//! - proof of knowledge of accumulator membership and non-membership
//! - proof of knowledge of Pedersen commitment opening.
//! - proof of knowledge of a BBS+ signature and certain message satisfies given bounds (range proof)
//! - verifiable encryption of messages in a BBS+ signature
//!
//! See following tests for examples:
//!
//! - test `pok_of_3_bbs_plus_sig_and_message_equality` proves knowledge of 3 BBS+ signatures and also that certain
//!   messages are equal among them without revealing them.
//! - test `pok_of_bbs_plus_sig_and_accumulator` proves knowledge of a BBS+ signature and also that certain messages
//!   are present and absent in the 2 accumulators respectively.
//! - test `pok_of_knowledge_in_pedersen_commitment_and_bbs_plus_sig` proves knowledge of a BBS+ signature and opening
//!   of a Pedersen commitment.
//! - test `requesting_partially_blind_bbs_plus_sig` shows how to request a blind BBS+ signature by proving opening of
//!   a Pedersen commitment.
//! - test `verifier_local_linkability` shows how a verifier can link separate proofs from a prover (with prover's
//!   permission) and assign a unique identifier to the prover without learning any message from the BBS+ signature.
//!   Also this identifier cannot be linked across different verifiers (intentional by the prover).
//! - test `pok_of_bbs_plus_sig_and_bounded_message` shows proving knowledge of a BBS+ signature and that a specific
//!   message satisfies some upper and lower bounds i.e. min <= signed message <= max. This is a range proof.
//! - test `pok_of_bbs_plus_sig_and_verifiable_encryption` shows how to verifiably encrypt a message signed with BBS+ such
//!   that the verifier cannot decrypt it but still ensure that it is encrypted correctly for the specified decryptor.
//! - test `pok_of_bbs_plus_sig_with_reusing_setup_params` shows proving knowledge of several BBS+ signatures
//!   using [`SetupParams`]s. Here the same signers are used in multiple signatures thus their public params
//!   can be put as a variant of enum [`SetupParams`]. Similarly test
//!   `pok_of_knowledge_in_pedersen_commitment_and_equality_with_commitment_key_reuse` shows use of [`SetupParams`]
//!   when the same commitment key is reused in several commitments and test `pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages`
//!   shows use of [`SetupParams`] when several messages are used in verifiable encryption for the same decryptor.
//!
//! *Note*: This design is largely inspired from my work at Hyperledger Ursa.
//!
//! *Note*: The design is tentative and will likely change as more protocols are integrated.
//!
//! [`Statement`]: crate::statement::Statement
//! [`MetaStatement`]: crate::meta_statement::MetaStatement
//! [`SaverProver`]: crate::statement::saver::SaverProver
//! [`SaverVerifier`]: crate::statement::saver::SaverVerifier
//! [`SetupParams`]: crate::setup_params::SetupParams
//! [`ProofSpec`]: crate::proof_spec::ProofSpec
//! [`Witness`]: crate::witness::Witness
//! [`StatementProof`]: crate::statement_proof::StatementProof
//! [`Proof`]: crate::proof::Proof
//! [`SubProtocol`]: crate::sub_protocols::SubProtocol
//! [`SaverProtocol`]: crate::sub_protocols::saver::SaverProtocol
//! [`SchnorrProtocol`]: crate::sub_protocols::schnorr::SchnorrProtocol

extern crate core;

#[macro_use]
pub mod util;
#[macro_use]
pub mod setup_params;
mod derived_params;
pub mod error;
pub mod meta_statement;
pub mod proof;
pub mod proof_spec;
pub mod statement;
pub mod statement_proof;
pub mod sub_protocols;
pub mod witness;

pub mod prelude {
    pub use crate::error::ProofSystemError;
    pub use crate::meta_statement::*;
    pub use crate::proof::*;
    pub use crate::proof_spec::*;
    pub use crate::setup_params::*;
    pub use crate::statement::*;
    pub use crate::statement_proof::*;
    pub use crate::sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check;
    pub use crate::witness::*;
}
