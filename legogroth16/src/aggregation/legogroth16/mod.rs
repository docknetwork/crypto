pub mod proof;
pub mod prover;
pub mod using_groth16;
pub mod verifier;

pub use {proof::AggregateLegoProof, prover::aggregate_proofs, verifier::verify_aggregate_proof};
