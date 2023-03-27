pub mod proof;
pub mod prover;
pub mod using_groth16;
pub mod verifier;

pub use proof::AggregateLegoProof;
pub use prover::aggregate_proofs;
pub use verifier::verify_aggregate_proof;
