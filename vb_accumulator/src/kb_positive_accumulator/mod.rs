//! A dynamic positive accumulator based on construction 2, Fig. 2 in the paper [Efficient Constructions of Pairing Based Accumulators](https://eprint.iacr.org/2021/638)

pub mod adaptive_accumulator;
pub mod non_adaptive_accumulator;
// pub mod proofs;
pub mod witness;

pub mod proofs;
pub mod proofs_cdh;
pub mod setup;

pub use adaptive_accumulator::KBPositiveAccumulator;
