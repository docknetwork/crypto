//! Universal dynamic accumulator defined in section 6, Fig 3 of the paper [Efficient Constructions of Pairing Based Accumulators](https://eprint.iacr.org/2021/638)

pub mod accumulator;
pub mod proofs;
pub mod proofs_cdh;
pub mod proofs_keyed_verification;
pub mod witness;

pub use accumulator::KBUniversalAccumulator;
