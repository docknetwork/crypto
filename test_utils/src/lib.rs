use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::PairingEngine;
use blake2::Blake2b;
use proof_system::proof::Proof;

pub type Fr = <Bls12_381 as PairingEngine>::Fr;
pub type G1 = <Bls12_381 as PairingEngine>::G1Affine;
pub type ProofG1 = Proof<Bls12_381, G1Affine, Blake2b>;

pub mod accumulators;
pub mod bbs_plus;
#[macro_use]
pub mod serialization;
