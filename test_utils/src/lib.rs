use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use proof_system::proof::Proof;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;
pub type G1 = <Bls12_381 as Pairing>::G1Affine;
pub type ProofG1 = Proof<Bls12_381, G1Affine>;

pub mod accumulators;
pub mod bbs_plus;
#[macro_use]
pub mod serialization;
