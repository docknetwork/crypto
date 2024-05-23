use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;
pub type G1 = <Bls12_381 as Pairing>::G1Affine;
pub type G2 = <Bls12_381 as Pairing>::G2Affine;

pub mod accumulators;
pub mod bbs;
#[macro_use]
pub mod serialization;
pub mod kvac;
pub mod ot;
