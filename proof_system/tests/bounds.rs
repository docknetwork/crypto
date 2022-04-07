use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{rand::prelude::StdRng, rand::SeedableRng, UniformRand};

use proof_system::prelude::bound_check::generate_snark_srs_bound_check;
