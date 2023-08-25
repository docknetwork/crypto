use ark_bls12_381::Bls12_381;
use ark_std::rand::RngCore;
use legogroth16::{
    circom::{CircomCircuit, R1CS},
    ProvingKey,
};
use std::path::PathBuf;

pub mod bounded_sum;
pub mod mimc_hash;
pub mod multiple_circuits_in_single_proof;
pub mod proof_aggregation;
pub mod set_membership;
pub mod single_circuit_in_a_proof;

/// Given path relative to this crate, return absolute disk path
pub fn abs_path(relative_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative_path);
    path.to_string_lossy().to_string()
}

pub fn get_r1cs_and_wasm_bytes<R: RngCore>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    rng: &mut R,
) -> (ProvingKey<Bls12_381>, R1CS<Bls12_381>, Vec<u8>) {
    let circuit = CircomCircuit::<Bls12_381>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();
    let snark_pk = circuit
        .generate_proving_key(commit_witness_count, rng)
        .unwrap();

    let r1cs = R1CS::from_file(abs_path(r1cs_file_path)).unwrap();
    let wasm_bytes = std::fs::read(abs_path(wasm_file_path)).unwrap();
    (snark_pk, r1cs, wasm_bytes)
}
