use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Zero;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use legogroth16::circom::{CircomCircuit, R1CS};
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, Statements, Witness,
        WitnessRef, Witnesses,
    },
    proof::Proof,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        r1cs_legogroth16::{
            R1CSCircomProver as R1CSProverStmt, R1CSCircomVerifier as R1CSVerifierStmt,
        },
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use crate::r1cs::abs_path;
use test_utils::bbs::*;

#[test]
fn pok_of_bbs_plus_sig_and_knowledge_of_hash_preimage() {
    // Prove knowledge of a signature and that a specific signed message's MiMC hash equals a public value

    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 5;
    let mut msgs: Vec<Fr> = (0..msg_count - 1).map(|_| Fr::rand(&mut rng)).collect();
    msgs.push(Fr::from(105u64));

    // Message index that will be hashed
    let msg_idx_to_hash = msg_count - 2;

    let (sig_params, sig_keypair, sig) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs);

    let commit_witness_count = 1;
    // Circom code for following in tests/r1cs/circom/circuits/mimc_hash.circom
    let r1cs_file_path = "tests/r1cs/circom/bls12-381/mimc_hash_bls12_381.r1cs";
    let wasm_file_path = "tests/r1cs/circom/bls12-381/mimc_hash_bls12_381.wasm";
    let start = Instant::now();
    let circuit = CircomCircuit::<Bls12_381>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();
    println!(
        "Creating MiMC circuit from R1CS takes {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    let snark_pk = circuit
        .clone()
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();
    println!(
        "Creating proving key for MiMC circuit takes {:?}",
        start.elapsed()
    );

    let r1cs = R1CS::from_file(abs_path(r1cs_file_path)).unwrap();
    let wasm_bytes = std::fs::read(abs_path(wasm_file_path)).unwrap();

    // This is arbitrary
    let k = Fr::zero();

    // Output of MiMC hash. This should have been created by implementing the MiMC hash here
    let image = {
        use legogroth16::circom::WitnessCalculator;
        let mut wits_calc = WitnessCalculator::<Bls12_381>::from_wasm_bytes(&wasm_bytes).unwrap();
        let mut circ = circuit;
        circ.set_wires_using_witness_calculator(
            &mut wits_calc,
            [
                (String::from("in"), vec![msgs[msg_idx_to_hash]]),
                (String::from("k"), vec![Fr::zero()]),
            ]
            .into_iter(),
            false,
        )
        .unwrap();
        circ.get_public_inputs().unwrap()[0]
    };

    let start = Instant::now();
    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        R1CSProverStmt::new_statement_from_params(r1cs, wasm_bytes, snark_pk.clone()).unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_idx_to_hash), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("in".to_string(), vec![msgs[msg_idx_to_hash]]);
    r1cs_wit.set_private("k".to_string(), vec![k]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;
    println!(
        "Creating proof for MiMC circuit takes {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(vec![image], snark_pk.vk.clone()).unwrap(),
    );
    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
        .unwrap();
    println!(
        "Verifying proof for MiMC circuit takes {:?}",
        start.elapsed()
    );

    // Proof with wrong public input fails
    let mut verifier_statements_1 = Statements::new();
    verifier_statements_1.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params,
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements_1.add(
        R1CSVerifierStmt::new_statement_from_params(vec![Fr::rand(&mut rng)], snark_pk.vk).unwrap(),
    );
    let verifier_proof_spec_1 = ProofSpec::new(
        verifier_statements_1.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec_1.validate().unwrap();
    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec_1, None, Default::default())
        .is_err());
}
