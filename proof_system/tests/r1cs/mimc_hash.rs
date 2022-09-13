use ark_bls12_381::Bls12_381;
use ark_ff::Zero;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use legogroth16::circom::{CircomCircuit, R1CS};
use proof_system::prelude::{
    EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, Statements, Witness, WitnessRef,
    Witnesses,
};
use proof_system::statement::{
    bbs_plus::PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    r1cs_legogroth16::{
        R1CSCircomProver as R1CSProverStmt, R1CSCircomVerifier as R1CSVerifierStmt,
    },
};
use proof_system::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use std::collections::{BTreeMap, BTreeSet};

use crate::r1cs::abs_path;
use test_utils::bbs_plus::*;
use test_utils::{Fr, ProofG1};

#[test]
fn pok_of_bbs_plus_sig_and_knowledge_of_attribute_hash_preimage() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 5;
    let mut msgs: Vec<Fr> = (0..msg_count - 1)
        .into_iter()
        .map(|_| Fr::rand(&mut rng))
        .collect();
    msgs.push(Fr::from(105u64));

    let msg_idx_to_hash = msg_count - 1;

    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    let commit_witness_count = 1;
    // Circom code for following in tests/r1cs/circom/mimc_hash.circom
    let r1cs_file_path = "tests/r1cs/circom/mimc_hash_bls12_381.r1cs";
    let wasm_file_path = "tests/r1cs/circom/mimc_hash_bls12_381.wasm";
    let circuit = CircomCircuit::<Bls12_381>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();
    let snark_pk = circuit
        .clone()
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    let r1cs = R1CS::from_file(abs_path(r1cs_file_path)).unwrap();
    let wasm_bytes = std::fs::read(abs_path(wasm_file_path)).unwrap();

    let k = Fr::zero();

    // Output of MiMC hash. This should have been created by implementing the MiMC hash here
    let image = {
        use legogroth16::circom::WitnessCalculator;
        let mut wits_calc = WitnessCalculator::<Bls12_381>::from_wasm_bytes(&wasm_bytes).unwrap();
        let mut circ = circuit.clone();
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

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        R1CSProverStmt::new_statement_from_params(
            r1cs.clone(),
            wasm_bytes.clone(),
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_count - 1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    assert!(proof_spec_prover.is_valid());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("in".to_string(), vec![msgs[msg_count - 1]]);
    r1cs_wit.set_private("k".to_string(), vec![k]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    let proof = ProofG1::new(&mut rng, proof_spec_prover.clone(), witnesses.clone(), None).unwrap();

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
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
    assert!(verifier_proof_spec.is_valid());
    proof
        .clone()
        .verify(verifier_proof_spec.clone(), None)
        .unwrap();

    // Proof with wrong public input fails
    let mut verifier_statements_1 = Statements::new();
    verifier_statements_1.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements_1.add(
        R1CSVerifierStmt::new_statement_from_params(vec![Fr::rand(&mut rng)], snark_pk.vk.clone())
            .unwrap(),
    );
    let verifier_proof_spec_1 = ProofSpec::new(
        verifier_statements_1.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    assert!(verifier_proof_spec_1.is_valid());
    assert!(proof.verify(verifier_proof_spec_1.clone(), None).is_err());
}
