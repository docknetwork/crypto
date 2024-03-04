use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use legogroth16::{
    aggregation::srs,
    circom::{CircomCircuit, R1CS},
};
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, SetupParams, SnarkpackSRS,
        Statements, VerifierConfig, Witness, WitnessRef, Witnesses,
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
use std::collections::{BTreeMap, BTreeSet};

use crate::r1cs::abs_path;
use test_utils::bbs::*;

#[test]
fn pok_of_bbs_plus_sig_and_multiple_set_membership_proofs_aggregated() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 20;
    let (msgs, sig_params, sig_keypair, sig) = bbs_plus_sig_setup(&mut rng, msg_count);

    // A public set which will not contain any of the signed messages
    let mut public_set = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    // These messages' membership/non-membership will be checked
    let member_idxs = vec![0, 2];
    let non_member_idxs = vec![11, 12, 13, 14, 15, 16];

    for i in member_idxs.iter() {
        public_set[*i] = msgs[*i];
    }

    let commit_witness_count = 1;
    // Circom code for following in tests/r1cs/circom/circuits/set_membership_5_public.circom
    let r1cs_file_path = "tests/r1cs/circom/bls12-381/set_membership_5_public.r1cs";
    let wasm_file_path = "tests/r1cs/circom/bls12-381/set_membership_5_public.wasm";
    let circuit = CircomCircuit::<Bls12_381>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();
    let snark_pk = circuit
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    let r1cs = R1CS::from_file(abs_path(r1cs_file_path)).unwrap();
    let wasm_bytes = std::fs::read(abs_path(wasm_file_path)).unwrap();

    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, 100);
    let (prover_srs, ver_srs) = srs.specialize((member_idxs.len() + non_member_idxs.len()) as u32);

    let mut prover_setup_params = vec![];
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk.clone()));
    prover_setup_params.push(SetupParams::R1CS(r1cs));
    prover_setup_params.push(SetupParams::Bytes(wasm_bytes));

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..member_idxs.len() + non_member_idxs.len() {
        stmts_to_aggr.insert(
            prover_statements.add(R1CSProverStmt::new_statement_from_params_ref(1, 2, 0).unwrap()),
        );
    }

    let mut meta_statements = MetaStatements::new();
    for i in 0..member_idxs.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, member_idxs[i]), (1 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }
    for i in 0..non_member_idxs.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, non_member_idxs[i]), (1 + member_idxs.len() + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }

    let proof_spec_prover = ProofSpec::new_with_aggregation(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
        None,
        Some(vec![stmts_to_aggr]),
        Some(SnarkpackSRS::ProverSrs(prover_srs)),
    );
    proof_spec_prover.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));

    for i in 0..member_idxs.len() {
        let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
        r1cs_wit.set_private("x".to_string(), vec![msgs[member_idxs[i]]]);
        r1cs_wit.set_public("set".to_string(), public_set.clone());
        witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));
    }

    for i in 0..non_member_idxs.len() {
        let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
        r1cs_wit.set_private("x".to_string(), vec![msgs[non_member_idxs[i]]]);
        r1cs_wit.set_public("set".to_string(), public_set.clone());
        witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));
    }

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    // The 1st public input will be 1 indicating that the message is present in the set
    let mut public_inputs_mem = vec![Fr::one()];
    public_inputs_mem.extend(&public_set);

    // The 1st public input will be 0 indicating that the message is not present in the set
    let mut public_inputs_non_mem = vec![Fr::zero()];
    public_inputs_non_mem.extend(&public_set);

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk.vk));
    verifier_setup_params.push(SetupParams::FieldElemVec(public_inputs_mem));
    verifier_setup_params.push(SetupParams::FieldElemVec(public_inputs_non_mem));

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params,
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..member_idxs.len() {
        stmts_to_aggr.insert(
            verifier_statements.add(R1CSVerifierStmt::new_statement_from_params_ref(1, 0).unwrap()),
        );
    }
    for _ in 0..non_member_idxs.len() {
        stmts_to_aggr.insert(
            verifier_statements.add(R1CSVerifierStmt::new_statement_from_params_ref(2, 0).unwrap()),
        );
    }

    let verifier_proof_spec = ProofSpec::new_with_aggregation(
        verifier_statements.clone(),
        meta_statements.clone(),
        verifier_setup_params,
        None,
        None,
        Some(vec![stmts_to_aggr]),
        Some(SnarkpackSRS::VerifierSrs(ver_srs)),
    );
    verifier_proof_spec.validate().unwrap();

    let updated_proof = proof.for_aggregate();

    updated_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: None,
            },
        )
        .unwrap();

    updated_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(true),
            },
        )
        .unwrap();

    updated_proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec,
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
}
