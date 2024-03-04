use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, SetupParams, Statements,
        Witness, WitnessRef, Witnesses,
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

use crate::r1cs::get_r1cs_and_wasm_bytes;
use test_utils::{bbs::*, test_serialization};

#[test]
fn pok_of_bbs_plus_sig_and_attribute_less_than_check_with_private_and_public_values() {
    // Prove knowledge of 2 BBS+ signatures and less than relation between several of their signed messages.
    // Uses 2 circuits, one where less than relation is proved with both operands hidden and the other
    // where one of the operand is public.

    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 5;
    let mut msgs_1: Vec<Fr> = (0..msg_count_1).map(|_| Fr::rand(&mut rng)).collect();
    msgs_1[1] = Fr::from(100u64);
    msgs_1[3] = Fr::from(300u64);
    let (sig_params_1, sig_keypair_1, sig_1) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let msgs_2: Vec<Fr> = (0..msg_count_2)
        .map(|_| Fr::from(u64::MAX - u64::rand(&mut rng)))
        .collect();
    let (sig_params_2, sig_keypair_2, sig_2) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_2);

    let commit_witness_count_1 = 2;
    // Circom code for following in tests/r1cs/circom/circuits/less_than_32.circom
    let (snark_pk_1, r1cs_1, wasm_bytes_1) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/less_than_32.r1cs",
        "tests/r1cs/circom/bls12-381/less_than_32.wasm",
        commit_witness_count_1,
        &mut rng,
    );

    let commit_witness_count_2 = 1;
    // Circom code for following in tests/r1cs/circom/circuits/less_than_public_64.circom
    let (snark_pk_2, r1cs_2, wasm_bytes_2) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/less_than_public_64.r1cs",
        "tests/r1cs/circom/bls12-381/less_than_public_64.wasm",
        commit_witness_count_2,
        &mut rng,
    );

    let mut prover_setup_params = vec![];
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk_1.clone()));
    prover_setup_params.push(SetupParams::R1CS(r1cs_1));
    prover_setup_params.push(SetupParams::Bytes(wasm_bytes_1));
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk_2.clone()));
    prover_setup_params.push(SetupParams::R1CS(r1cs_2));
    prover_setup_params.push(SetupParams::Bytes(wasm_bytes_2));

    test_serialization!(Vec<SetupParams<Bls12_381>>, prover_setup_params);

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params_1.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params_2.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(R1CSProverStmt::new_statement_from_params_ref(1, 2, 0).unwrap());
    for _ in 0..msg_count_2 {
        prover_statements.add(R1CSProverStmt::new_statement_from_params_ref(4, 5, 3).unwrap());
    }

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 3), (2, 1)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    for i in 0..msg_count_2 {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(1, i), (3 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
    );
    proof_spec_prover.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1,
        msgs_1.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2,
        msgs_2.clone().into_iter().enumerate().collect(),
    ));

    let mut r1cs_wit = R1CSCircomWitness::new();
    r1cs_wit.set_private("a".to_string(), vec![msgs_1[1]]);
    r1cs_wit.set_private("b".to_string(), vec![msgs_1[3]]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    for i in 0..msg_count_2 {
        let mut r1cs_wit = R1CSCircomWitness::new();
        r1cs_wit.set_private("a".to_string(), vec![msgs_2[i]]);
        r1cs_wit.set_private("b".to_string(), vec![Fr::from(u64::MAX)]);
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

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk_1.vk));
    verifier_setup_params.push(SetupParams::FieldElemVec(vec![Fr::one()]));
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk_2.vk));
    verifier_setup_params.push(SetupParams::FieldElemVec(vec![
        Fr::one(),
        Fr::from(u64::MAX),
    ]));
    test_serialization!(Vec<SetupParams<Bls12_381>>, verifier_setup_params);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_1,
        sig_keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_2,
        sig_keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    verifier_statements.add(R1CSVerifierStmt::new_statement_from_params_ref(1, 0).unwrap());

    for _ in 0..msg_count_2 {
        verifier_statements.add(R1CSVerifierStmt::new_statement_from_params_ref(3, 2).unwrap());
    }

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        verifier_setup_params,
        None,
    );
    verifier_proof_spec.validate().unwrap();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
        .unwrap();
}
