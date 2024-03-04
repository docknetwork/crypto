use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::{
    prelude::{PublicKeyG2, SignatureG1},
    setup::SignatureParamsG1,
};
use blake2::Blake2b512;
use legogroth16::{circom::R1CS, ProvingKey};
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
fn pok_of_bbs_plus_sig_and_attributes_not_equals_check() {
    // Prove knowledge of a BBS+ signature and one of the signed message being not equal to a
    // public value.

    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 5;
    let msgs: Vec<Fr> = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect();

    let (sig_params, sig_keypair, sig) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs);

    // A random value with which inequality will be proved. This will be public.
    let a_random_value = Fr::rand(&mut rng);
    // The message index with which inequality will be proved. This will be hidden
    let unequal_msg_idx = 0;
    assert_ne!(msgs[unequal_msg_idx], a_random_value);

    let commit_witness_count = 1;
    // Circom code for following in tests/r1cs/circom/circuits/not_equal_public.circom
    let (snark_pk, r1cs, wasm_bytes) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/not_equal_public.r1cs",
        "tests/r1cs/circom/bls12-381/not_equal_public.wasm",
        commit_witness_count,
        &mut rng,
    );

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
        vec![(0, unequal_msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();
    test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("in".to_string(), vec![msgs[unequal_msg_idx]]);
    r1cs_wit.set_public("pub".to_string(), vec![a_random_value]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));

    // The public inputs for verifier are the output signal 1 and the public input `a_random_value`
    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(
            vec![Fr::one(), a_random_value],
            snark_pk.vk.clone(),
        )
        .unwrap(),
    );

    test_serialization!(Statements<Bls12_381>, verifier_statements);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            Default::default(),
        )
        .unwrap();

    // Proof with wrong public input fails
    let mut verifier_statements_1 = Statements::new();
    verifier_statements_1.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params,
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements_1.add(
        R1CSVerifierStmt::new_statement_from_params(
            vec![Fr::one(), msgs[unequal_msg_idx]],
            snark_pk.vk,
        )
        .unwrap(),
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

    // Proof with wrong meta statement fails. Here the relation being proven in Circom is correct but
    // the prover is proving equality with wrong message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, unequal_msg_idx + 1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_prover_1 = ProofSpec::new(
        prover_statements.clone(),
        meta_statements_wrong.clone(),
        vec![],
        None,
    );
    proof_spec_prover_1.validate().unwrap();

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover_1,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    let proof_spec_verifier_2 = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements_wrong,
        vec![],
        None,
    );
    proof_spec_verifier_2.validate().unwrap();
    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_verifier_2, None, Default::default())
        .is_err());
}

#[test]
fn pok_of_bbs_plus_sig_and_attributes_less_than_check() {
    // Prove knowledge of 2 BBS+ signatures and less than relation between several of their signed messages.
    // Message of the same signature and different signatures are compared.

    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 5;
    let mut msgs_1: Vec<Fr> = (0..msg_count_1).map(|_| Fr::rand(&mut rng)).collect();
    msgs_1[1] = Fr::from(100u64);
    msgs_1[3] = Fr::from(300u64);
    let (sig_params_1, sig_keypair_1, sig_1) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let mut msgs_2: Vec<Fr> = (0..msg_count_2).map(|_| Fr::rand(&mut rng)).collect();
    msgs_2[4] = Fr::from(50u64);
    msgs_2[5] = Fr::from(200u64);
    let (sig_params_2, sig_keypair_2, sig_2) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_2);

    let commit_witness_count = 2;
    // Circom code for following in tests/r1cs/circom/circuits/less_than_32.circom
    let (snark_pk, r1cs, wasm_bytes) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/less_than_32.r1cs",
        "tests/r1cs/circom/bls12-381/less_than_32.wasm",
        commit_witness_count,
        &mut rng,
    );

    // Will check for less than relation among the messages of the same signature
    fn check(
        rng: &mut StdRng,
        r1cs: R1CS<Bls12_381>,
        wasm_bytes: Vec<u8>,
        l_msg_idx: usize,
        g_msg_idx: usize,
        msgs: Vec<Fr>,
        sig: SignatureG1<Bls12_381>,
        sig_params: SignatureParamsG1<Bls12_381>,
        pk: PublicKeyG2<Bls12_381>,
        snark_pk: ProvingKey<Bls12_381>,
    ) {
        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(
            R1CSProverStmt::new_statement_from_params(r1cs, wasm_bytes, snark_pk.clone()).unwrap(),
        );

        // Check for less than relation between messages
        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, l_msg_idx), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, g_msg_idx), (1, 1)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        test_serialization!(Statements<Bls12_381>, prover_statements);
        test_serialization!(MetaStatements, meta_statements);

        let proof_spec_prover = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof_spec_prover.validate().unwrap();
        test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().collect(),
        ));
        let mut r1cs_wit = R1CSCircomWitness::new();
        r1cs_wit.set_private("a".to_string(), vec![msgs[l_msg_idx]]);
        r1cs_wit.set_private("b".to_string(), vec![msgs[g_msg_idx]]);
        witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof = Proof::new::<StdRng, Blake2b512>(
            rng,
            proof_spec_prover.clone(),
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;

        test_serialization!(Proof<Bls12_381>, proof);

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params.clone(),
            pk.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(
            R1CSVerifierStmt::new_statement_from_params(vec![Fr::one()], snark_pk.vk.clone())
                .unwrap(),
        );

        test_serialization!(Statements<Bls12_381>, verifier_statements);

        let verifier_proof_spec = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        verifier_proof_spec.validate().unwrap();

        test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

        proof
            .clone()
            .verify::<StdRng, Blake2b512>(
                rng,
                verifier_proof_spec.clone(),
                None,
                Default::default(),
            )
            .unwrap();

        // Proof with wrong public input fails
        let mut verifier_statements_1 = Statements::new();
        verifier_statements_1.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params.clone(),
            BTreeMap::new(),
        ));
        verifier_statements_1.add(
            R1CSVerifierStmt::new_statement_from_params(vec![Fr::zero()], snark_pk.vk.clone())
                .unwrap(),
        );
        let verifier_proof_spec_1 = ProofSpec::new(
            verifier_statements_1.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        verifier_proof_spec_1.validate().unwrap();
        assert!(proof
            .verify::<StdRng, Blake2b512>(rng, verifier_proof_spec_1, None, Default::default())
            .is_err());

        // -----------------------------------------------------------------------------

        // Check for less than relation between messages
        let mut meta_statements_1 = MetaStatements::new();
        meta_statements_1.add_witness_equality(EqualWitnesses(
            vec![(0, g_msg_idx), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements_1.add_witness_equality(EqualWitnesses(
            vec![(0, l_msg_idx), (1, 1)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        let proof_spec_prover_1 = ProofSpec::new(
            prover_statements.clone(),
            meta_statements_1.clone(),
            vec![],
            None,
        );
        proof_spec_prover_1.validate().unwrap();

        let mut witnesses_1 = Witnesses::new();
        witnesses_1.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig,
            msgs.clone().into_iter().enumerate().collect(),
        ));
        let mut r1cs_wit = R1CSCircomWitness::new();
        r1cs_wit.set_private("a".to_string(), vec![msgs[g_msg_idx]]);
        r1cs_wit.set_private("b".to_string(), vec![msgs[l_msg_idx]]);
        witnesses_1.add(Witness::R1CSLegoGroth16(r1cs_wit));

        let proof_1 = Proof::new::<StdRng, Blake2b512>(
            rng,
            proof_spec_prover_1,
            witnesses_1.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;

        let mut verifier_statements_2 = Statements::new();
        verifier_statements_2.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params.clone(),
            pk.clone(),
            BTreeMap::new(),
        ));
        verifier_statements_2.add(
            R1CSVerifierStmt::new_statement_from_params(vec![Fr::zero()], snark_pk.vk.clone())
                .unwrap(),
        );

        let verifier_proof_spec_2 = ProofSpec::new(
            verifier_statements_2.clone(),
            meta_statements_1.clone(),
            vec![],
            None,
        );
        verifier_proof_spec_2.validate().unwrap();
        proof_1
            .clone()
            .verify::<StdRng, Blake2b512>(rng, verifier_proof_spec_2, None, Default::default())
            .unwrap();

        // Proof with wrong public input fails
        let mut verifier_statements_3 = Statements::new();
        verifier_statements_3.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params,
            BTreeMap::new(),
        ));
        verifier_statements_3.add(
            R1CSVerifierStmt::new_statement_from_params(vec![Fr::one()], snark_pk.vk).unwrap(),
        );
        let verifier_proof_spec_3 = ProofSpec::new(
            verifier_statements_3.clone(),
            meta_statements_1.clone(),
            vec![],
            None,
        );
        verifier_proof_spec_3.validate().unwrap();
        assert!(proof_1
            .verify::<StdRng, Blake2b512>(rng, verifier_proof_spec_3, None, Default::default())
            .is_err());
    }

    check(
        &mut rng,
        r1cs.clone(),
        wasm_bytes.clone(),
        1,
        3,
        msgs_1.clone(),
        sig_1.clone(),
        sig_params_1.clone(),
        sig_keypair_1.public_key.clone(),
        snark_pk.clone(),
    );
    check(
        &mut rng,
        r1cs.clone(),
        wasm_bytes.clone(),
        4,
        5,
        msgs_2.clone(),
        sig_2.clone(),
        sig_params_2.clone(),
        sig_keypair_2.public_key.clone(),
        snark_pk.clone(),
    );

    // Will check for less than relation among the messages of the both signature

    let mut prover_setup_params = vec![];
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk.clone()));
    prover_setup_params.push(SetupParams::R1CS(r1cs));
    prover_setup_params.push(SetupParams::Bytes(wasm_bytes));
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
    prover_statements.add(R1CSProverStmt::new_statement_from_params_ref(1, 2, 0).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(1, 5), (2, 1)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(1, 4), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 3), (3, 1)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

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

    let mut r1cs_wit_1 = R1CSCircomWitness::new();
    r1cs_wit_1.set_private("a".to_string(), vec![msgs_1[1]]);
    r1cs_wit_1.set_private("b".to_string(), vec![msgs_2[5]]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit_1));

    let mut r1cs_wit_2 = R1CSCircomWitness::new();
    r1cs_wit_2.set_private("a".to_string(), vec![msgs_2[4]]);
    r1cs_wit_2.set_private("b".to_string(), vec![msgs_1[3]]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit_2));

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
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk.vk.clone()));
    verifier_setup_params.push(SetupParams::FieldElemVec(vec![Fr::one()]));
    test_serialization!(Vec<SetupParams<Bls12_381>>, verifier_setup_params);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_1.clone(),
        sig_keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_2.clone(),
        sig_keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(vec![Fr::one()], snark_pk.vk.clone()).unwrap(),
    );
    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(vec![Fr::one()], snark_pk.vk.clone()).unwrap(),
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

    // Proof with wrong public input fails
    let mut verifier_statements_1 = Statements::new();
    verifier_statements_1.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_1,
        sig_keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements_1.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params_2,
        sig_keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements_1.add(
        R1CSVerifierStmt::new_statement_from_params(vec![Fr::zero()], snark_pk.vk.clone()).unwrap(),
    );
    verifier_statements_1
        .add(R1CSVerifierStmt::new_statement_from_params(vec![Fr::zero()], snark_pk.vk).unwrap());
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

#[test]
fn pok_of_bbs_plus_sig_and_multiplication_check() {
    // Prove knowledge of a BBS+ signature and product of 2 messages being equal to a
    // public value. Checks 2 cases -
    // 1) both inputs to the product are signed messages,
    // 2) only one of the input is a signed message, the other input is not part of the signature

    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 5;
    let msgs: Vec<Fr> = (0..msg_count)
        .map(|i| Fr::from((100 + i) * 10_u64))
        .collect();

    let (sig_params, sig_keypair, sig) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs);

    let msg_1_idx = 1;
    let msg_2_idx = 3;

    // Products
    let product_1 = msgs[msg_1_idx] * msgs[msg_2_idx]; // For case 2

    let a_random = Fr::rand(&mut rng);
    let product_2 = msgs[msg_1_idx] * a_random; // For case 2

    let commit_witness_count = 2;
    // Circom code for following in tests/r1cs/circom/circuits/multiply2.circom
    let (snark_pk, r1cs, wasm_bytes) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/multiply2.r1cs",
        "tests/r1cs/circom/bls12-381/multiply2.wasm",
        commit_witness_count,
        &mut rng,
    );

    // ---------------- Case 1 ----------------------------------------------

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
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
        vec![(0, msg_1_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_2_idx), (1, 1)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();
    test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("a".to_string(), vec![msgs[msg_1_idx]]);
    r1cs_wit.set_private("b".to_string(), vec![msgs[msg_2_idx]]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));

    // The public input for verifier is the product `product`
    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(vec![product_1], snark_pk.vk.clone()).unwrap(),
    );

    test_serialization!(Statements<Bls12_381>, verifier_statements);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            Default::default(),
        )
        .unwrap();

    // Proof with wrong public input fails
    let mut verifier_statements_1 = Statements::new();
    verifier_statements_1.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
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
    verifier_proof_spec_1.validate().unwrap();
    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec_1, None, Default::default())
        .is_err());

    // Proof with wrong meta statement fails. Here the relation being proven in Circom is correct but
    // the prover is proving equality with wrong message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, msg_1_idx + 1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, msg_2_idx), (1, 1)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_prover_1 = ProofSpec::new(
        prover_statements.clone(),
        meta_statements_wrong.clone(),
        vec![],
        None,
    );
    proof_spec_prover_1.validate().unwrap();

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover_1,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    let proof_spec_verifier_2 = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements_wrong,
        vec![],
        None,
    );
    proof_spec_verifier_2.validate().unwrap();
    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_verifier_2, None, Default::default())
        .is_err());

    // ---------------- Case 2 ----------------------------------------------

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
        vec![(0, msg_1_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();
    test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("a".to_string(), vec![msgs[msg_1_idx]]);
    r1cs_wit.set_private("b".to_string(), vec![a_random]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));

    // The public input for verifier is the product `product`
    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(vec![product_2], snark_pk.vk.clone()).unwrap(),
    );

    test_serialization!(Statements<Bls12_381>, verifier_statements);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            Default::default(),
        )
        .unwrap();

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

    // Proof with wrong meta statement fails. Here the relation being proven in Circom is correct but
    // the prover is proving equality with wrong message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, msg_1_idx + 1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_prover_1 = ProofSpec::new(
        prover_statements.clone(),
        meta_statements_wrong.clone(),
        vec![],
        None,
    );
    proof_spec_prover_1.validate().unwrap();

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover_1,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    let proof_spec_verifier_2 = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements_wrong,
        vec![],
        None,
    );
    proof_spec_verifier_2.validate().unwrap();
    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_verifier_2, None, Default::default())
        .is_err());
}
