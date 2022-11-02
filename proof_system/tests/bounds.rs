use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{rand::prelude::StdRng, rand::SeedableRng};
use std::time::Instant;

use proof_system::prelude::{
    EqualWitnesses, MetaStatements, ProofSpec, Witness, WitnessRef, Witnesses,
};
use proof_system::setup_params::SetupParams;
use proof_system::statement::{
    bbs_plus::PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    bound_check_legogroth16::BoundCheckLegoGroth16Prover as BoundCheckProverStmt,
    bound_check_legogroth16::BoundCheckLegoGroth16Verifier as BoundCheckVerifierStmt, Statements,
};
use proof_system::sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check;
use proof_system::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;

use test_utils::bbs_plus::*;
use test_utils::{test_serialization, Fr, ProofG1};

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    let mut rng = StdRng::seed_from_u64(0u64);

    let min = 100;
    let max = 200;
    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters for bound check circuit. Ideally this should be
    // done only once per verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements
        .add(BoundCheckProverStmt::new_statement_from_params(min, max, snark_pk.clone()).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();
    let start = Instant::now();
    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec_prover);
    println!(
        "Testing serialization for 1 bound check takes {:?}",
        start.elapsed()
    );

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let start = Instant::now();
    let proof = ProofG1::new(&mut rng, proof_spec_prover.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of bound check of 1 message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    test_serialization!(ProofG1, proof);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        BoundCheckVerifierStmt::new_statement_from_params(min, max, snark_pk.vk.clone()).unwrap(),
    );

    test_serialization!(Statements<Bls12_381, G1Affine>, verifier_statements);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

    let start = Instant::now();
    proof
        .clone()
        .verify(verifier_proof_spec.clone(), None)
        .unwrap();
    println!(
        "Time taken to verify proof of bound check of 1 message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    // Correct message used in proof creation but meta statement is specifying equality with another message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements_wrong.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();

    let proof = ProofG1::new(&mut rng, proof_spec_prover.clone(), witnesses.clone(), None).unwrap();

    let proof_spec_verifier = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements_wrong,
        vec![],
        None,
    );
    proof_spec_verifier.validate().unwrap();
    assert!(proof.verify(proof_spec_verifier.clone(), None).is_err());

    // Prove bound over a message which was not signed
    let mut witnesses_wrong = Witnesses::new();
    witnesses_wrong.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_wrong.add(Witness::BoundCheckLegoGroth16(Fr::from(min)));

    let proof_spec_prover =
        ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);
    proof_spec_prover.validate().unwrap();

    let proof = ProofG1::new(&mut rng, proof_spec_prover, witnesses_wrong, None).unwrap();
    let proof_spec_verifier = ProofSpec::new(verifier_statements, meta_statements, vec![], None);
    proof_spec_verifier.validate().unwrap();
    assert!(proof.verify(proof_spec_verifier.clone(), None).is_err());
}

#[test]
fn pok_of_bbs_plus_sig_and_message_same_as_bound() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    // Here message set as min and them max
    let mut rng = StdRng::seed_from_u64(0u64);

    let min = 100;
    let max = 200;
    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
    // verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();

    // Message same as minimum
    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        BoundCheckProverStmt::new_statement_from_params(
            msg.into_repr().as_ref()[0],
            max,
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
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
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    let proof = ProofG1::new(&mut rng, proof_spec_prover.clone(), witnesses.clone(), None).unwrap();

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        BoundCheckVerifierStmt::new_statement_from_params(
            msg.into_repr().as_ref()[0],
            max,
            snark_pk.vk.clone(),
        )
        .unwrap(),
    );
    let proof_spec_verifier = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_verifier.validate().unwrap();
    proof.verify(proof_spec_verifier.clone(), None).unwrap();

    // Message same as maximum
    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        BoundCheckProverStmt::new_statement_from_params(
            min,
            msg.into_repr().as_ref()[0],
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
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
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    let proof = ProofG1::new(&mut rng, proof_spec_prover.clone(), witnesses.clone(), None).unwrap();

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        BoundCheckVerifierStmt::new_statement_from_params(
            min,
            msg.into_repr().as_ref()[0],
            snark_pk.vk.clone(),
        )
        .unwrap(),
    );
    let proof_spec_verifier = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_verifier.validate().unwrap();
    proof.verify(proof_spec_verifier.clone(), None).unwrap();
}

#[test]
fn pok_of_bbs_plus_sig_and_many_bounded_messages() {
    // Prove knowledge of BBS+ signature and certain messages satisfy some bounds.
    fn check(reuse_key: bool) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let min_1 = 50;
        let max_1 = 200;
        let min_2 = 40;
        let max_2 = 300;
        let min_3 = 30;
        let max_3 = 380;
        let msg_count = 5;
        let msgs = (0..msg_count)
            .into_iter()
            .map(|i| Fr::from(101u64 + i as u64))
            .collect::<Vec<_>>();
        let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

        // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
        // verifier and can be published by the verifier for any proofs submitted to him
        let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

        // Following messages' bounds will be checked
        let msg_idx_1 = 1;
        let msg_idx_2 = 2;
        let msg_idx_3 = 4;
        let msg_1 = msgs[msg_idx_1].clone();
        let msg_2 = msgs[msg_idx_2].clone();
        let msg_3 = msgs[msg_idx_3].clone();

        let mut prover_setup_params = vec![];
        if reuse_key {
            prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, prover_setup_params);
        }

        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        if reuse_key {
            prover_statements
                .add(BoundCheckProverStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap());
            prover_statements
                .add(BoundCheckProverStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap());
            prover_statements
                .add(BoundCheckProverStmt::new_statement_from_params_ref(min_3, max_3, 0).unwrap());
        } else {
            prover_statements.add(
                BoundCheckProverStmt::new_statement_from_params(min_1, max_1, snark_pk.clone())
                    .unwrap(),
            );
            prover_statements.add(
                BoundCheckProverStmt::new_statement_from_params(min_2, max_2, snark_pk.clone())
                    .unwrap(),
            );
            prover_statements.add(
                BoundCheckProverStmt::new_statement_from_params(min_3, max_3, snark_pk.clone())
                    .unwrap(),
            );
        }

        test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements);

        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, msg_idx_1), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, msg_idx_2), (2, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, msg_idx_3), (3, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        let prover_proof_spec = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            prover_setup_params,
            None,
        );
        prover_proof_spec.validate().unwrap();

        test_serialization!(ProofSpec<Bls12_381, G1Affine>, prover_proof_spec);

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        ));
        witnesses.add(Witness::BoundCheckLegoGroth16(msg_1));
        witnesses.add(Witness::BoundCheckLegoGroth16(msg_2));
        witnesses.add(Witness::BoundCheckLegoGroth16(msg_3));

        let start = Instant::now();
        let proof =
            ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();
        println!(
            "Time taken to create proof of bound check of 3 messages in signature over {} messages: {:?}",
            msg_count,
            start.elapsed()
        );

        test_serialization!(ProofG1, proof);

        let mut verifier_setup_params = vec![];
        if reuse_key {
            verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk.vk.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, verifier_setup_params);
        }

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        if reuse_key {
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap(),
            );
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap(),
            );
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params_ref(min_3, max_3, 0).unwrap(),
            );
        } else {
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params(
                    min_1,
                    max_1,
                    snark_pk.vk.clone(),
                )
                .unwrap(),
            );
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params(
                    min_2,
                    max_2,
                    snark_pk.vk.clone(),
                )
                .unwrap(),
            );
            verifier_statements.add(
                BoundCheckVerifierStmt::new_statement_from_params(
                    min_3,
                    max_3,
                    snark_pk.vk.clone(),
                )
                .unwrap(),
            );
        }

        test_serialization!(Statements<Bls12_381, G1Affine>, verifier_statements);

        let verifier_proof_spec = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            verifier_setup_params,
            None,
        );
        verifier_proof_spec.validate().unwrap();

        test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

        let start = Instant::now();
        proof.verify(verifier_proof_spec.clone(), None).unwrap();
        println!(
            "Time taken to verify proof of bound check of 3 messages in signature over {} messages: {:?}",
            msg_count,
            start.elapsed()
        );
    }
    check(false);
    check(true);
}
