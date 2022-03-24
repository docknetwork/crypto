use crate::prelude::bound_check::generate_snark_srs_bound_check;
use crate::prelude::{
    EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, Statements, Witness,
    WitnessRef, Witnesses,
};
use crate::statement::{
    BoundCheckLegoGroth16 as BoundCheckStmt, PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
};
use crate::test_utils::sig_setup_given_messages;
use crate::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::PairingEngine;
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::prelude::StdRng;
use ark_std::rand::SeedableRng;
use blake2::Blake2b;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(101u64 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
    // verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();

    let min = msg - Fr::from(35u64);
    let max = msg + Fr::from(100u64);

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(BoundCheckStmt::new_as_statement(min, max, snark_pk.clone()).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());
    let start = Instant::now();
    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);
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
    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of bound check of 1 message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof.clone().verify(proof_spec.clone(), None).unwrap();
    println!(
        "Time taken to verify proof of bound check of 1 message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    // Correct message used in proof creation but meta statement is specifying equality with another message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements_wrong,
        None,
    );
    assert!(proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    assert!(proof.verify(proof_spec.clone(), None).is_err());

    // Prove bound over a message which was not signed
    let mut witnesses_wrong = Witnesses::new();
    witnesses_wrong.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_wrong.add(Witness::BoundCheckLegoGroth16(min + Fr::one()));

    let proof_spec =
        ProofSpec::new_with_statements_and_meta_statements(statements, meta_statements, None);
    assert!(proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses_wrong, None).unwrap();
    assert!(proof.verify(proof_spec.clone(), None).is_err());
}

#[test]
fn pok_of_bbs_plus_sig_and_message_same_as_bound() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    // Here message set as min and them max
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(101u64 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
    // verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();
    let min = msg - Fr::from(35u64);
    let max = msg + Fr::from(100u64);

    // Message same as minimum
    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(BoundCheckStmt::new_as_statement(msg, max, snark_pk.clone()).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    proof.verify(proof_spec.clone(), None).unwrap();

    // Message same as maximum
    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(BoundCheckStmt::new_as_statement(min, msg, snark_pk.clone()).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    proof.verify(proof_spec.clone(), None).unwrap();
}

#[test]
fn pok_of_bbs_plus_sig_and_many_bounded_messages() {
    // Prove knowledge of BBS+ signature and certain messages satisfy some bounds.
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(101u64 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
    // verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following messages's bounds will be checked
    let msg_idx_1 = 1;
    let msg_idx_2 = 2;
    let msg_idx_3 = 4;
    let msg_1 = msgs[msg_idx_1].clone();
    let msg_2 = msgs[msg_idx_2].clone();
    let msg_3 = msgs[msg_idx_3].clone();

    let min_1 = msg_1 - Fr::from(50u64);
    let max_1 = msg_1 + Fr::from(100u64);

    let min_2 = msg_2 - Fr::from(60u64);
    let max_2 = msg_2 + Fr::from(200u64);

    let min_3 = msg_3 - Fr::from(70u64);
    let max_3 = msg_3 + Fr::from(180u64);

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(BoundCheckStmt::new_as_statement(min_1, max_1, snark_pk.clone()).unwrap());
    statements.add(BoundCheckStmt::new_as_statement(min_2, max_2, snark_pk.clone()).unwrap());
    statements.add(BoundCheckStmt::new_as_statement(min_3, max_3, snark_pk.clone()).unwrap());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx_1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx_2), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, msg_idx_3), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg_1));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg_2));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg_3));

    let start = Instant::now();
    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of bound check of 3 messages in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof.verify(proof_spec.clone(), None).unwrap();
    println!(
        "Time taken to verify proof of bound check of 3 messages in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );
}
