use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{prelude::StdRng, SeedableRng},
};
use blake2::Blake2b512;
use legogroth16::aggregation::srs;
use proof_system::{
    prelude::{
        generate_snark_srs_bound_check, EqualWitnesses, MetaStatements, ProofSpec, SnarkpackSRS,
        VerifierConfig, Witness, WitnessRef, Witnesses,
    },
    proof::Proof,
    setup_params::SetupParams,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        bound_check_legogroth16::{
            BoundCheckLegoGroth16Prover as BoundCheckProverStmt,
            BoundCheckLegoGroth16Verifier as BoundCheckVerifierStmt,
        },
        saver::{SaverProver as SaverProverStmt, SaverVerifier as SaverVerifierStmt},
        Statements,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use saver::setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens};
use std::time::Instant;

use test_utils::bbs::*;

#[test]
fn pok_of_bbs_plus_sigs_and_verifiable_encryption_with_saver_aggregation() {
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 4;
    let (msgs_1, params_1, keypair_1, sig_1) = bbs_plus_sig_setup(&mut rng, msg_count_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let (msgs_2, params_2, keypair_2, sig_2) = bbs_plus_sig_setup(&mut rng, msg_count_2);

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

    // For transformed commitment to the message
    let chunked_comm_gens = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);

    let chunk_bit_size = 16;

    let (snark_pk, _, ek, _) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Message with following indices are verifiably encrypted
    let enc_msg_indices_1 = vec![0, 2];
    let enc_msgs_1 = enc_msg_indices_1
        .iter()
        .map(|i| msgs_1[*i])
        .collect::<Vec<_>>();
    let enc_msg_indices_2 = vec![1, 2, 3, 4, 5, 6];
    let enc_msgs_2 = enc_msg_indices_2
        .iter()
        .map(|i| msgs_2[*i])
        .collect::<Vec<_>>();

    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, 100);
    let (prover_srs, ver_srs) =
        srs.specialize((enc_msg_indices_1.len() + enc_msg_indices_2.len()) as u32);

    let mut prover_setup_params = vec![];

    prover_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
    prover_setup_params.push(SetupParams::SaverCommitmentGens(chunked_comm_gens.clone()));
    prover_setup_params.push(SetupParams::SaverEncryptionKey(ek.clone()));
    prover_setup_params.push(SetupParams::SaverProvingKey(snark_pk.clone()));

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        params_1.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        params_2.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..(enc_msg_indices_1.len() + enc_msg_indices_2.len()) {
        let i = prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
            chunk_bit_size,
            0,
            1,
            2,
            3,
        ));
        stmts_to_aggr.insert(i);
    }

    let mut meta_statements = MetaStatements::new();
    for i in 0..enc_msg_indices_1.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, enc_msg_indices_1[i]), (2 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }
    for i in 0..enc_msg_indices_2.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![
                (1, enc_msg_indices_2[i]),
                (2 + enc_msg_indices_1.len() + i, 0),
            ]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
        ));
    }

    let prover_proof_spec = ProofSpec::new_with_aggregation(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
        Some(vec![stmts_to_aggr]),
        None,
        Some(SnarkpackSRS::ProverSrs(prover_srs)),
    );
    prover_proof_spec.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1,
        msgs_1.into_iter().enumerate().collect(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2,
        msgs_2.into_iter().enumerate().collect(),
    ));
    for m in enc_msgs_1 {
        witnesses.add(Witness::Saver(m));
    }
    for m in enc_msgs_2 {
        witnesses.add(Witness::Saver(m));
    }

    let (proof, _) = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        prover_proof_spec,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap();

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
    verifier_setup_params.push(SetupParams::SaverCommitmentGens(chunked_comm_gens));
    verifier_setup_params.push(SetupParams::SaverEncryptionKey(ek));
    verifier_setup_params.push(SetupParams::SaverVerifyingKey(snark_pk.pk.vk));

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        params_1,
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        params_2,
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..(enc_msg_indices_1.len() + enc_msg_indices_2.len()) {
        let i = verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
            chunk_bit_size,
            0,
            1,
            2,
            3,
        ));
        stmts_to_aggr.insert(i);
    }

    let verifier_proof_spec = ProofSpec::new_with_aggregation(
        verifier_statements.clone(),
        meta_statements.clone(),
        verifier_setup_params,
        None,
        Some(vec![stmts_to_aggr]),
        None,
        Some(SnarkpackSRS::VerifierSrs(ver_srs)),
    );
    verifier_proof_spec.validate().unwrap();

    let updated_proof = proof.for_aggregate();

    let start = Instant::now();
    updated_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!(
        "Time taken to verify {} aggregated SAVER proofs with randomized pairing check: {:?}",
        enc_msg_indices_1.len() + enc_msg_indices_2.len(),
        start.elapsed()
    );

    let start = Instant::now();
    updated_proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec,
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(true),
            },
        )
        .unwrap();
    println!(
        "Time taken to verify {} aggregated SAVER proofs with lazy randomized pairing check: {:?}",
        enc_msg_indices_1.len() + enc_msg_indices_2.len(),
        start.elapsed()
    );
}

#[test]
fn pok_of_bbs_plus_sigs_and_bound_check_with_aggregation() {
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 4;
    let msgs_1 = (1..=msg_count_1)
        .map(|i| Fr::from(100u64 + i * 10_u64))
        .collect::<Vec<_>>();
    let (params_1, keypair_1, sig_1) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let msgs_2 = (1..=msg_count_2)
        .map(|i| Fr::from(1000u64 + i * 10_u64))
        .collect::<Vec<_>>();
    let (params_2, keypair_2, sig_2) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs_2);

    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    let min_1 = 100;
    let max_1 = 200;

    let min_2 = 1000;
    let max_2 = 2000;

    let bounded_msg_indices_1 = vec![0, 2];
    let bounded_msgs_1 = bounded_msg_indices_1
        .iter()
        .map(|i| msgs_1[*i])
        .collect::<Vec<_>>();
    let bounded_msg_indices_2 = vec![1, 2, 3, 4, 5, 6];
    let bounded_msgs_2 = bounded_msg_indices_2
        .iter()
        .map(|i| msgs_2[*i])
        .collect::<Vec<_>>();

    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, 100);
    let (prover_srs, ver_srs) =
        srs.specialize((bounded_msg_indices_1.len() + bounded_msg_indices_2.len()) as u32);

    let mut prover_setup_params = vec![];
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk.clone()));

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        params_1.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        params_2.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..bounded_msg_indices_1.len() {
        let i = prover_statements
            .add(BoundCheckProverStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap());
        stmts_to_aggr.insert(i);
    }
    for _ in 0..bounded_msg_indices_2.len() {
        let i = prover_statements
            .add(BoundCheckProverStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap());
        stmts_to_aggr.insert(i);
    }

    let mut meta_statements = MetaStatements::new();
    for i in 0..bounded_msg_indices_1.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, bounded_msg_indices_1[i]), (2 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }
    for i in 0..bounded_msg_indices_2.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![
                (1, bounded_msg_indices_2[i]),
                (2 + bounded_msg_indices_1.len() + i, 0),
            ]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
        ));
    }

    let prover_proof_spec = ProofSpec::new_with_aggregation(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
        None,
        Some(vec![stmts_to_aggr]),
        Some(SnarkpackSRS::ProverSrs(prover_srs)),
    );
    prover_proof_spec.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1,
        msgs_1.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2,
        msgs_2.clone().into_iter().enumerate().collect(),
    ));
    for m in bounded_msgs_1 {
        witnesses.add(Witness::BoundCheckLegoGroth16(m));
    }
    for m in bounded_msgs_2 {
        witnesses.add(Witness::BoundCheckLegoGroth16(m));
    }

    let (proof, _) = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        prover_proof_spec,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap();

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk.vk));

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        params_1,
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        params_2,
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..bounded_msg_indices_1.len() {
        let i = verifier_statements
            .add(BoundCheckVerifierStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap());
        stmts_to_aggr.insert(i);
    }
    for _ in 0..bounded_msg_indices_2.len() {
        let i = verifier_statements
            .add(BoundCheckVerifierStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap());
        stmts_to_aggr.insert(i);
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

    let start = Instant::now();
    updated_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec.clone(),
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!(
        "Time taken to verify {} aggregated bound check proofs with randomized pairing check: {:?}",
        bounded_msg_indices_1.len() + bounded_msg_indices_2.len(),
        start.elapsed()
    );

    let start = Instant::now();
    updated_proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            verifier_proof_spec,
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(true),
            },
        )
        .unwrap();
    println!(
        "Time taken to verify {} aggregated bound check proofs with lazy randomized pairing check: {:?}",
        bounded_msg_indices_1.len() + bounded_msg_indices_2.len(),
        start.elapsed()
    );
}
