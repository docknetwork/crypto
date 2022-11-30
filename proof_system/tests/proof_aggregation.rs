use ark_bls12_381::{Bls12_381, G1Affine};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{rand::prelude::StdRng, rand::SeedableRng, UniformRand};
use proof_system::prelude::{generate_snark_srs_bound_check, ProverConfig, SnarkpackSRS};
use proof_system::prelude::{
    EqualWitnesses, MetaStatements, ProofSpec, Witness, WitnessRef, Witnesses,
};
use proof_system::setup_params::SetupParams;
use proof_system::statement::{
    bbs_plus::PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    bound_check_legogroth16::BoundCheckLegoGroth16Prover as BoundCheckProverStmt,
    bound_check_legogroth16::BoundCheckLegoGroth16Verifier as BoundCheckVerifierStmt,
    saver::SaverProver as SaverProverStmt, saver::SaverVerifier as SaverVerifierStmt, Statements,
};
use proof_system::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use saver::keygen::{DecryptionKey, SecretKey};
use saver::prelude::VerifyingKey;
use saver::setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens};
use std::time::Instant;
use legogroth16::aggregation::srs;

use test_utils::bbs_plus::*;
use test_utils::{Fr, ProofG1};

#[test]
fn pok_of_bbs_plus_sigs_and_verifiable_encryption_with_saver_aggregation() {
    // Prove knowledge of BBS+ signature and a specific message is verifiably encrypted.
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 4;
    let (msgs_1, params_1, keypair_1, sig_1) = sig_setup(&mut rng, msg_count_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let (msgs_2, params_2, keypair_2, sig_2) = sig_setup(&mut rng, msg_count_2);

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

    // For transformed commitment to the message
    let chunked_comm_gens = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);

    let chunk_bit_size = 16;

    let (snark_pk, sk, ek, dk) =
        setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Message with following indices are verifiably encrypted
    let enc_msg_indices_1 = vec![0, 2];
    let enc_msgs_1 = enc_msg_indices_1.iter().map(|i| msgs_1[*i]).collect::<Vec<_>>();
    let enc_msg_indices_2 = vec![1, 2, 3, 4, 5, 6];
    let enc_msgs_2 = enc_msg_indices_2.iter().map(|i| msgs_2[*i]).collect::<Vec<_>>();

    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, 100);
    let (prover_srs, ver_srs) = srs.specialize(enc_msg_indices_1.len() + enc_msg_indices_2.len());

    let mut prover_setup_params = vec![];

    prover_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
    prover_setup_params.push(SetupParams::SaverCommitmentGens(
        chunked_comm_gens.clone(),
    ));
    prover_setup_params.push(SetupParams::SaverEncryptionKey(ek.clone()));
    prover_setup_params.push(SetupParams::SaverProvingKey(snark_pk.clone()));

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_2.clone(),
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..(enc_msg_indices_1.len()+enc_msg_indices_2.len()) {
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
            vec![(0, enc_msg_indices_1[i]), (2+i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }
    for i in 0..enc_msg_indices_2.len() {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(1, enc_msg_indices_2[i]), (2+enc_msg_indices_1.len()+i, 0)]
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
            Some(SnarkpackSRS::ProverSrs(prover_srs))
    );
    prover_proof_spec.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        msgs_1.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2.clone(),
        msgs_2.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    for m in enc_msgs_1 {
        witnesses.add(Witness::Saver(m));
    }
    for m in enc_msgs_2 {
        witnesses.add(Witness::Saver(m));
    }

    let (proof, comm_rand) = ProofG1::new(
        &mut rng,
        prover_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
        .unwrap();

    let updated_proof = proof.for_aggregate();

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
    verifier_setup_params.push(SetupParams::SaverCommitmentGens(
        chunked_comm_gens.clone(),
    ));
    verifier_setup_params.push(SetupParams::SaverEncryptionKey(ek.clone()));
    verifier_setup_params.push(SetupParams::SaverVerifyingKey(snark_pk.pk.vk.clone()));

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_2.clone(),
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let mut stmts_to_aggr = BTreeSet::new();
    for _ in 0..(enc_msg_indices_1.len()+enc_msg_indices_2.len()) {
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
        None,
        Some(vec![stmts_to_aggr]),
        Some(SnarkpackSRS::VerifierSrs(ver_srs))
    );
    verifier_proof_spec.validate().unwrap();

    proof
        .clone()
        .verify(verifier_proof_spec.clone(), None, Default::default())
        .unwrap();
}