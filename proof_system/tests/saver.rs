use ark_bls12_381::{Bls12_381, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{rand::prelude::StdRng, rand::SeedableRng, UniformRand};
use proof_system::prelude::generate_snark_srs_bound_check;
use proof_system::prelude::{
    EqualWitnesses, MetaStatements, ProofSpec, StatementProof, Witness, WitnessRef, Witnesses,
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

use test_utils::bbs_plus::*;
use test_utils::{test_serialization, Fr, ProofG1};

pub fn decrypt_and_verify(
    proof: &ProofG1,
    stmt_idx: usize,
    snark_vk: &VerifyingKey<Bls12_381>,
    decrypted: Fr,
    sk: &SecretKey<Fr>,
    dk: &DecryptionKey<Bls12_381>,
    enc_gens: &EncryptionGens<Bls12_381>,
    chunk_bit_size: u8,
) {
    let ct = match &proof.statement_proof(stmt_idx).unwrap() {
        StatementProof::Saver(s) => &s.ciphertext,
        _ => panic!("This should never happen"),
    };
    let (decrypted_message, nu) = ct
        .decrypt_given_groth16_vk(sk, dk, snark_vk, chunk_bit_size)
        .unwrap();
    assert_eq!(decrypted_message, decrypted);
    ct.verify_decryption_given_groth16_vk(
        &decrypted_message,
        &nu,
        chunk_bit_size,
        dk,
        snark_vk,
        enc_gens,
    )
    .unwrap();
}

#[test]
fn pok_of_bbs_plus_sig_and_verifiable_encryption() {
    // Prove knowledge of BBS+ signature and a specific message is verifiably encrypted.
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

    // For transformed commitment to the message
    let chunked_comm_gens = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);

    let chunk_bit_size = 16;

    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Message with index `enc_msg_idx` is verifiably encrypted
    let enc_msg_idx = 1;
    let enc_msg = msgs[enc_msg_idx].clone();

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        SaverProverStmt::new_statement_from_params(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens.clone(),
            ek.clone(),
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, enc_msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements, Instant);
    test_serialization!(MetaStatements, meta_statements);

    let prover_proof_spec = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    assert!(prover_proof_spec.is_valid());

    let start = Instant::now();
    test_serialization!(ProofSpec<Bls12_381, G1Affine>, prover_proof_spec);
    println!(
        "Testing serialization for 1 verifiable encryption takes {:?}",
        start.elapsed()
    );

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::Saver(enc_msg));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let start = Instant::now();
    let proof = ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of 1 encrypted message in signature over {} messages {:?}",
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
        SaverVerifierStmt::new_statement_from_params(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens,
            ek,
            snark_pk.pk.vk.clone(),
        )
        .unwrap(),
    );

    test_serialization!(Statements<Bls12_381, G1Affine>, verifier_statements, Instant);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    assert!(verifier_proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

    let start = Instant::now();
    proof
        .clone()
        .verify(verifier_proof_spec.clone(), None)
        .unwrap();
    println!(
        "Time taken to verify proof of 1 encrypted message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    let start = Instant::now();
    decrypt_and_verify(
        &proof,
        1,
        &snark_pk.pk.vk,
        msgs[enc_msg_idx].clone(),
        &sk,
        &dk,
        &enc_gens,
        chunk_bit_size,
    );
    println!(
        "Time taken to decrypt and verify 1 encrypted message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    // Correct message verifiably encrypted but meta statement is specifying equality with another message
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let prover_proof_spec = ProofSpec::new(
        prover_statements.clone(),
        meta_statements_wrong.clone(),
        vec![],
        None,
    );
    assert!(prover_proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements_wrong,
        vec![],
        None,
    );
    assert!(verifier_proof_spec.is_valid());
    assert!(proof.verify(verifier_proof_spec.clone(), None).is_err());

    // Verifiably encrypt a message which was not signed
    let mut witnesses_wrong = Witnesses::new();
    witnesses_wrong.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_wrong.add(Witness::Saver(Fr::rand(&mut rng)));

    let prover_proof_spec =
        ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);
    assert!(prover_proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses_wrong, None).unwrap();

    let verifier_proof_spec =
        ProofSpec::new(verifier_statements.clone(), meta_statements, vec![], None);
    assert!(verifier_proof_spec.is_valid());
    assert!(proof.verify(verifier_proof_spec.clone(), None).is_err());
}

#[test]
fn pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages() {
    // Prove knowledge of BBS+ signature and a certain messages are verifiably encrypted.
    fn check(reuse_setup_params: bool) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let msg_count = 5;
        let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

        // Decryptor creates public parameters
        let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

        // For transformed commitment to the message
        let chunked_comm_gens = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);

        let chunk_bit_size = 16;

        let (snark_pk, sk, ek, dk) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

        // Message with following indices are verifiably encrypted
        let enc_msg_indices = vec![0, 2, 3];
        let enc_msgs = enc_msg_indices.iter().map(|i| msgs[*i]).collect::<Vec<_>>();

        let mut prover_setup_params = vec![];
        if reuse_setup_params {
            prover_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
            prover_setup_params.push(SetupParams::SaverCommitmentGens(chunked_comm_gens.clone()));
            prover_setup_params.push(SetupParams::SaverEncryptionKey(ek.clone()));
            prover_setup_params.push(SetupParams::SaverProvingKey(snark_pk.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, prover_setup_params);
        }

        let mut prover_statements = Statements::new();
        let mut meta_statements = MetaStatements::new();
        prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        for (i, j) in enc_msg_indices.iter().enumerate() {
            if reuse_setup_params {
                prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
                    chunk_bit_size,
                    0,
                    1,
                    2,
                    3,
                ));
            } else {
                prover_statements.add(
                    SaverProverStmt::new_statement_from_params(
                        chunk_bit_size,
                        enc_gens.clone(),
                        chunked_comm_gens.clone(),
                        ek.clone(),
                        snark_pk.clone(),
                    )
                    .unwrap(),
                );
            }

            meta_statements.add_witness_equality(EqualWitnesses(
                vec![(0, *j), (1 + i, 0)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            ));
        }

        test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements, Instant);

        let prover_proof_spec = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            prover_setup_params,
            None,
        );
        assert!(prover_proof_spec.is_valid());
        test_serialization!(ProofSpec<Bls12_381, G1Affine>, prover_proof_spec);

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        ));
        for m in enc_msgs {
            witnesses.add(Witness::Saver(m));
        }

        let start = Instant::now();
        let proof =
            ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();
        println!(
            "Time taken to create proof of {} encrypted messages in signature over {} messages: {:?}",
            enc_msg_indices.len(),
            msg_count,
            start.elapsed()
        );

        let mut verifier_setup_params = vec![];
        if reuse_setup_params {
            verifier_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens.clone()));
            verifier_setup_params.push(SetupParams::SaverCommitmentGens(chunked_comm_gens.clone()));
            verifier_setup_params.push(SetupParams::SaverEncryptionKey(ek.clone()));
            verifier_setup_params.push(SetupParams::SaverVerifyingKey(snark_pk.pk.vk.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, verifier_setup_params);
        }

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        for _ in 0..enc_msg_indices.len() {
            if reuse_setup_params {
                verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
                    chunk_bit_size,
                    0,
                    1,
                    2,
                    3,
                ));
            } else {
                verifier_statements.add(
                    SaverVerifierStmt::new_statement_from_params(
                        chunk_bit_size,
                        enc_gens.clone(),
                        chunked_comm_gens.clone(),
                        ek.clone(),
                        snark_pk.pk.vk.clone(),
                    )
                    .unwrap(),
                );
            }
        }
        test_serialization!(Statements<Bls12_381, G1Affine>, verifier_statements, Instant);

        let verifier_proof_spec = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            verifier_setup_params,
            None,
        );
        assert!(verifier_proof_spec.is_valid());
        test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

        let start = Instant::now();
        proof
            .clone()
            .verify(verifier_proof_spec.clone(), None)
            .unwrap();
        println!(
            "Time taken to verify proof of {} encrypted messages in signature over {} messages: {:?}",
            enc_msg_indices.len(),
            msg_count,
            start.elapsed()
        );

        let start = Instant::now();
        for (i, j) in enc_msg_indices.iter().enumerate() {
            decrypt_and_verify(
                &proof,
                i + 1,
                &snark_pk.pk.vk,
                msgs[*j].clone(),
                &sk,
                &dk,
                &enc_gens,
                chunk_bit_size,
            );
        }
        println!(
            "Time taken to decrypt and verify {} encrypted messages in signature over {} messages {:?}",
            enc_msg_indices.len(),
            msg_count,
            start.elapsed()
        );
    }
    check(true);
    check(false);
}

#[test]
fn pok_of_bbs_plus_sig_and_verifiable_encryption_for_different_decryptors() {
    // Prove knowledge of BBS+ signature and a certain messages are verifiably encrypted for 2 different decryptors
    fn check(reuse_setup_params: bool) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let msg_count = 5;
        let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

        let chunk_bit_size = 16;

        // 1st Decryptor setup
        let enc_gens_1 = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
        // For transformed commitment to the message
        let chunked_comm_gens_1 = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);
        // Snark setup and keygen
        let (snark_pk_1, sk_1, ek_1, dk_1) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens_1).unwrap();

        // 2nd Decryptor setup
        let enc_gens_2 = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
        // For transformed commitment to the message
        let chunked_comm_gens_2 = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);
        // Snark setup and keygen
        let (snark_pk_2, sk_2, ek_2, dk_2) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens_2).unwrap();

        // Message with index `enc_msg_idx_1` is verifiably encrypted for both decryptors
        let enc_msg_idx_1 = 1;
        let enc_msg_1 = msgs[enc_msg_idx_1].clone();

        // Message with index `enc_msg_idx_2` is verifiably encrypted both 1st decryptor only
        let enc_msg_idx_2 = 2;
        let enc_msg_2 = msgs[enc_msg_idx_2].clone();

        // Message with index `enc_msg_idx_3` is verifiably encrypted both 2nd decryptor only
        let enc_msg_idx_3 = 3;
        let enc_msg_3 = msgs[enc_msg_idx_3].clone();

        let mut prover_setup_params = vec![];
        if reuse_setup_params {
            prover_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens_1.clone()));
            prover_setup_params.push(SetupParams::SaverCommitmentGens(
                chunked_comm_gens_1.clone(),
            ));
            prover_setup_params.push(SetupParams::SaverEncryptionKey(ek_1.clone()));
            prover_setup_params.push(SetupParams::SaverProvingKey(snark_pk_1.clone()));
            prover_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens_2.clone()));
            prover_setup_params.push(SetupParams::SaverCommitmentGens(
                chunked_comm_gens_2.clone(),
            ));
            prover_setup_params.push(SetupParams::SaverEncryptionKey(ek_2.clone()));
            prover_setup_params.push(SetupParams::SaverProvingKey(snark_pk_2.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, prover_setup_params);
        }

        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));

        // For encrypting message at `enc_msg_idx_1` for 1st decryptor
        if reuse_setup_params {
            prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
                chunk_bit_size,
                0,
                1,
                2,
                3,
            ));
        } else {
            prover_statements.add(
                SaverProverStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_1.clone(),
                    chunked_comm_gens_1.clone(),
                    ek_1.clone(),
                    snark_pk_1.clone(),
                )
                .unwrap(),
            );
        }
        // For encrypting message at `enc_msg_idx_1` for 2nd decryptor
        if reuse_setup_params {
            prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
                chunk_bit_size,
                4,
                5,
                6,
                7,
            ));
        } else {
            prover_statements.add(
                SaverProverStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_2.clone(),
                    chunked_comm_gens_2.clone(),
                    ek_2.clone(),
                    snark_pk_2.clone(),
                )
                .unwrap(),
            );
        }
        // For encrypting message at `enc_msg_idx_2` for 1st decryptor
        if reuse_setup_params {
            prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
                chunk_bit_size,
                0,
                1,
                2,
                3,
            ));
        } else {
            prover_statements.add(
                SaverProverStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_1.clone(),
                    chunked_comm_gens_1.clone(),
                    ek_1.clone(),
                    snark_pk_1.clone(),
                )
                .unwrap(),
            );
        }
        // For encrypting message at `enc_msg_idx_3` for 2nd decryptor
        if reuse_setup_params {
            prover_statements.add(SaverProverStmt::new_statement_from_params_ref(
                chunk_bit_size,
                4,
                5,
                6,
                7,
            ));
        } else {
            prover_statements.add(
                SaverProverStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_2.clone(),
                    chunked_comm_gens_2.clone(),
                    ek_2.clone(),
                    snark_pk_2.clone(),
                )
                .unwrap(),
            );
        }

        test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements);

        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, enc_msg_idx_1), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, enc_msg_idx_1), (2, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, enc_msg_idx_2), (3, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, enc_msg_idx_3), (4, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        let prover_proof_spec = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            prover_setup_params,
            None,
        );
        assert!(prover_proof_spec.is_valid());

        test_serialization!(ProofSpec<Bls12_381, G1Affine>, prover_proof_spec);

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        ));
        witnesses.add(Witness::Saver(enc_msg_1));
        witnesses.add(Witness::Saver(enc_msg_1));
        witnesses.add(Witness::Saver(enc_msg_2));
        witnesses.add(Witness::Saver(enc_msg_3));

        let start = Instant::now();
        let proof =
            ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();
        println!(
            "Time taken to create proof of verifiable encryption of 4 messages in signature: {:?}",
            start.elapsed()
        );

        let mut verifier_setup_params = vec![];
        if reuse_setup_params {
            verifier_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens_1.clone()));
            verifier_setup_params.push(SetupParams::SaverCommitmentGens(
                chunked_comm_gens_1.clone(),
            ));
            verifier_setup_params.push(SetupParams::SaverEncryptionKey(ek_1.clone()));
            verifier_setup_params.push(SetupParams::SaverVerifyingKey(snark_pk_1.pk.vk.clone()));
            verifier_setup_params.push(SetupParams::SaverEncryptionGens(enc_gens_2.clone()));
            verifier_setup_params.push(SetupParams::SaverCommitmentGens(
                chunked_comm_gens_2.clone(),
            ));
            verifier_setup_params.push(SetupParams::SaverEncryptionKey(ek_2.clone()));
            verifier_setup_params.push(SetupParams::SaverVerifyingKey(snark_pk_2.pk.vk.clone()));
            test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, verifier_setup_params);
        }

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));

        // For encrypting message at `enc_msg_idx_1` for 1st decryptor
        if reuse_setup_params {
            verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
                chunk_bit_size,
                0,
                1,
                2,
                3,
            ));
        } else {
            verifier_statements.add(
                SaverVerifierStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_1.clone(),
                    chunked_comm_gens_1.clone(),
                    ek_1.clone(),
                    snark_pk_1.pk.vk.clone(),
                )
                .unwrap(),
            );
        }

        // For encrypting message at `enc_msg_idx_1` for 2nd decryptor
        if reuse_setup_params {
            verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
                chunk_bit_size,
                4,
                5,
                6,
                7,
            ));
        } else {
            verifier_statements.add(
                SaverVerifierStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_2.clone(),
                    chunked_comm_gens_2.clone(),
                    ek_2.clone(),
                    snark_pk_2.pk.vk.clone(),
                )
                .unwrap(),
            );
        }

        // For encrypting message at `enc_msg_idx_2` for 1st decryptor
        if reuse_setup_params {
            verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
                chunk_bit_size,
                0,
                1,
                2,
                3,
            ));
        } else {
            verifier_statements.add(
                SaverVerifierStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_1.clone(),
                    chunked_comm_gens_1.clone(),
                    ek_1.clone(),
                    snark_pk_1.pk.vk.clone(),
                )
                .unwrap(),
            );
        }

        // For encrypting message at `enc_msg_idx_3` for 2nd decryptor
        if reuse_setup_params {
            verifier_statements.add(SaverVerifierStmt::new_statement_from_params_ref(
                chunk_bit_size,
                4,
                5,
                6,
                7,
            ));
        } else {
            verifier_statements.add(
                SaverVerifierStmt::new_statement_from_params(
                    chunk_bit_size,
                    enc_gens_2.clone(),
                    chunked_comm_gens_2.clone(),
                    ek_2.clone(),
                    snark_pk_2.pk.vk.clone(),
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
        assert!(verifier_proof_spec.is_valid());
        test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

        let start = Instant::now();
        proof
            .clone()
            .verify(verifier_proof_spec.clone(), None)
            .unwrap();
        println!(
            "Time taken to verify proof of verifiable encryption of 4 messages in signature: {:?}",
            start.elapsed()
        );

        decrypt_and_verify(
            &proof,
            1,
            &snark_pk_1.pk.vk,
            msgs[enc_msg_idx_1].clone(),
            &sk_1,
            &dk_1,
            &enc_gens_1,
            chunk_bit_size,
        );
        decrypt_and_verify(
            &proof,
            2,
            &snark_pk_2.pk.vk,
            msgs[enc_msg_idx_1].clone(),
            &sk_2,
            &dk_2,
            &enc_gens_2,
            chunk_bit_size,
        );
        decrypt_and_verify(
            &proof,
            3,
            &snark_pk_1.pk.vk,
            msgs[enc_msg_idx_2].clone(),
            &sk_1,
            &dk_1,
            &enc_gens_1,
            chunk_bit_size,
        );
        decrypt_and_verify(
            &proof,
            4,
            &snark_pk_2.pk.vk,
            msgs[enc_msg_idx_3].clone(),
            &sk_2,
            &dk_2,
            &enc_gens_2,
            chunk_bit_size,
        );
    }
    check(true);
    check(false);
}

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message_and_verifiable_encryption() {
    // Prove knowledge of BBS+ signature and a certain messages satisfy some bounds i.e. min <= message <= max
    // and a message is verifiably encrypted.
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
    let bound_snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    let chunk_bit_size = 16;
    // For transformed commitment to the message
    let chunked_comm_gens = ChunkedCommitmentGens::<G1Affine>::new_using_rng(&mut rng);
    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();

    // Message with index `enc_msg_idx` is verifiably encrypted and its bounds are checked as well
    let enc_msg_idx = 3;
    let enc_msg = msgs[enc_msg_idx].clone();

    let mut prover_setup_params = vec![];
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(bound_snark_pk.clone()));

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    prover_statements
        .add(BoundCheckProverStmt::new_statement_from_params_ref(min, max, 0).unwrap());
    prover_statements
        .add(BoundCheckProverStmt::new_statement_from_params_ref(min, max, 0).unwrap());
    prover_statements.add(
        SaverProverStmt::new_statement_from_params(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens.clone(),
            ek.clone(),
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
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, enc_msg_idx), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, enc_msg_idx), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let prover_proof_spec = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
    );
    assert!(prover_proof_spec.is_valid());
    test_serialization!(ProofSpec<Bls12_381, G1Affine>, prover_proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));
    witnesses.add(Witness::BoundCheckLegoGroth16(enc_msg));
    witnesses.add(Witness::Saver(enc_msg));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = ProofG1::new(&mut rng, prover_proof_spec.clone(), witnesses.clone(), None).unwrap();
    test_serialization!(ProofG1, proof);

    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(
        bound_snark_pk.vk.clone(),
    ));

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements
        .add(BoundCheckVerifierStmt::new_statement_from_params_ref(min, max, 0).unwrap());
    verifier_statements
        .add(BoundCheckVerifierStmt::new_statement_from_params_ref(min, max, 0).unwrap());
    verifier_statements.add(
        SaverVerifierStmt::new_statement_from_params(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens,
            ek,
            snark_pk.pk.vk.clone(),
        )
        .unwrap(),
    );

    test_serialization!(Statements<Bls12_381, G1Affine>, verifier_statements);

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements,
        meta_statements.clone(),
        verifier_setup_params,
        None,
    );
    assert!(verifier_proof_spec.is_valid());
    test_serialization!(ProofSpec<Bls12_381, G1Affine>, verifier_proof_spec);

    proof
        .clone()
        .verify(verifier_proof_spec.clone(), None)
        .unwrap();

    decrypt_and_verify(
        &proof,
        3,
        &snark_pk.pk.vk,
        msgs[enc_msg_idx].clone(),
        &sk,
        &dk,
        &enc_gens,
        chunk_bit_size,
    );
}
