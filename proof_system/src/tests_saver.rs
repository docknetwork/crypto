use crate::prelude::{
    EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, StatementProof, Statements,
    Witness, WitnessRef, Witnesses,
};
use crate::statement::{PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt, Saver as SaverStmt};
use crate::test_serialization;
use crate::test_utils::sig_setup;
use crate::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::PairingEngine;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b;
use saver::keygen::{DecryptionKey, SecretKey};
use saver::setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens};
use std::time::Instant;

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Blake2b>;

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
    let chunked_comm_gens =
        ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(&mut rng);

    let chunk_bit_size = 8;

    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Message with index `enc_msg_idx` is verifiably encrypted
    let enc_msg_idx = 1;
    let enc_msg = msgs[enc_msg_idx].clone();

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens,
            ek,
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements, Instant);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());
    let start = Instant::now();
    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);
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
    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of 1 encrypted message in signature over {} messages {:?}",
        msg_count,
        start.elapsed()
    );

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof.clone().verify(proof_spec.clone(), None).unwrap();
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
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements_wrong,
        None,
    );
    assert!(proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    assert!(proof.verify(proof_spec.clone(), None).is_err());

    // Verifiably encrypt a message which was not signed
    let mut witnesses_wrong = Witnesses::new();
    witnesses_wrong.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_wrong.add(Witness::Saver(Fr::rand(&mut rng)));

    let proof_spec =
        ProofSpec::new(statements, meta_statements, None);
    assert!(proof_spec.is_valid());

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses_wrong, None).unwrap();
    assert!(proof.verify(proof_spec.clone(), None).is_err());
}

#[test]
fn pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages() {
    // Prove knowledge of BBS+ signature and a specific message is verifiably encrypted.
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

    // For transformed commitment to the message
    let chunked_comm_gens =
        ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(&mut rng);

    let chunk_bit_size = 8;

    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Message with following indices are verifiably encrypted
    let enc_msg_indices = vec![0, 2, 3];
    let enc_msgs = enc_msg_indices.iter().map(|i| msgs[*i]).collect::<Vec<_>>();

    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    for (i, j) in enc_msg_indices.iter().enumerate() {
        statements.add(
            SaverStmt::new_as_statement(
                chunk_bit_size,
                enc_gens.clone(),
                chunked_comm_gens.clone(),
                ek.clone(),
                snark_pk.clone(),
            )
            .unwrap(),
        );
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, *j), (1 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
    }

    let proof_spec = ProofSpec::new(
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
    for m in enc_msgs {
        witnesses.add(Witness::Saver(m));
    }

    let start = Instant::now();
    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!(
        "Time taken to create proof of {} encrypted messages in signature over {} messages {:?}",
        enc_msg_indices.len(),
        msg_count,
        start.elapsed()
    );

    let start = Instant::now();
    proof.clone().verify(proof_spec.clone(), None).unwrap();
    println!(
        "Time taken to verify proof of {} encrypted messages in signature over {} messages {:?}",
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

#[test]
fn pok_of_bbs_plus_sig_and_verifiable_encryption_for_different_decryptors() {
    // Prove knowledge of BBS+ signature and a certain messages are verifiably encrypted for 2 different decryptors
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    let chunk_bit_size = 8;

    // 1st Decryptor setup
    let enc_gens_1 = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    // For transformed commitment to the message
    let chunked_comm_gens_1 =
        ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(&mut rng);
    // Snark setup and keygen
    let (snark_pk_1, sk_1, ek_1, dk_1) =
        setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens_1).unwrap();

    // 2nd Decryptor setup
    let enc_gens_2 = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    // For transformed commitment to the message
    let chunked_comm_gens_2 =
        ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(&mut rng);
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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    // For encrypting message at `enc_msg_idx_1` for 1st decryptor
    statements.add(
        SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens_1.clone(),
            chunked_comm_gens_1.clone(),
            ek_1.clone(),
            snark_pk_1.clone(),
        )
        .unwrap(),
    );
    // For encrypting message at `enc_msg_idx_1` for 2nd decryptor
    statements.add(
        SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens_2.clone(),
            chunked_comm_gens_2.clone(),
            ek_2.clone(),
            snark_pk_2.clone(),
        )
        .unwrap(),
    );
    // For encrypting message at `enc_msg_idx_2` for 1st decryptor
    statements.add(
        SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens_1.clone(),
            chunked_comm_gens_1,
            ek_1,
            snark_pk_1.clone(),
        )
        .unwrap(),
    );
    // For encrypting message at `enc_msg_idx_3` for 2nd decryptor
    statements.add(
        SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens_2.clone(),
            chunked_comm_gens_2,
            ek_2,
            snark_pk_2.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx_1), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx_1), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx_2), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx_3), (4, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let proof_spec = ProofSpec::new(
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
    witnesses.add(Witness::Saver(enc_msg_1));
    witnesses.add(Witness::Saver(enc_msg_1));
    witnesses.add(Witness::Saver(enc_msg_2));
    witnesses.add(Witness::Saver(enc_msg_3));

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    proof.clone().verify(proof_spec.clone(), None).unwrap();

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
