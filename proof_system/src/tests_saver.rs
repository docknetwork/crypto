use crate::prelude::{
    EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, StatementProof, Statements,
    Witness, WitnessRef, Witnesses,
};
use crate::statement::{PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt, Saver as SaverStmt};
use crate::test_serialization;
use crate::test_utils::sig_setup;
use crate::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b;
use saver::setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens};
use std::time::Instant;

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

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
    statements.add(SaverStmt::new_as_statement(
        chunk_bit_size,
        enc_gens.clone(),
        chunked_comm_gens,
        ek,
        snark_pk.clone(),
    ));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx), (1, 0)]
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
    let ct = match &proof.0[1] {
        StatementProof::Saver(s) => &s.ciphertext,
        _ => panic!("This should never happen"),
    };
    let (decrypted_message, nu) = ct
        .decrypt_given_groth16_vk(&sk, &dk, &snark_pk.pk.vk, chunk_bit_size)
        .unwrap();
    assert_eq!(decrypted_message, msgs[enc_msg_idx]);
    ct.verify_decryption_given_groth16_vk(
        &decrypted_message,
        &nu,
        chunk_bit_size,
        &dk,
        &snark_pk.pk.vk,
        &enc_gens,
    )
    .unwrap();
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
    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(
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
        ProofSpec::new_with_statements_and_meta_statements(statements, meta_statements, None);
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
        statements.add(SaverStmt::new_as_statement(
            chunk_bit_size,
            enc_gens.clone(),
            chunked_comm_gens.clone(),
            ek.clone(),
            snark_pk.clone(),
        ));
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, *j), (1 + i, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
    }

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
        let ct = match &proof.0[i + 1] {
            StatementProof::Saver(s) => &s.ciphertext,
            _ => panic!("This should never happen"),
        };
        let (decrypted_message, nu) = ct
            .decrypt_given_groth16_vk(&sk, &dk, &snark_pk.pk.vk, chunk_bit_size)
            .unwrap();
        assert_eq!(decrypted_message, msgs[*j]);
        ct.verify_decryption_given_groth16_vk(
            &decrypted_message,
            &nu,
            chunk_bit_size,
            &dk,
            &snark_pk.pk.vk,
            &enc_gens,
        )
        .unwrap();
    }
    println!(
        "Time taken to decrypt and verify {} encrypted messages in signature over {} messages {:?}",
        enc_msg_indices.len(),
        msg_count,
        start.elapsed()
    );
}
