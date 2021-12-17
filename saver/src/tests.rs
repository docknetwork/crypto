use crate::commitment::{commitment_to_chunks, create_gs};
use crate::encryption::{decrypt, encrypt, verify_ciphertext_commitment};
use crate::saver_groth16::{create_proof, generate_crs, verify_proof, BitsizeCheckCircuit};
use crate::setup::{keygen, Generators};
use crate::utils::decompose;
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_groth16::prepare_verifying_key;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::UniformRand;
use bbs_plus::setup::{KeypairG2, SignatureParamsG1};
use bbs_plus::signature::SignatureG1;
use blake2::Blake2b;
use proof_system::prelude::{
    EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, Statement, Statements,
    Witness, WitnessRef, Witnesses,
};
use proof_system::statement::{
    PedersenCommitment as PedersenCommitmentStmt, PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
};
use proof_system::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Add;
use std::time::Instant;

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

fn sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: usize,
) -> (
    Vec<Fr>,
    SignatureParamsG1<Bls12_381>,
    KeypairG2<Bls12_381>,
    SignatureG1<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count)
        .into_iter()
        .map(|_| Fr::rand(rng))
        .collect();
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
    let sig = SignatureG1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
    sig.verify(&messages, &keypair.public_key, &params).unwrap();
    (messages, params, keypair, sig)
}

#[test]
fn bbs_plus_verifiably_encrypt_user_id() {
    // Given a BBS+ signature with one of the message as user id, verifiably encrypt the user id for an entity
    // called decryptor which can decrypt the user id but the verifier can't decrypt, only verify

    let mut rng = StdRng::seed_from_u64(0u64);
    // Prover has the BBS+ signature
    let message_count = 10;
    let (messages, sig_params, keypair, sig) = sig_setup(&mut rng, message_count);
    sig.verify(&messages, &keypair.public_key, &sig_params)
        .unwrap();

    // User id at message index `user_id_idx`
    let user_id_idx = 1;

    let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);

    // These could be same as `gens`
    let G = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
    let H = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

    let chunk_bit_size = 8;
    let chunks_count = 32;

    let circuit = BitsizeCheckCircuit {
        required_bit_size: chunk_bit_size,
        values_count: chunks_count,
        values: None,
    };
    let params = generate_crs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();

    let g_i = &params.pk.vk.gamma_abc_g1[1..];

    // Decryptor creates a keypair
    let (sk, ek, dk) = keygen(
        &mut rng,
        chunks_count,
        &gens,
        g_i,
        &params.pk.delta_g1,
        &params.gamma_g1,
    );

    // User encrypts
    let (ct, r) = encrypt(&mut rng, &messages[user_id_idx], &ek, &g_i, chunk_bit_size);
    let comm_ct = ct.last().unwrap();

    // User creates proof
    let decomposed_message = decompose(&messages[user_id_idx], chunk_bit_size)
        .into_iter()
        .map(|m| Fr::from(m as u64))
        .collect::<Vec<_>>();

    let circuit = BitsizeCheckCircuit {
        required_bit_size: 8,
        values_count: 4,
        values: Some(decomposed_message.clone()),
    };

    let start = Instant::now();
    let blinding = Fr::rand(&mut rng);

    let comm_full_message = G
        .mul(messages[user_id_idx].into_repr())
        .add(&(H.mul(blinding.into_repr())));
    let comm_chunks = commitment_to_chunks(
        &messages[user_id_idx],
        chunks_count,
        &G,
        chunk_bit_size,
        &H,
        &blinding,
    );

    let mut bases_comm_chunks = create_gs(&G, chunks_count, 1 << chunk_bit_size);
    bases_comm_chunks.push(H.clone());
    let mut wit_comm_chunks = decomposed_message.clone();
    wit_comm_chunks.push(blinding.clone());

    let mut bases_comm_ct = ek.Y.clone();
    bases_comm_ct.push(ek.P_1.clone());

    let mut wit_comm_ct = decomposed_message.clone();
    wit_comm_ct.push(r.clone());

    let mut statements = Statements::new();
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: vec![G, H],
        commitment: comm_full_message.into_affine(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_chunks.clone(),
        commitment: comm_chunks.clone(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_ct.clone(),
        commitment: comm_ct.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, user_id_idx), (1, 0)] // 0th statement's `user_id_idx`th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    for i in 0..chunks_count as usize {
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(2, i), (3, i)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
    }

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements.clone(),
        context: None,
    };

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        messages
            .clone()
            .into_iter()
            .enumerate()
            .map(|t| t)
            .collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(vec![
        messages[user_id_idx].clone(),
        blinding,
    ]));
    witnesses.add(Witness::PedersenCommitment(wit_comm_chunks));
    witnesses.add(Witness::PedersenCommitment(wit_comm_ct));

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!("Time taken to create proof {:?}", start.elapsed());

    // Verifies the proof
    let start = Instant::now();
    proof.verify(proof_spec, None).unwrap();
    println!("Time taken to verify proof {:?}", start.elapsed());

    let start = Instant::now();
    let proof = create_proof(circuit, r, &params, &ek, &mut rng).unwrap();
    println!("Time taken to create Groth16 proof {:?}", start.elapsed());

    let start = Instant::now();
    assert!(verify_ciphertext_commitment(&ct, &ek, &gens));
    let pvk = prepare_verifying_key::<Bls12_381>(&params.pk.vk);
    assert!(verify_proof(&pvk, &proof, &ct).unwrap());
    println!("Time taken to verify Groth16 proof {:?}", start.elapsed());

    // Decryptor decrypts
    let (decrypted_message, nu_) = decrypt(&ct, &sk, &dk, &g_i, chunk_bit_size);
    assert_eq!(decrypted_message, messages[user_id_idx]);
}

#[test]
fn bbs_plus_verifiably_encrypt_user_id_from_2_sigs() {
    // Given 2 BBS+ signatures with one of the message as user id, verifiably encrypt the user ids for an entity
    // called decryptor which can decrypt the user id but the verifier can't decrypt, only verify

    let mut rng = StdRng::seed_from_u64(0u64);

    // Prover has the BBS+ signatures
    let message_count_1 = 5;
    let (messages_1, sig_params_1, keypair_1, sig_1) = sig_setup(&mut rng, message_count_1);
    sig_1
        .verify(&messages_1, &keypair_1.public_key, &sig_params_1)
        .unwrap();

    let message_count_2 = 8;
    let (messages_2, sig_params_2, keypair_2, sig_2) = sig_setup(&mut rng, message_count_2);
    sig_2
        .verify(&messages_2, &keypair_2.public_key, &sig_params_2)
        .unwrap();

    // User id at message index `user_id_idx`
    let user_id_idx = 1;

    let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);

    // These could be same as `gens`
    let G = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
    let H = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

    let chunk_bit_size = 8;
    let chunks_count = 32;

    let circuit = BitsizeCheckCircuit {
        required_bit_size: chunk_bit_size,
        values_count: chunks_count,
        values: None,
    };
    let params = generate_crs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();

    let g_i = &params.pk.vk.gamma_abc_g1[1..];

    // Decryptor creates a keypair
    let (sk, ek, dk) = keygen(
        &mut rng,
        chunks_count,
        &gens,
        g_i,
        &params.pk.delta_g1,
        &params.gamma_g1,
    );

    // User encrypts 1st user id
    let (ct_1, r_1) = encrypt(
        &mut rng,
        &messages_1[user_id_idx],
        &ek,
        &g_i,
        chunk_bit_size,
    );
    let comm_ct_1 = ct_1.last().unwrap();

    // User encrypts 2nd user id
    let (ct_2, r_2) = encrypt(
        &mut rng,
        &messages_2[user_id_idx],
        &ek,
        &g_i,
        chunk_bit_size,
    );
    let comm_ct_2 = ct_2.last().unwrap();

    // User creates proof
    let decomposed_message_1 = decompose(&messages_1[user_id_idx], chunk_bit_size)
        .into_iter()
        .map(|m| Fr::from(m as u64))
        .collect::<Vec<_>>();

    // User creates proof
    let decomposed_message_2 = decompose(&messages_2[user_id_idx], chunk_bit_size)
        .into_iter()
        .map(|m| Fr::from(m as u64))
        .collect::<Vec<_>>();

    let circuit_1 = BitsizeCheckCircuit {
        required_bit_size: 8,
        values_count: 4,
        values: Some(decomposed_message_1.clone()),
    };
    let circuit_2 = BitsizeCheckCircuit {
        required_bit_size: 8,
        values_count: 4,
        values: Some(decomposed_message_2.clone()),
    };

    let start = Instant::now();
    let blinding_1 = Fr::rand(&mut rng);
    let blinding_2 = Fr::rand(&mut rng);

    let comm_full_message_1 = G
        .mul(messages_1[user_id_idx].into_repr())
        .add(&(H.mul(blinding_1.into_repr())));
    let comm_chunks_1 = commitment_to_chunks(
        &messages_1[user_id_idx],
        chunks_count,
        &G,
        chunk_bit_size,
        &H,
        &blinding_1,
    );

    let comm_full_message_2 = G
        .mul(messages_2[user_id_idx].into_repr())
        .add(&(H.mul(blinding_2.into_repr())));
    let comm_chunks_2 = commitment_to_chunks(
        &messages_2[user_id_idx],
        chunks_count,
        &G,
        chunk_bit_size,
        &H,
        &blinding_2,
    );

    let mut bases_comm_chunks = create_gs(&G, chunks_count, 1 << chunk_bit_size);
    bases_comm_chunks.push(H.clone());

    let mut wit_comm_chunks_1 = decomposed_message_1.clone();
    wit_comm_chunks_1.push(blinding_1.clone());

    let mut wit_comm_chunks_2 = decomposed_message_2.clone();
    wit_comm_chunks_2.push(blinding_2.clone());

    let mut bases_comm_ct = ek.Y.clone();
    bases_comm_ct.push(ek.P_1.clone());

    let mut wit_comm_ct_1 = decomposed_message_1.clone();
    wit_comm_ct_1.push(r_1.clone());

    let mut wit_comm_ct_2 = decomposed_message_2.clone();
    wit_comm_ct_2.push(r_2.clone());

    let mut statements = Statements::new();
    // For 1st sig
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params_1.clone(),
        public_key: keypair_1.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: vec![G, H],
        commitment: comm_full_message_1.into_affine(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_chunks.clone(),
        commitment: comm_chunks_1.clone(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_ct.clone(),
        commitment: comm_ct_1.clone(),
    }));

    // For 2nd sig
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params_2.clone(),
        public_key: keypair_2.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: vec![G, H],
        commitment: comm_full_message_2.into_affine(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_chunks.clone(),
        commitment: comm_chunks_2.clone(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_comm_ct.clone(),
        commitment: comm_ct_2.clone(),
    }));

    let mut meta_statements = MetaStatements::new();

    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, user_id_idx), (1, 0)] // 0th statement's `user_id_idx`th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    for i in 0..chunks_count as usize {
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(2, i), (3, i)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
    }

    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(4, user_id_idx), (5, 0)] // 0th statement's `user_id_idx`th witness is equal to 4th statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    for i in 0..chunks_count as usize {
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(6, i), (7, i)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
    }

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements.clone(),
        context: None,
    };

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        messages_1
            .clone()
            .into_iter()
            .enumerate()
            .map(|t| t)
            .collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(vec![
        messages_1[user_id_idx].clone(),
        blinding_1,
    ]));
    witnesses.add(Witness::PedersenCommitment(wit_comm_chunks_1));
    witnesses.add(Witness::PedersenCommitment(wit_comm_ct_1));

    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2.clone(),
        messages_2
            .clone()
            .into_iter()
            .enumerate()
            .map(|t| t)
            .collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(vec![
        messages_2[user_id_idx].clone(),
        blinding_2,
    ]));
    witnesses.add(Witness::PedersenCommitment(wit_comm_chunks_2));
    witnesses.add(Witness::PedersenCommitment(wit_comm_ct_2));

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    println!("Time taken to create proof {:?}", start.elapsed());

    // Verifies the proof
    let start = Instant::now();
    proof.verify(proof_spec, None).unwrap();
    println!("Time taken to verify proof {:?}", start.elapsed());

    let start = Instant::now();
    let proof_1 = create_proof(circuit_1, r_1, &params, &ek, &mut rng).unwrap();
    let proof_2 = create_proof(circuit_2, r_2, &params, &ek, &mut rng).unwrap();
    println!("Time taken to create Groth16 proof {:?}", start.elapsed());

    let start = Instant::now();
    assert!(verify_ciphertext_commitment(&ct_1, &ek, &gens));
    assert!(verify_ciphertext_commitment(&ct_2, &ek, &gens));
    let pvk = prepare_verifying_key::<Bls12_381>(&params.pk.vk);
    assert!(verify_proof(&pvk, &proof_1, &ct_1).unwrap());
    assert!(verify_proof(&pvk, &proof_2, &ct_2).unwrap());
    println!("Time taken to verify Groth16 proof {:?}", start.elapsed());

    // Decryptor decrypts
    let (decrypted_message_1, _) = decrypt(&ct_1, &sk, &dk, &g_i, chunk_bit_size);
    assert_eq!(decrypted_message_1, messages_1[user_id_idx]);

    let (decrypted_message_2, _) = decrypt(&ct_2, &sk, &dk, &g_i, chunk_bit_size);
    assert_eq!(decrypted_message_2, messages_2[user_id_idx]);
}
