use crate::{
    circuit::BitsizeCheckCircuit,
    commitment::ChunkedCommitment,
    encryption::Encryption,
    keygen::{PreparedDecryptionKey, PreparedEncryptionKey},
    saver_groth16::{create_proof, verify_proof},
    setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens, PreparedEncryptionGens},
    utils::decompose,
};
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_groth16::prepare_verifying_key;
use ark_std::{
    rand::{prelude::StdRng, RngCore, SeedableRng},
    UniformRand,
};
use bbs_plus::{
    setup::{KeypairG2, SignatureParamsG1},
    signature::SignatureG1,
};
use blake2::Blake2b512;
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, Statements, Witness,
        WitnessRef, Witnesses,
    },
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        ped_comm::PedersenCommitment as PedersenCommitmentStmt,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Add,
    time::Instant,
};

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
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
    sig.verify(&messages, keypair.public_key.clone(), params.clone())
        .unwrap();
    (messages, params, keypair, sig)
}

#[test]
fn bbs_plus_verifiably_encrypt_message() {
    // Given a BBS+ signature with one of the messages as user id, verifiably encrypt the user id for an entity
    // called decryptor which can decrypt the user id. But the verifier can't decrypt, only verify

    fn check(chunk_bit_size: u8) {
        let mut rng = StdRng::seed_from_u64(0u64);
        // Prover has the BBS+ signature
        let message_count = 10;
        let (messages, sig_params, keypair, sig) = sig_setup(&mut rng, message_count);
        sig.verify(&messages, keypair.public_key.clone(), sig_params.clone())
            .unwrap();

        // User id at message index `user_id_idx`
        let user_id_idx = 1;

        // Decryptor creates public parameters
        let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

        // For transformed commitment to the message
        let chunked_comm_gens =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng);

        let (snark_srs, sk, ek, dk) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
        let chunks_count = ek.supported_chunks_count().unwrap();

        // Precomputation
        let prepared_gens = PreparedEncryptionGens::from(enc_gens.clone());
        let prepared_ek = PreparedEncryptionKey::from(ek.clone());
        let prepared_dk = PreparedDecryptionKey::from(dk.clone());
        let pairing_powers = prepared_dk
            .pairing_powers_given_groth16_vk(chunk_bit_size, &snark_srs.pk.vk)
            .unwrap();

        // User encrypts
        let (ct, r) = Encryption::encrypt_given_snark_vk(
            &mut rng,
            &messages[user_id_idx],
            &ek,
            &snark_srs.pk.vk,
            chunk_bit_size,
        )
        .unwrap();

        // User creates proof
        let decomposed_message = decompose(&messages[user_id_idx], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();

        let circuit =
            BitsizeCheckCircuit::new(chunk_bit_size, None, Some(decomposed_message.clone()), true);

        let start = Instant::now();

        let blinding = Fr::rand(&mut rng);
        let comm_single = chunked_comm_gens
            .G
            .mul_bigint(messages[user_id_idx].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding.into_bigint())));
        let comm_chunks = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages[user_id_idx],
            &blinding,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let bases_comm_chunks =
            ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::commitment_key(
                &chunked_comm_gens,
                chunk_bit_size,
            );
        let mut wit_comm_chunks = decomposed_message.clone();
        wit_comm_chunks.push(blinding.clone());

        let bases_comm_ct = ek.commitment_key();
        let mut wit_comm_ct = decomposed_message.clone();
        wit_comm_ct.push(r.clone());

        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct.commitment.clone(),
        ));

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

        let proof_spec = ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);

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

        println!("Timing for {}-bit chunks", chunk_bit_size);
        let proof = Proof::new::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;
        println!("Time taken to create proof {:?}", start.elapsed());

        // Verifies the proof
        assert_eq!(comm_chunks, comm_single);
        let start = Instant::now();
        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params.clone(),
            keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct.commitment.clone(),
        ));
        let proof_spec = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof
            .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
            .unwrap();
        println!("Time taken to verify proof {:?}", start.elapsed());

        let start = Instant::now();
        let proof = create_proof(circuit, &r, &snark_srs, &ek, &mut rng).unwrap();
        println!("Time taken to create Groth16 proof {:?}", start.elapsed());

        let start = Instant::now();
        ct.verify_commitment(ek.clone(), enc_gens.clone()).unwrap();
        println!(
            "Time taken to verify ciphertext commitment {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        ct.verify_commitment(prepared_ek.clone(), prepared_gens.clone())
            .unwrap();
        println!(
            "Time taken to verify ciphertext commitment using prepared {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
        verify_proof(&pvk, &proof, &ct).unwrap();
        println!("Time taken to verify Groth16 proof {:?}", start.elapsed());

        // Decryptor decrypts
        let (decrypted_message, nu) = ct
            .decrypt_given_groth16_vk(&sk, dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
            .unwrap();
        assert_eq!(decrypted_message, messages[user_id_idx]);
        ct.verify_decryption_given_groth16_vk(
            &decrypted_message,
            &nu,
            chunk_bit_size,
            dk.clone(),
            &snark_srs.pk.vk,
            enc_gens.clone(),
        )
        .unwrap();

        let (decrypted_message, nu) = ct
            .decrypt_given_groth16_vk(&sk, prepared_dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
            .unwrap();
        assert_eq!(decrypted_message, messages[user_id_idx]);
        ct.verify_decryption_given_groth16_vk(
            &decrypted_message,
            &nu,
            chunk_bit_size,
            prepared_dk.clone(),
            &snark_srs.pk.vk,
            prepared_gens.clone(),
        )
        .unwrap();

        let (decrypted_message, nu) = ct
            .decrypt_given_groth16_vk_and_pairing_powers(
                &sk,
                prepared_dk.clone(),
                &snark_srs.pk.vk,
                chunk_bit_size,
                &pairing_powers,
            )
            .unwrap();
        assert_eq!(decrypted_message, messages[user_id_idx]);
        ct.verify_decryption_given_groth16_vk(
            &decrypted_message,
            &nu,
            chunk_bit_size,
            prepared_dk.clone(),
            &snark_srs.pk.vk,
            prepared_gens.clone(),
        )
        .unwrap();
    }

    check(4);
    check(8);
    check(16);
}

#[test]
fn bbs_plus_verifiably_encrypt_many_messages() {
    fn check(chunk_bit_size: u8) {
        let mut rng = StdRng::seed_from_u64(0u64);
        // Prover has the BBS+ signature
        let message_count = 10;
        let (messages, sig_params, keypair, sig) = sig_setup(&mut rng, message_count);
        sig.verify(&messages, keypair.public_key.clone(), sig_params.clone())
            .unwrap();

        let m_idx_1 = 1;
        let m_idx_2 = 3;
        let m_idx_3 = 7;

        // Decryptor creates public parameters
        let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

        // For transformed commitment to the message
        let chunked_comm_gens =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng);

        let (snark_srs, sk, ek, dk) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
        let chunks_count = ek.supported_chunks_count().unwrap();

        // Precomputation
        let prepared_gens = PreparedEncryptionGens::from(enc_gens.clone());
        let prepared_ek = PreparedEncryptionKey::from(ek.clone());
        let prepared_dk = PreparedDecryptionKey::from(dk.clone());
        let pairing_powers = prepared_dk
            .pairing_powers_given_groth16_vk(chunk_bit_size, &snark_srs.pk.vk)
            .unwrap();

        // User encrypts
        let (ct_1, r_1, proof_1) = Encryption::encrypt_with_proof(
            &mut rng,
            &messages[m_idx_1],
            &ek,
            &snark_srs,
            chunk_bit_size,
        )
        .unwrap();
        let (ct_2, r_2, proof_2) = Encryption::encrypt_with_proof(
            &mut rng,
            &messages[m_idx_2],
            &ek,
            &snark_srs,
            chunk_bit_size,
        )
        .unwrap();
        let (ct_3, r_3, proof_3) = Encryption::encrypt_with_proof(
            &mut rng,
            &messages[m_idx_3],
            &ek,
            &snark_srs,
            chunk_bit_size,
        )
        .unwrap();

        let decomposed_message_1 = decompose(&messages[m_idx_1], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();
        let blinding_1 = Fr::rand(&mut rng);
        let comm_single_1 = chunked_comm_gens
            .G
            .mul_bigint(messages[m_idx_1].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding_1.into_bigint())));
        let comm_chunks_1 = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages[m_idx_1],
            &blinding_1,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let decomposed_message_2 = decompose(&messages[m_idx_2], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();
        let blinding_2 = Fr::rand(&mut rng);
        let comm_single_2 = chunked_comm_gens
            .G
            .mul_bigint(messages[m_idx_2].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding_2.into_bigint())));
        let comm_chunks_2 = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages[m_idx_2],
            &blinding_2,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let decomposed_message_3 = decompose(&messages[m_idx_3], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();
        let blinding_3 = Fr::rand(&mut rng);
        let comm_single_3 = chunked_comm_gens
            .G
            .mul_bigint(messages[m_idx_3].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding_3.into_bigint())));
        let comm_chunks_3 = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages[m_idx_3],
            &blinding_3,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let bases_comm_chunks =
            ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::commitment_key(
                &chunked_comm_gens,
                chunk_bit_size,
            );
        let bases_comm_ct = ek.commitment_key();

        let mut wit_comm_chunks_1 = decomposed_message_1.clone();
        wit_comm_chunks_1.push(blinding_1.clone());
        let mut wit_comm_ct_1 = decomposed_message_1.clone();
        wit_comm_ct_1.push(r_1.clone());

        let mut wit_comm_chunks_2 = decomposed_message_2.clone();
        wit_comm_chunks_2.push(blinding_2.clone());
        let mut wit_comm_ct_2 = decomposed_message_2.clone();
        wit_comm_ct_2.push(r_2.clone());

        let mut wit_comm_chunks_3 = decomposed_message_3.clone();
        wit_comm_chunks_3.push(blinding_3.clone());
        let mut wit_comm_ct_3 = decomposed_message_3.clone();
        wit_comm_ct_3.push(r_3.clone());

        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params.clone(),
            BTreeMap::new(),
        ));

        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_1.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_1.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_1.commitment.clone(),
        ));

        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_2.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_2.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_2.commitment.clone(),
        ));

        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_3.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_3.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_3.commitment.clone(),
        ));

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, m_idx_1), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, m_idx_2), (4, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, m_idx_3), (7, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));

        for i in 0..chunks_count as usize {
            meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                vec![(2, i), (3, i)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            )));
            meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                vec![(5, i), (6, i)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            )));
            meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                vec![(8, i), (9, i)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            )));
        }

        let proof_spec = ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);

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
            messages[m_idx_1].clone(),
            blinding_1,
        ]));
        witnesses.add(Witness::PedersenCommitment(wit_comm_chunks_1));
        witnesses.add(Witness::PedersenCommitment(wit_comm_ct_1));

        witnesses.add(Witness::PedersenCommitment(vec![
            messages[m_idx_2].clone(),
            blinding_2,
        ]));
        witnesses.add(Witness::PedersenCommitment(wit_comm_chunks_2));
        witnesses.add(Witness::PedersenCommitment(wit_comm_ct_2));

        witnesses.add(Witness::PedersenCommitment(vec![
            messages[m_idx_3].clone(),
            blinding_3,
        ]));
        witnesses.add(Witness::PedersenCommitment(wit_comm_chunks_3));
        witnesses.add(Witness::PedersenCommitment(wit_comm_ct_3));

        let proof = Proof::new::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;

        // Verifies the proof
        assert_eq!(comm_chunks_1, comm_single_1);
        assert_eq!(comm_chunks_2, comm_single_2);
        assert_eq!(comm_chunks_3, comm_single_3);
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params.clone(),
            keypair.public_key.clone(),
            BTreeMap::new(),
        ));

        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_1.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_1.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_1.commitment.clone(),
        ));

        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_2.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_2.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_2.commitment.clone(),
        ));

        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_3.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_3.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_3.commitment.clone(),
        ));
        let proof_spec = ProofSpec::new(verifier_statements, meta_statements.clone(), vec![], None);
        proof
            .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
            .unwrap();

        for (ct, proof, m_idx) in vec![
            (&ct_1, &proof_1, m_idx_1),
            (&ct_2, &proof_2, m_idx_2),
            (&ct_3, &proof_3, m_idx_3),
        ] {
            ct.verify_commitment_and_proof(proof, &pvk, prepared_ek.clone(), prepared_gens.clone())
                .unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(
                    &sk,
                    prepared_dk.clone(),
                    &snark_srs.pk.vk,
                    chunk_bit_size,
                )
                .unwrap();
            assert_eq!(decrypted_message, messages[m_idx]);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                prepared_dk.clone(),
                &snark_srs.pk.vk,
                prepared_gens.clone(),
            )
            .unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(
                    &sk,
                    prepared_dk.clone(),
                    &snark_srs.pk.vk,
                    chunk_bit_size,
                )
                .unwrap();
            assert_eq!(decrypted_message, messages[m_idx]);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                prepared_dk.clone(),
                &snark_srs.pk.vk,
                prepared_gens.clone(),
            )
            .unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk_and_pairing_powers(
                    &sk,
                    prepared_dk.clone(),
                    &snark_srs.pk.vk,
                    chunk_bit_size,
                    &pairing_powers,
                )
                .unwrap();
            assert_eq!(decrypted_message, messages[m_idx]);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                prepared_dk.clone(),
                &snark_srs.pk.vk,
                prepared_gens.clone(),
            )
            .unwrap();
        }
    }
    check(4);
    check(8);
    check(16);
}

#[test]
fn bbs_plus_verifiably_encrypt_message_from_2_sigs() {
    // Given 2 BBS+ signatures with one of the message as user id, verifiably encrypt the user ids for an entity
    // called decryptor which can decrypt the user id. But the verifier can't decrypt, only verify

    fn check(chunk_bit_size: u8) {
        let mut rng = StdRng::seed_from_u64(0u64);

        // Prover has the BBS+ signatures
        let message_count_1 = 5;
        let (messages_1, sig_params_1, keypair_1, sig_1) = sig_setup(&mut rng, message_count_1);
        sig_1
            .verify(
                &messages_1,
                keypair_1.public_key.clone(),
                sig_params_1.clone(),
            )
            .unwrap();

        let message_count_2 = 8;
        let (messages_2, sig_params_2, keypair_2, sig_2) = sig_setup(&mut rng, message_count_2);
        sig_2
            .verify(
                &messages_2,
                keypair_2.public_key.clone(),
                sig_params_2.clone(),
            )
            .unwrap();

        // User id at message index `user_id_idx`
        let user_id_idx = 1;

        let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

        // For transformed commitment to the message
        let chunked_comm_gens =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng);

        let (snark_srs, sk, ek, dk) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
        let chunks_count = ek.supported_chunks_count().unwrap();

        // User encrypts 1st user id
        let (ct_1, r_1) = Encryption::encrypt_given_snark_vk(
            &mut rng,
            &messages_1[user_id_idx],
            &ek,
            &snark_srs.pk.vk,
            chunk_bit_size,
        )
        .unwrap();

        // User encrypts 2nd user id
        let (ct_2, r_2) = Encryption::encrypt_given_snark_vk(
            &mut rng,
            &messages_2[user_id_idx],
            &ek,
            &&snark_srs.pk.vk,
            chunk_bit_size,
        )
        .unwrap();

        // User creates proof
        let decomposed_message_1 = decompose(&messages_1[user_id_idx], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();

        // User creates proof
        let decomposed_message_2 = decompose(&messages_2[user_id_idx], chunk_bit_size)
            .unwrap()
            .into_iter()
            .map(|m| Fr::from(m as u64))
            .collect::<Vec<_>>();

        let circuit_1 = BitsizeCheckCircuit::new(
            chunk_bit_size,
            None,
            Some(decomposed_message_1.clone()),
            true,
        );
        let circuit_2 = BitsizeCheckCircuit::new(
            chunk_bit_size,
            None,
            Some(decomposed_message_2.clone()),
            true,
        );

        let start = Instant::now();
        let blinding_1 = Fr::rand(&mut rng);
        let blinding_2 = Fr::rand(&mut rng);

        let comm_single_1 = chunked_comm_gens
            .G
            .mul_bigint(messages_1[user_id_idx].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding_1.into_bigint())));
        let comm_chunks_1 = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages_1[user_id_idx],
            &blinding_1,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let comm_single_2 = chunked_comm_gens
            .G
            .mul_bigint(messages_2[user_id_idx].into_bigint())
            .add(&(chunked_comm_gens.H.mul_bigint(blinding_2.into_bigint())));
        let comm_chunks_2 = ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::new(
            &messages_2[user_id_idx],
            &blinding_2,
            chunk_bit_size,
            &chunked_comm_gens,
        )
        .unwrap()
        .0;

        let bases_comm_chunks =
            ChunkedCommitment::<<Bls12_381 as Pairing>::G1Affine>::commitment_key(
                &chunked_comm_gens,
                chunk_bit_size,
            );

        let mut wit_comm_chunks_1 = decomposed_message_1.clone();
        wit_comm_chunks_1.push(blinding_1.clone());

        let mut wit_comm_chunks_2 = decomposed_message_2.clone();
        wit_comm_chunks_2.push(blinding_2.clone());

        let bases_comm_ct = ek.commitment_key();

        let mut wit_comm_ct_1 = decomposed_message_1.clone();
        wit_comm_ct_1.push(r_1.clone());

        let mut wit_comm_ct_2 = decomposed_message_2.clone();
        wit_comm_ct_2.push(r_2.clone());

        let mut prover_statements = Statements::new();
        // For 1st sig
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params_1.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_1.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_1.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_1.commitment.clone(),
        ));

        // For 2nd sig
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params_2.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_2.into_affine(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_2.clone(),
        ));
        prover_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_2.commitment.clone(),
        ));

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

        let proof_spec = ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);

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

        let proof = Proof::new::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;
        println!("Time taken to create proof {:?}", start.elapsed());

        // Verifies the proof
        assert_eq!(comm_chunks_1, comm_single_1);
        assert_eq!(comm_chunks_2, comm_single_2);
        let start = Instant::now();
        let mut verifier_statements = Statements::new();
        // For 1st sig
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params_1.clone(),
            keypair_1.public_key.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_1.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_1.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_1.commitment.clone(),
        ));

        // For 2nd sig
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params_2.clone(),
            keypair_2.public_key.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![chunked_comm_gens.G, chunked_comm_gens.H],
            comm_single_2.into_affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_chunks.clone(),
            comm_chunks_2.clone(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            bases_comm_ct.clone(),
            ct_2.commitment.clone(),
        ));
        let proof_spec = ProofSpec::new(verifier_statements, meta_statements, vec![], None);
        proof
            .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
            .unwrap();
        println!("Time taken to verify proof {:?}", start.elapsed());

        let start = Instant::now();
        let proof_1 = create_proof(circuit_1, &r_1, &snark_srs, &ek, &mut rng).unwrap();
        let proof_2 = create_proof(circuit_2, &r_2, &snark_srs, &ek, &mut rng).unwrap();
        println!(
            "Time taken to create 2 Groth16 proofs {:?}",
            start.elapsed()
        );

        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

        let start = Instant::now();
        ct_1.verify_commitment(ek.clone(), enc_gens.clone())
            .unwrap();
        ct_2.verify_commitment(ek.clone(), enc_gens.clone())
            .unwrap();
        println!(
            "Time taken to verify ciphertext commitment {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        verify_proof(&pvk, &proof_1, &ct_1).unwrap();
        verify_proof(&pvk, &proof_2, &ct_2).unwrap();
        println!(
            "Time taken to verify 2 Groth16 proofs {:?}",
            start.elapsed()
        );

        // Decryptor decrypts
        let (decrypted_message_1, nu_1) = ct_1
            .decrypt_given_groth16_vk(&sk, dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
            .unwrap();
        assert_eq!(decrypted_message_1, messages_1[user_id_idx]);

        let (decrypted_message_2, nu_2) = ct_2
            .decrypt_given_groth16_vk(&sk, dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
            .unwrap();
        assert_eq!(decrypted_message_2, messages_2[user_id_idx]);

        ct_1.verify_decryption_given_groth16_vk(
            &decrypted_message_1,
            &nu_1,
            chunk_bit_size,
            dk.clone(),
            &snark_srs.pk.vk,
            enc_gens.clone(),
        )
        .unwrap();

        ct_2.verify_decryption_given_groth16_vk(
            &decrypted_message_2,
            &nu_2,
            chunk_bit_size,
            dk.clone(),
            &snark_srs.pk.vk,
            enc_gens.clone(),
        )
        .unwrap();
    }

    check(4);
    check(8);
    check(16);
}
