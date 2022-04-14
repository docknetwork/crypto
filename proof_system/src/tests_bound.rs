use crate::prelude::bound_check::generate_snark_srs_bound_check;
use crate::prelude::{
    EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, Statements, Witness,
    WitnessRef, Witnesses,
};
use crate::statement::{
    BoundCheckLegoGroth16 as BoundCheckStmt, PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    Saver as SaverStmt,
};
use crate::test_utils::sig_setup_given_messages;
use crate::tests_saver::decrypt_and_verify;
use crate::witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit;
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::PairingEngine;
use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::prelude::StdRng;
use ark_std::rand::SeedableRng;
use blake2::Blake2b;
use saver::setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Blake2b>;

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message_and_verifiable_encryption() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let msgs = (0..msg_count)
        .into_iter()
        .map(|i| Fr::from(101u64 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters for bound check circuit. Ideally this should be
    // done only once per verifier and can be published by the verifier for any proofs submitted to him
    let bound_snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Decryptor creates public parameters
    let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    let chunk_bit_size = 8;
    // For transformed commitment to the message
    let chunked_comm_gens =
        ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(&mut rng);
    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx].clone();

    // Message with index `enc_msg_idx` is verifiably encrypted and its bounds are checked as well
    let enc_msg_idx = 3;
    let enc_msg = msgs[enc_msg_idx].clone();

    let min = msg - Fr::from(50u64);
    let max = msg + Fr::from(100u64);

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(BoundCheckStmt::new_as_statement(min, max, bound_snark_pk.clone()).unwrap());
    statements.add(BoundCheckStmt::new_as_statement(min, max, bound_snark_pk.clone()).unwrap());
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
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, enc_msg_idx), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        None,
    );
    assert!(proof_spec.is_valid());
    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));
    witnesses.add(Witness::BoundCheckLegoGroth16(enc_msg));
    witnesses.add(Witness::Saver(enc_msg));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
    test_serialization!(ProofG1, proof);

    proof.clone().verify(proof_spec.clone(), None).unwrap();

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
