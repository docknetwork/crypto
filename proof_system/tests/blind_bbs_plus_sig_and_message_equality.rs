// cargo-fmt makes this much harder to read
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::prelude::SignatureG1;
use blake2::Blake2b512;
use proof_system::{
    prelude::{EqualWitnesses, MetaStatements, Proof, ProofSystemError, WitnessRef, Witnesses},
    proof_spec::ProofSpec,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        Statements,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use test_utils::bbs::*;

#[test]
fn blind_bbs_plus_sig_and_message_equality() {
    // This test
    // - creates two issuers/signers
    // - creates one signature for each signer, including a common attribute, blinded (by the holder) for each signature
    // - it then unblinds the signatures and
    // - creates a proof of knowledge of both signatures and equality of the blinded attributes
    // It tests that
    // - when the blinded values are   equal, proof creation and verification both succeeds
    // - when the blinded values are unequal, either proof creation fails, or verification of the created proof fails
    //
    // This test was motivated by the fact that the existing blinding tests
    //   proof_system/tests/bbs_plus_and_accumulators.rs
    //     requesting_partially_blind_bbs_plus_sig
    //     requesting_partially_blind_bbs_sig
    // do not use the unblinded/blind signature in proofs.  Hence, this test.

    blind_bbs_plus_sig_and_message_equality_aux(true).unwrap();
    // NOTE: current behaviour is that proof creation succeeds and verification of the created proof yields:
    // Err(ProofSystemError::BBSPlusProofContributionFailed(1,BBSPlusError::SecondSchnorrVerificationFailed))
    // but this test requires only that proof creation and verification do not BOTH succeed
    assert!(blind_bbs_plus_sig_and_message_equality_aux(false).is_err());
}

#[cfg_attr(rustfmt, rustfmt_skip)]
fn blind_bbs_plus_sig_and_message_equality_aux(eq : bool) -> Result<(), ProofSystemError> {
    let mut rng = StdRng::seed_from_u64(0u64);
    let total_msg_count = 4;
    let (    msgs_1, sig_params_1, sig_keypair_1, _) = bbs_plus_sig_setup(&mut rng, total_msg_count as u32);
    let (mut msgs_2, sig_params_2, sig_keypair_2, _) = bbs_plus_sig_setup(&mut rng, total_msg_count as u32);

    let blinding_1 = Fr::rand(&mut rng);
    let committed_messages_1   = BTreeMap::from([                (1, &msgs_1[1])]); // aka blinded messages
    let uncommitted_messages_1 = BTreeMap::from([(0, &msgs_1[0]),                  (2, &msgs_1[2]), (3, &msgs_1[3])]);
    let commitment_1 = sig_params_1.commit_to_messages(committed_messages_1.clone(), &blinding_1).unwrap();

    if eq {
        // make the values in the blinded attribute of the two credentials the same
        msgs_2[1] = msgs_1[1];
    }
    let blinding_2 = Fr::rand(&mut rng);
    let committed_messages_2   = BTreeMap::from([                (1, &msgs_2[1])]); // aka blinded messages
    let uncommitted_messages_2 = BTreeMap::from([(0, &msgs_2[0]),                  (2, &msgs_2[2]), (3, &msgs_2[3])]);
    let commitment_2 = sig_params_2.commit_to_messages(committed_messages_2.clone(), &blinding_2).unwrap();

    let blinded_sig_1 = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment_1,
        uncommitted_messages_1.clone(),
        &sig_keypair_1.secret_key,
        &sig_params_1,
    ).unwrap();
    let blinded_sig_2 = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment_2,
        uncommitted_messages_2.clone(),
        &sig_keypair_2.secret_key,
        &sig_params_2,
    ).unwrap();

    let sig_1 = blinded_sig_1.clone().unblind(&blinding_1);
    sig_1.verify(&msgs_1, sig_keypair_1.public_key.clone(), sig_params_1.clone()).unwrap();
    let sig_2 = blinded_sig_2.clone().unblind(&blinding_2);
    sig_2.verify(&msgs_2, sig_keypair_2.public_key.clone(), sig_params_2.clone()).unwrap();

    // --------------------------------------------------
    // Prover

    let mut prover_statements = Statements::<Bls12_381>::new();
    let revealed_messages_1 = uncommitted_messages_1.into_iter()
        .map(|(i, m)| (i, *m)) // this is because new_with_committed_messages takes
                               // BTreeMap<usize, &E::ScalarField>
                               // but new_statement_from_params takes
                               // BTreeMap<usize, E::ScalarField>,
        .collect::<BTreeMap<_, _>>();
    prover_statements.add(
        PoKSignatureBBSG1ProverStmt::new_statement_from_params(sig_params_1.clone(), revealed_messages_1.clone()));
    let revealed_messages_2 = uncommitted_messages_2.into_iter()
        .map(|(i, m)| (i, *m))
        .collect::<BTreeMap<_, _>>();
    prover_statements.add(
        PoKSignatureBBSG1ProverStmt::new_statement_from_params(sig_params_2.clone(), revealed_messages_2.clone()));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (1, 1)] // 0th statement's 1st witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let context = Some(b"test_context".to_vec());
    let prover_proof_spec = ProofSpec::new(prover_statements.clone(), meta_statements.clone(), vec![], context.clone());
    prover_proof_spec.validate().unwrap();

    let mut witnesses = Witnesses::new();
    let unrevealed_messages_1 = committed_messages_1.into_iter()
        .map(|(i, m)| (i, *m))
        .collect::<BTreeMap<_, _>>();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(sig_1, unrevealed_messages_1.clone()));
    let unrevealed_messages_2 = committed_messages_2.into_iter()
        .map(|(i, m)| (i, *m))
        .collect::<BTreeMap<_, _>>();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(sig_2, unrevealed_messages_2.clone()));

    // Proof

    let nonce = Some(b"test nonce".to_vec());
    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        prover_proof_spec,
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    ).unwrap().0;

    // --------------------------------------------------
    // Verifier

    let mut verifier_statements = Statements::<Bls12_381>::new();
    verifier_statements.add(
        PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params_1, sig_keypair_1.public_key.clone(), revealed_messages_1));
    verifier_statements.add(
        PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params_2, sig_keypair_2.public_key.clone(), revealed_messages_2));

    let verifier_proof_spec = ProofSpec::new(verifier_statements.clone(), meta_statements, vec![], context);
    proof.verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, nonce, Default::default())
}
