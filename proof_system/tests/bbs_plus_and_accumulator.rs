use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{rand::prelude::StdRng, rand::SeedableRng, UniformRand};
use bbs_plus::prelude::SignatureG1;
use blake2::Blake2b512;
use std::time::Instant;
use vb_accumulator::prelude::{Accumulator, MembershipProvingKey, NonMembershipProvingKey};

use proof_system::prelude::{
    EqualWitnesses, MetaStatements, VerifierConfig, Witness, WitnessRef, Witnesses,
};
use proof_system::proof_spec::ProofSpec;
use proof_system::setup_params::SetupParams;
use proof_system::statement::Statements;
use proof_system::statement::{
    accumulator::AccumulatorMembership as AccumulatorMembershipStmt,
    accumulator::AccumulatorNonMembership as AccumulatorNonMembershipStmt,
    bbs_plus::PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    ped_comm::PedersenCommitment as PedersenCommitmentStmt,
};
use proof_system::witness::{
    Membership as MembershipWit, NonMembership as NonMembershipWit,
    PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use test_utils::{accumulators::*, bbs_plus::*};
use test_utils::{test_serialization, Fr, ProofG1};

#[test]
fn pok_of_3_bbs_plus_sig_and_message_equality() {
    // Prove knowledge of 3 BBS+ signatures and 3 of the messages are same among them.
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 6;
    let (msgs_1, params_1, keypair_1, sig_1) = sig_setup(&mut rng, msg_count_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let (mut msgs_2, params_2, keypair_2, _) = sig_setup(&mut rng, msg_count_2);

    // 3rd BBS+ sig
    let msg_count_3 = 12;
    let (mut msgs_3, params_3, keypair_3, _) = sig_setup(&mut rng, msg_count_3);

    // Make 3 messages same
    msgs_2[9] = msgs_1[5].clone();
    msgs_3[9] = msgs_1[5].clone();
    msgs_2[8] = msgs_1[4].clone();
    msgs_3[8] = msgs_1[4].clone();
    msgs_2[7] = msgs_1[3].clone();
    msgs_3[7] = msgs_1[3].clone();

    msgs_3[5] = msgs_3[7].clone();

    let sig_2 =
        SignatureG1::<Bls12_381>::new(&mut rng, &msgs_2, &keypair_2.secret_key, &params_2).unwrap();
    sig_2
        .verify(&msgs_2, &keypair_2.public_key, &params_2)
        .unwrap();

    let sig_3 =
        SignatureG1::<Bls12_381>::new(&mut rng, &msgs_3, &keypair_3.secret_key, &params_3).unwrap();
    sig_3
        .verify(&msgs_3, &keypair_3.public_key, &params_3)
        .unwrap();

    // Prepare revealed messages for the proof of knowledge of 1st signature
    let mut revealed_indices_1 = BTreeSet::new();
    revealed_indices_1.insert(0);
    revealed_indices_1.insert(2);

    let mut revealed_msgs_1 = BTreeMap::new();
    let mut unrevealed_msgs_1 = BTreeMap::new();
    for i in 0..msg_count_1 {
        if revealed_indices_1.contains(&i) {
            revealed_msgs_1.insert(i, msgs_1[i]);
        } else {
            unrevealed_msgs_1.insert(i, msgs_1[i]);
        }
    }

    // Prepare revealed messages for the proof of knowledge of 2nd signature
    let mut revealed_indices_2 = BTreeSet::new();
    revealed_indices_2.insert(1);
    revealed_indices_2.insert(3);
    revealed_indices_2.insert(5);

    let mut revealed_msgs_2 = BTreeMap::new();
    let mut unrevealed_msgs_2 = BTreeMap::new();
    for i in 0..msg_count_2 {
        if revealed_indices_2.contains(&i) {
            revealed_msgs_2.insert(i, msgs_2[i]);
        } else {
            unrevealed_msgs_2.insert(i, msgs_2[i]);
        }
    }

    let unrevealed_msgs_3 = msgs_3
        .iter()
        .enumerate()
        .map(|(i, m)| (i, m.clone()))
        .collect::<BTreeMap<_, _>>();

    // Since proving knowledge of 3 BBS+ signatures, add 3 statements, all of the same type though.
    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        revealed_msgs_1.clone(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_2.clone(),
        keypair_2.public_key.clone(),
        revealed_msgs_2.clone(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_3.clone(),
        keypair_3.public_key.clone(),
        BTreeMap::new(),
    ));

    // Since 3 of the messages are being proven equal, add a `MetaStatement` describing that
    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 5), (1, 9), (2, 9)] // 0th statement's 5th witness is equal to 1st statement's 9th witness and 2nd statement's 9th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 4), (1, 8), (2, 8)] // 0th statement's 4th witness is equal to 1st statement's 8th witness and 2nd statement's 8th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 3), (1, 7), (2, 7)] // 0th statement's 3rd witness is equal to 1st statement's 7th witness and 2nd statement's 7th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(2, 5), (2, 7)] // 0th statement's 1th witness is equal to 2nd statement's 9th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    // Create a proof spec, this is shared between prover and verifier
    // Context must be known to both prover and verifier
    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    // Prover now creates/loads it witnesses corresponding to the proof spec
    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        unrevealed_msgs_1.clone(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2.clone(),
        unrevealed_msgs_2.clone(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_3.clone(),
        unrevealed_msgs_3.clone(),
    ));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    // Prover now creates the proof using the proof spec and witnesses. This will be sent to the verifier
    let nonce = Some(b"some nonce".to_vec());
    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses,
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    // Proof with no nonce shouldn't verify
    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec.clone(), None, Default::default())
        .is_err());
    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .is_err());

    // Proof with invalid nonce shouldn't verify
    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            Some(b"random...".to_vec()),
            Default::default()
        )
        .is_err());
    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            Some(b"random...".to_vec()),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .is_err());

    test_serialization!(ProofG1, proof);

    // Verifier verifies the proof
    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default(),
        )
        .unwrap();
    println!(
        "Time to verify proof with 3 BBS+ signatures: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            nonce,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!(
        "Time to verify proof with 3 BBS+ signatures with randomized pairing check: {:?}",
        start.elapsed()
    );
}

#[test]
fn pok_of_bbs_plus_sig_and_accumulator() {
    // Prove knowledge of BBS+ signature and one of the message's membership and non-membership in accumulators
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 6;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    let max = 10;
    let (pos_accum_params, pos_accum_keypair, mut pos_accumulator, mut pos_state) =
        setup_positive_accum(&mut rng);
    let mem_prk = MembershipProvingKey::generate_using_rng(&mut rng);

    // Message with index `accum_member_1_idx` is added in the positive accumulator
    let accum_member_1_idx = 1;
    let accum_member_1 = msgs[accum_member_1_idx].clone();

    pos_accumulator = pos_accumulator
        .add(
            accum_member_1.clone(),
            &pos_accum_keypair.secret_key,
            &mut pos_state,
        )
        .unwrap();
    let mem_1_wit = pos_accumulator
        .get_membership_witness(&accum_member_1, &pos_accum_keypair.secret_key, &pos_state)
        .unwrap();
    assert!(pos_accumulator.verify_membership(
        &accum_member_1,
        &mem_1_wit,
        &pos_accum_keypair.public_key,
        &pos_accum_params
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        pos_accum_params.clone(),
        pos_accum_keypair.public_key.clone(),
        mem_prk.clone(),
        pos_accumulator.value().clone(),
    ));

    // Create meta statement describing that message in the signature at index `accum_member_1_idx` is
    // same as the accumulator member
    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![
            (0, accum_member_1_idx),
            (1, 0), // Since accumulator (non)membership has only one (for applications) which is the (non)member, that witness is at index 0.
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(MembershipWit::new_as_witness(
        accum_member_1.clone(),
        mem_1_wit.clone(),
    ));
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test-nonce".to_vec());

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default(),
        )
        .unwrap();
    println!(
        "Time to verify proof with a BBS+ signature and positive accumulator membership: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and positive accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Wrong witness reference fails to verify
    let mut meta_statements_incorrect = MetaStatements::new();
    meta_statements_incorrect.add_witness_equality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let proof_spec_incorrect = ProofSpec::new(
        statements.clone(),
        meta_statements_incorrect,
        vec![],
        context.clone(),
    );
    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_incorrect.clone(),
        witnesses,
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec_incorrect.clone(),
            nonce.clone(),
            Default::default()
        )
        .is_err());
    assert!(proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec_incorrect.clone(),
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .is_err());

    // Non-member fails to verify
    let mut witnesses_incorrect = Witnesses::new();
    witnesses_incorrect.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    }));
    witnesses_incorrect.add(Witness::AccumulatorMembership(MembershipWit {
        element: msgs[2].clone(), // 2nd message from BBS+ sig in accumulator
        witness: mem_1_wit.clone(),
    }));
    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![
            (0, 2), // 2nd message from BBS+ sig in accumulator
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    ));
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();
    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses_incorrect,
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;
    assert!(proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default()
        )
        .is_err());
    assert!(proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .is_err());

    // Prove knowledge of signature and membership of message with index `accum_member_2_idx` in universal accumulator
    let accum_member_2_idx = 2;
    let accum_member_2 = msgs[accum_member_2_idx].clone();
    let (uni_accum_params, uni_accum_keypair, mut uni_accumulator, initial_elements, mut uni_state) =
        setup_universal_accum(&mut rng, max);
    let non_mem_prk = NonMembershipProvingKey::generate_using_rng(&mut rng);
    let derived_mem_prk = non_mem_prk.derive_membership_proving_key();

    uni_accumulator = uni_accumulator
        .add(
            accum_member_2.clone(),
            &uni_accum_keypair.secret_key,
            &initial_elements,
            &mut uni_state,
        )
        .unwrap();
    let mem_2_wit = uni_accumulator
        .get_membership_witness(&accum_member_2, &uni_accum_keypair.secret_key, &uni_state)
        .unwrap();
    assert!(uni_accumulator.verify_membership(
        &accum_member_2,
        &mem_2_wit,
        &uni_accum_keypair.public_key,
        &uni_accum_params
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        uni_accum_params.clone(),
        uni_accum_keypair.public_key.clone(),
        derived_mem_prk.clone(),
        uni_accumulator.value().clone(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    }));
    witnesses.add(Witness::AccumulatorMembership(MembershipWit {
        element: accum_member_2.clone(),
        witness: mem_2_wit.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_2_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default(),
        )
        .unwrap();
    println!(
        "Time to verify proof with a BBS+ signature and universal accumulator membership: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and universal accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and non-membership of message with index `accum_non_member_idx` in universal accumulator
    let accum_non_member_idx = 3;
    let accum_non_member = msgs[accum_non_member_idx].clone();
    let non_mem_wit = uni_accumulator
        .get_non_membership_witness(
            &accum_non_member,
            &uni_accum_keypair.secret_key,
            &uni_state,
            &uni_accum_params,
        )
        .unwrap();
    assert!(uni_accumulator.verify_non_membership(
        &accum_non_member,
        &non_mem_wit,
        &uni_accum_keypair.public_key,
        &uni_accum_params
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorNonMembershipStmt::new_statement_from_params(
        uni_accum_params.clone(),
        uni_accum_keypair.public_key.clone(),
        non_mem_prk.clone(),
        uni_accumulator.value().clone(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    }));
    witnesses.add(Witness::AccumulatorNonMembership(NonMembershipWit {
        element: accum_non_member.clone(),
        witness: non_mem_wit.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_non_member_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default(),
        )
        .unwrap();
    println!(
        "Time to verify proof with a BBS+ signature and universal accumulator non-membership: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and universal accumulator non-membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and
    // - membership of message with index `accum_member_1_idx` in positive accumulator
    // - membership of message with index `accum_member_2_idx` in universal accumulator
    // - non-membership of message with index `accum_non_member_idx` in universal accumulator
    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::VbAccumulatorParams(uni_accum_params));
    all_setup_params.push(SetupParams::VbAccumulatorPublicKey(
        uni_accum_keypair.public_key.clone(),
    ));
    all_setup_params.push(SetupParams::VbAccumulatorMemProvingKey(derived_mem_prk));
    all_setup_params.push(SetupParams::VbAccumulatorNonMemProvingKey(non_mem_prk));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        pos_accum_params.clone(),
        pos_accum_keypair.public_key.clone(),
        mem_prk.clone(),
        pos_accumulator.value().clone(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params_ref(
        0,
        1,
        2,
        uni_accumulator.value().clone(),
    ));
    statements.add(AccumulatorNonMembershipStmt::new_statement_from_params_ref(
        0,
        1,
        3,
        uni_accumulator.value().clone(),
    ));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_1_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_2_idx), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_non_member_idx), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    }));
    witnesses.add(Witness::AccumulatorMembership(MembershipWit {
        element: accum_member_1.clone(),
        witness: mem_1_wit.clone(),
    }));
    witnesses.add(Witness::AccumulatorMembership(MembershipWit {
        element: accum_member_2.clone(),
        witness: mem_2_wit.clone(),
    }));
    witnesses.add(Witness::AccumulatorNonMembership(NonMembershipWit {
        element: accum_non_member.clone(),
        witness: non_mem_wit.clone(),
    }));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements,
        all_setup_params,
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec.clone(),
            nonce.clone(),
            Default::default(),
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and 3 accumulator membership and non-membership checks: {:?}", start.elapsed());

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            nonce,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and 3 accumulator membership and non-membership checks with randomized pairing check: {:?}", start.elapsed());
}

#[test]
fn pok_of_knowledge_in_pedersen_commitment_and_bbs_plus_sig() {
    // Prove knowledge of commitment in Pedersen commitments and equality with a BBS+ signature.
    // Useful when requesting a blind signature and proving knowledge of a signature along with
    // some the equality of certain messages in the commitment and signature

    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 6;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    let bases = (0..5)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let mut scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    // Make 2 of the messages in the commitment same as in the signature
    scalars[1] = msgs[0].clone();
    scalars[4] = msgs[5].clone();
    let commitment = G1Projective::msm_unchecked(&bases, &scalars).into_affine();

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases.clone(),
        commitment.clone(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 0), (1, 1)] // 0th statement's 0th witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 5), (1, 4)] // 0th statement's 5th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(scalars.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, nonce.clone(), Default::default())
        .unwrap();

    // Wrong message equality should fail to verify
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, 3), (1, 0)] // this equality doesn't hold
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements_wrong.add_witness_equality(EqualWitnesses(
        vec![(0, 5), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let proof_spec_invalid = ProofSpec::new(
        statements.clone(),
        meta_statements_wrong,
        vec![],
        context.clone(),
    );

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_invalid.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    assert!(proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_invalid, nonce, Default::default())
        .is_err());
}

#[test]
fn requesting_partially_blind_bbs_plus_sig() {
    // Request a partially blind signature by first proving knowledge of values in a Pedersen commitment. The
    // requester then unblinds the signature and verifies it.

    let mut rng = StdRng::seed_from_u64(0u64);

    // The total number of messages in the signature
    let total_msg_count = 10;

    // Setup params and messages
    let (msgs, sig_params, sig_keypair, _) = sig_setup(&mut rng, total_msg_count);

    // Message indices hidden from signer. Here signer does not know msgs[0], msgs[4] and msgs[6]
    let committed_indices = vec![0, 4, 6].into_iter().collect::<BTreeSet<usize>>();

    // Requester commits messages msgs[0], msgs[4] and msgs[6] as `sig_params.h_0 * blinding + params.h[0] * msgs[0] + params.h[4] * msgs[4] + params.h[6] * msgs[6]`
    let blinding = Fr::rand(&mut rng);
    let committed_messages = committed_indices
        .iter()
        .map(|i| (*i, &msgs[*i]))
        .collect::<BTreeMap<_, _>>();
    let commitment = sig_params
        .commit_to_messages(committed_messages, &blinding)
        .unwrap();

    // Requester proves knowledge of committed messages
    let mut statements = Statements::new();
    let mut bases = vec![sig_params.h_0.clone()];
    let mut committed_msgs = vec![blinding.clone()];
    for i in committed_indices.iter() {
        bases.push(sig_params.h[*i].clone());
        committed_msgs.push(msgs[*i].clone());
    }
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases.clone(),
        commitment.clone(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(
        statements.clone(),
        MetaStatements::new(),
        vec![],
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(committed_msgs));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(ProofG1, proof);

    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, nonce, Default::default())
        .unwrap();

    // Now requester picks the messages he is revealing to the signer and prepares `uncommitted_messages`
    // to request the blind signature
    let uncommitted_messages = (0..total_msg_count)
        .filter(|i| !committed_indices.contains(i))
        .map(|i| (i, &msgs[i]))
        .collect::<BTreeMap<_, _>>();

    // Signer creates the blind signature using the commitment
    let blinded_sig = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment,
        uncommitted_messages,
        &sig_keypair.secret_key,
        &sig_params,
    )
    .unwrap();

    let sig = blinded_sig.unblind(&blinding);
    sig.verify(&msgs, &sig_keypair.public_key, &sig_params)
        .unwrap();
}

#[test]
fn proof_spec_modification() {
    // Prover modifies the proof spec like removing meta-statements or statements but proof verification should detect that

    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st BBS+ sig
    let msg_count_1 = 6;
    let (msgs_1, params_1, keypair_1, sig_1) = sig_setup(&mut rng, msg_count_1);

    // 2nd BBS+ sig
    let msg_count_2 = 10;
    let (mut msgs_2, params_2, keypair_2, _) = sig_setup(&mut rng, msg_count_2);

    msgs_2[9] = msgs_1[5].clone();

    let sig_2 =
        SignatureG1::<Bls12_381>::new(&mut rng, &msgs_2, &keypair_2.secret_key, &params_2).unwrap();
    sig_2
        .verify(&msgs_2, &keypair_2.public_key, &params_2)
        .unwrap();

    let mut statements = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_2.clone(),
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let invalid_eq_wit = EqualWitnesses(vec![(0, 1)].into_iter().collect::<BTreeSet<WitnessRef>>());
    assert!(!invalid_eq_wit.is_valid());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(invalid_eq_wit);

    let invalid_proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], None);
    assert!(invalid_proof_spec.validate().is_err());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        msgs_1
            .clone()
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2.clone(),
        msgs_2
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));

    assert!(ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default()
    )
    .is_err());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 5), (2, 4)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let invalid_proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], None);
    assert!(ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default()
    )
    .is_err());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, 8), (1, 4)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let invalid_proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], None);
    assert!(ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default()
    )
    .is_err());

    // Verifier creates proof spec with meta statements, prover modifies it to remove meta-statement
    let valid_eq_wit = EqualWitnesses(
        vec![(0, 5), (1, 9)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(valid_eq_wit);

    // Verifier's created proof spec
    let orig_proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], None);

    // Prover's modified proof spec
    let modified_proof_spec =
        ProofSpec::new(statements.clone(), MetaStatements::new(), vec![], None);

    // Proof created using modified proof spec wont be a valid
    let invalid_proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        modified_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    // Above proof is valid if verified using the modified proof spec but not with the original proof spec
    invalid_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            modified_proof_spec.clone(),
            None,
            Default::default(),
        )
        .unwrap();
    assert!(invalid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .is_err());

    // Proof created using original proof spec will be valid
    let valid_proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        orig_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;
    valid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .unwrap();

    // Verifier creates proof spec with 2 statements, prover modifies it to remove a statement
    let orig_proof_spec = ProofSpec::new(statements.clone(), MetaStatements::new(), vec![], None);

    // Prover's modified proof spec
    let mut only_1_statement = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    only_1_statement.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    let modified_proof_spec = ProofSpec::new(
        only_1_statement.clone(),
        MetaStatements::new(),
        vec![],
        None,
    );

    let mut only_1_witness = Witnesses::new();
    only_1_witness.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        msgs_1
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));

    // Proof created using modified proof spec wont be a valid
    let invalid_proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        modified_proof_spec.clone(),
        only_1_witness.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    // Above proof is valid if verified using the modified proof spec but not with the original proof spec
    invalid_proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            modified_proof_spec.clone(),
            None,
            Default::default(),
        )
        .unwrap();
    assert!(invalid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .is_err());

    // Proof created using original proof spec will be valid
    let valid_proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        orig_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;
    valid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .unwrap();
}

#[test]
fn verifier_local_linkability() {
    // A verifier wants to attach a unique identifier to a prover without either learning anything unintended (by prover)
    // from the prover's signature nor can that unique identifier be used by other verifiers to identify the prover,
    // eg. a seller (as a verifier) should be able to identify repeat customers (prover) by using a unique identifier
    // but he should not be able to share that unique identifier with other sellers using their own identifier for that prover.
    // This is done by making the prover go through a one-time registration process with the verifier by creating a
    // Pedersen commitment to some value in the signature(s) which the verifier persists, lets call it registration commitment.
    // At each subsequent proof, the prover resends the commitment with the proof that commitment contains message
    // from the the signature (prover had persisted commitment and randomness) and the verifier checks that the
    // commitment is same as the one during registration. The registration commitment serves as an identifier.

    // Following shows a prover interacting with 2 different verifiers and creating and using 2 different registration commitments, 1 at each verifier

    let mut rng = StdRng::seed_from_u64(0u64);

    // Prover got the signature
    let msg_count = 5;
    let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

    // Verifier 1 wants a commitment to prover message at index 1. Eg, index 1 is the SSN of a citizen
    // Prover creates commitment for verifier 1 using group generators `gens_1`
    let gens_1 = vec![
        G1Projective::rand(&mut rng).into_affine(),
        G1Projective::rand(&mut rng).into_affine(),
    ];
    let blinding_1 = Fr::rand(&mut rng);

    // This is the registration commitment of the prover for verifier 1
    let reg_commit_1 =
        G1Projective::msm_bigint(&gens_1, &[msgs[1].into_bigint(), blinding_1.into_bigint()])
            .into_affine();

    // The prover must persist `blinding_1` and `commitment_1` as long as he ever wants to interact with verifier 1.

    // Verifier 2 also wants a commitment to prover message at index 1
    // Prover creates commitment for verifier 2 using group generators `gens_2`
    let gens_2 = vec![
        G1Projective::rand(&mut rng).into_affine(),
        G1Projective::rand(&mut rng).into_affine(),
    ];
    let blinding_2 = Fr::rand(&mut rng);

    // This is the registration commitment of the prover for verifier 2
    let reg_commit_2 =
        G1Projective::msm_bigint(&gens_2, &[msgs[1].into_bigint(), blinding_2.into_bigint()])
            .into_affine();

    // The prover must persist `blinding_2` and `commitment_2` as long as he ever wants to interact with verifier 2.

    // The commitments are different for both verifiers for the same message
    assert_ne!(reg_commit_1, reg_commit_2);

    // Prover proves to verifier 1
    let mut statements_1 = Statements::new();
    statements_1.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements_1.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_1.clone(),
        reg_commit_1.clone(),
    ));

    let mut meta_statements_1 = MetaStatements::new();
    meta_statements_1.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let context = Some(b"For verifier 1".to_vec());
    let proof_spec_1 = ProofSpec::new(
        statements_1.clone(),
        meta_statements_1.clone(),
        vec![],
        context.clone(),
    );
    proof_spec_1.validate().unwrap();

    let mut witnesses_1 = Witnesses::new();
    witnesses_1.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_1.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_1.clone(),
    ]));

    let proof_1 = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_1.clone(),
        witnesses_1.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    proof_1
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_1, None, Default::default())
        .unwrap();

    // Prover proves to verifier 2
    let mut statements_2 = Statements::new();
    statements_2.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements_2.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_2.clone(),
        reg_commit_2.clone(),
    ));

    let mut meta_statements_2 = MetaStatements::new();
    meta_statements_2.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let context = Some(b"For verifier 2".to_vec());
    let proof_spec_2 = ProofSpec::new(
        statements_2.clone(),
        meta_statements_2.clone(),
        vec![],
        context.clone(),
    );
    proof_spec_2.validate().unwrap();

    let mut witnesses_2 = Witnesses::new();
    witnesses_2.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_2.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_2.clone(),
    ]));

    let proof_2 = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_2.clone(),
        witnesses_2.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    proof_2
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_2, None, Default::default())
        .unwrap();

    // Prover again proves to verifier 1, this time something different like revealing a message but still uses his registration
    // commitment corresponding to verifier 1.
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(3);

    let mut revealed_msgs = BTreeMap::new();
    let mut unrevealed_msgs = BTreeMap::new();
    for i in 0..msg_count {
        if revealed_indices.contains(&i) {
            revealed_msgs.insert(i, msgs[i]);
        } else {
            unrevealed_msgs.insert(i, msgs[i]);
        }
    }

    let mut statements_3 = Statements::new();
    statements_3.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        revealed_msgs,
    ));
    statements_3.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_1.clone(),
        reg_commit_1.clone(),
    ));

    let mut meta_statements_3 = MetaStatements::new();
    meta_statements_3.add_witness_equality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    let context = Some(b"For verifier 1, revealing messages this time".to_vec());
    let proof_spec_3 = ProofSpec::new(
        statements_3.clone(),
        meta_statements_3.clone(),
        vec![],
        context.clone(),
    );
    proof_spec_3.validate().unwrap();

    let mut witnesses_3 = Witnesses::new();
    witnesses_3.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        unrevealed_msgs,
    ));
    witnesses_3.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_1.clone(),
    ]));

    let proof_3 = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_3.clone(),
        witnesses_3.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    proof_3
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_3, None, Default::default())
        .unwrap();
}

#[test]
fn pok_of_bbs_plus_sig_with_reusing_setup_params() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (msgs_1, params_1, keypair_1, sig_1) = sig_setup(&mut rng, msg_count);
    let (msgs_2, params_2, keypair_2, sig_2) = sig_setup(&mut rng, msg_count);

    let msgs_3: Vec<Fr> = (0..msg_count)
        .into_iter()
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let sig_3 =
        SignatureG1::<Bls12_381>::new(&mut rng, &msgs_3, &keypair_1.secret_key, &params_1).unwrap();
    let msgs_4: Vec<Fr> = (0..msg_count)
        .into_iter()
        .map(|_| Fr::rand(&mut rng))
        .collect();
    let sig_4 =
        SignatureG1::<Bls12_381>::new(&mut rng, &msgs_4, &keypair_2.secret_key, &params_2).unwrap();

    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::BBSPlusSignatureParams(params_1.clone()));
    all_setup_params.push(SetupParams::BBSPlusPublicKey(keypair_1.public_key.clone()));
    all_setup_params.push(SetupParams::BBSPlusSignatureParams(params_2.clone()));
    all_setup_params.push(SetupParams::BBSPlusPublicKey(keypair_2.public_key.clone()));

    test_serialization!(Vec<SetupParams<Bls12_381, G1Affine>>, all_setup_params);

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params_ref(
        0,
        1,
        BTreeMap::new(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params_ref(
        0,
        1,
        BTreeMap::new(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params_ref(
        2,
        3,
        BTreeMap::new(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_statement_from_params_ref(
        2,
        3,
        BTreeMap::new(),
    ));

    test_serialization!(Statements<Bls12_381, G1Affine>, statements);

    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), all_setup_params, None);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381, G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_1.clone(),
        msgs_1
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_3.clone(),
        msgs_3
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_2.clone(),
        msgs_2
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig_4.clone(),
        msgs_4
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses,
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec.clone(), None, Default::default())
        .unwrap();
    println!(
        "Time to verify proof with 4 BBS+ signatures: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            None,
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!(
        "Time to verify proof with 4 BBS+ signatures with randomized pairing check: {:?}",
        start.elapsed()
    );
}

#[test]
fn proof_spec_validation() {
    // Catch invalid proof spec like with invalid witness equality or revealing a message while also referencing it in witness equality

    let mut rng = StdRng::seed_from_u64(0u64);

    let (msgs_1, params_1, keypair_1, _) = sig_setup(&mut rng, 5);
    let (msgs_2, params_2, keypair_2, _) = sig_setup(&mut rng, 6);

    let mut statements_1 = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    statements_1.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));

    let invalid_wit_eq = EqualWitnesses(vec![(0, 5)].into_iter().collect::<BTreeSet<WitnessRef>>());
    assert!(!invalid_wit_eq.is_valid());

    let mut meta_statements_1 = MetaStatements::new();
    meta_statements_1.add_witness_equality(invalid_wit_eq);

    let ps_1 = ProofSpec::new(statements_1, meta_statements_1, vec![], None);
    assert!(ps_1.validate().is_err());

    let mut revealed = BTreeMap::new();
    revealed.insert(1, msgs_1[1].clone());
    let mut statements_2 = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    statements_2.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        revealed,
    ));

    let valid_wit_eq = EqualWitnesses(
        vec![(0, 1), (0, 2)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    );
    assert!(valid_wit_eq.is_valid());

    let mut meta_statements_2 = MetaStatements::new();
    meta_statements_2.add_witness_equality(valid_wit_eq);

    let ps_2 = ProofSpec::new(statements_2, meta_statements_2, vec![], None);
    assert!(ps_2.validate().is_err());

    let mut revealed_1 = BTreeMap::new();
    revealed_1.insert(3, msgs_2[3].clone());
    let mut statements_3 = Statements::<Bls12_381, <Bls12_381 as Pairing>::G1Affine>::new();
    statements_3.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    statements_3.add(PoKSignatureBBSG1Stmt::new_statement_from_params(
        params_2.clone(),
        keypair_2.public_key.clone(),
        revealed_1,
    ));

    let valid_wit_eq = EqualWitnesses(
        vec![(0, 1), (1, 3)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    );
    assert!(valid_wit_eq.is_valid());

    let mut meta_statements_3 = MetaStatements::new();
    meta_statements_3.add_witness_equality(valid_wit_eq);

    let ps_3 = ProofSpec::new(statements_3, meta_statements_3, vec![], None);
    assert!(ps_3.validate().is_err());
}
