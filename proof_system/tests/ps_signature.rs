use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use coconut_crypto::setup::*;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use coconut_crypto::{
    BlindSignature, CommitmentOrMessage, MessageCommitment, MultiMessageCommitment, Signature,
};
use dock_crypto_utils::{
    hashing_utils::affine_group_elem_from_try_and_incr, misc::*, owned_pairs::*, pairs::*,
};
use std::time::Instant;
use vb_accumulator::prelude::{Accumulator, MembershipProvingKey, NonMembershipProvingKey};

use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatement, MetaStatements, VerifierConfig, Witness, WitnessRef,
        Witnesses,
    },
    proof::Proof,
    proof_spec::ProofSpec,
    setup_params::SetupParams,
    statement::{
        accumulator::{
            VBAccumulatorMembership as AccumulatorMembershipStmt,
            VBAccumulatorNonMembership as AccumulatorNonMembershipStmt,
        },
        ped_comm::PedersenCommitment as PedersenCommitmentStmt,
        ps_signature::PoKPSSignatureStatement,
        Statements,
    },
    witness::{Membership as MembershipWit, NonMembership as NonMembershipWit, PoKPSSignature},
};
use test_utils::{accumulators::*, test_serialization};

#[test]
fn pok_of_3_ps_sig_and_message_equality() {
    // Prove knowledge of 3 PS signatures and 3 of the messages are same among them.
    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st PS sig
    let msg_count_1 = 6;
    let (secret_key_1, public_key_1, sig_params_1, msgs_1) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count_1);

    // 2nd PS sig
    let msg_count_2 = 10;
    let (secret_key_2, public_key_2, sig_params_2, mut msgs_2) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count_2);

    // 3rd PS sig
    let msg_count_3 = 12;
    let (secret_key_3, public_key_3, sig_params_3, mut msgs_3) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count_3);

    // Make 3 messages same
    msgs_2[9] = msgs_1[5];
    msgs_3[9] = msgs_1[5];
    msgs_2[8] = msgs_1[4];
    msgs_3[8] = msgs_1[4];
    msgs_2[7] = msgs_1[3];
    msgs_3[7] = msgs_1[3];

    msgs_3[5] = msgs_3[7];

    let sig_1 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_1, &secret_key_1, &sig_params_1).unwrap();
    sig_1.verify(&msgs_1, &public_key_1, &sig_params_1).unwrap();

    let sig_2 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_2, &secret_key_2, &sig_params_2).unwrap();
    sig_2.verify(&msgs_2, &public_key_2, &sig_params_2).unwrap();

    let sig_3 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_3, &secret_key_3, &sig_params_3).unwrap();
    sig_3.verify(&msgs_3, &public_key_3, &sig_params_3).unwrap();

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
        .map(|(i, m)| (i, *m))
        .collect::<BTreeMap<_, _>>();

    // Since proving knowledge of 3 PS signatures, add 3 statements, all of the same type though.
    let mut statements = Statements::new();
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1.clone(),
        public_key_1,
        revealed_msgs_1.clone(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_2.clone(),
        public_key_2,
        revealed_msgs_2.clone(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_3.clone(),
        public_key_3,
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
        vec![(2, 5), (2, 7)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);

    // Create a proof spec, this is shared between prover and verifier
    // Context must be known to both prover and verifier
    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    // Prover now creates/loads it witnesses corresponding to the proof spec
    let mut witnesses = Witnesses::new();
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_1,
        unrevealed_msgs_1.clone(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_2,
        unrevealed_msgs_2.clone(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(sig_3, unrevealed_msgs_3));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    // Prover now creates the proof using the proof spec and witnesses. This will be sent to the verifier
    let nonce = Some(b"some nonce".to_vec());
    let proof = Proof::new::<StdRng, Blake2b512>(
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

    test_serialization!(Proof<Bls12_381>, proof);

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
        "Time to verify proof with 3 PS signatures: {:?}",
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
        "Time to verify proof with 3 PS signatures with randomized pairing check: {:?}",
        start.elapsed()
    );
}

#[test]
fn pok_of_ps_sig_and_accumulator() {
    // Prove knowledge of PS signature and one of the message's membership and non-membership in accumulators
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 6;
    let (secret_key, public_key, sig_params, msgs) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count);
    let sig = Signature::new(&mut rng, msgs.as_slice(), &secret_key, &sig_params).unwrap();

    let max = 10;
    let (pos_accum_params, pos_accum_keypair, mut pos_accumulator, mut pos_state) =
        setup_positive_accum(&mut rng);
    let mem_prk = MembershipProvingKey::generate_using_rng(&mut rng);

    // Message with index `accum_member_1_idx` is added in the positive accumulator
    let accum_member_1_idx = 1;
    let accum_member_1 = msgs[accum_member_1_idx];

    pos_accumulator = pos_accumulator
        .add(
            accum_member_1,
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
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        pos_accum_params.clone(),
        pos_accum_keypair.public_key.clone(),
        mem_prk.clone(),
        *pos_accumulator.value(),
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

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKPSSignature::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(MembershipWit::new_as_witness(
        accum_member_1,
        mem_1_wit.clone(),
    ));
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test-nonce".to_vec());

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

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
        "Time to verify proof with a PS signature and positive accumulator membership: {:?}",
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
    println!("Time to verify proof with a PS signature and positive accumulator membership with randomized pairing check: {:?}", start.elapsed());

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
    let proof = Proof::new::<StdRng, Blake2b512>(
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
            proof_spec_incorrect,
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .is_err());

    // Non-member fails to verify
    let mut witnesses_incorrect = Witnesses::new();
    witnesses_incorrect.add(Witness::PoKPSSignature(PoKPSSignature {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().collect(),
    }));
    witnesses_incorrect.add(Witness::VBAccumulatorMembership(MembershipWit {
        element: msgs[2], // 2nd message from PS sig in accumulator
        witness: mem_1_wit.clone(),
    }));
    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![
            (0, 2), // 2nd message from PS sig in accumulator
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    ));
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();
    let proof = Proof::new::<StdRng, Blake2b512>(
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
    let accum_member_2 = msgs[accum_member_2_idx];
    let (uni_accum_params, uni_accum_keypair, mut uni_accumulator, initial_elements, mut uni_state) =
        setup_universal_accum(&mut rng, max);
    let non_mem_prk = NonMembershipProvingKey::generate_using_rng(&mut rng);
    let derived_mem_prk = non_mem_prk.derive_membership_proving_key();

    uni_accumulator = uni_accumulator
        .add(
            accum_member_2,
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
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        uni_accum_params.clone(),
        uni_accum_keypair.public_key.clone(),
        derived_mem_prk.clone(),
        *uni_accumulator.value(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKPSSignature(PoKPSSignature {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().collect(),
    }));
    witnesses.add(Witness::VBAccumulatorMembership(MembershipWit {
        element: accum_member_2,
        witness: mem_2_wit.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_2_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

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
        "Time to verify proof with a PS signature and universal accumulator membership: {:?}",
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
    println!("Time to verify proof with a PS signature and universal accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and non-membership of message with index `accum_non_member_idx` in universal accumulator
    let accum_non_member_idx = 3;
    let accum_non_member = msgs[accum_non_member_idx];
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
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorNonMembershipStmt::new_statement_from_params(
        uni_accum_params.clone(),
        uni_accum_keypair.public_key.clone(),
        non_mem_prk.clone(),
        *uni_accumulator.value(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKPSSignature(PoKPSSignature {
        signature: sig.clone(),
        unrevealed_messages: msgs.clone().into_iter().enumerate().collect(),
    }));
    witnesses.add(Witness::VBAccumulatorNonMembership(NonMembershipWit {
        element: accum_non_member,
        witness: non_mem_wit.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_non_member_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

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
        "Time to verify proof with a PS signature and universal accumulator non-membership: {:?}",
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
    println!("Time to verify proof with a PS signature and universal accumulator non-membership with randomized pairing check: {:?}", start.elapsed());

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
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key,
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params(
        pos_accum_params,
        pos_accum_keypair.public_key.clone(),
        mem_prk,
        *pos_accumulator.value(),
    ));
    statements.add(AccumulatorMembershipStmt::new_statement_from_params_ref(
        0,
        1,
        2,
        *uni_accumulator.value(),
    ));
    statements.add(AccumulatorNonMembershipStmt::new_statement_from_params_ref(
        0,
        1,
        3,
        *uni_accumulator.value(),
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

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PoKPSSignature(PoKPSSignature {
        signature: sig,
        unrevealed_messages: msgs.clone().into_iter().enumerate().collect(),
    }));
    witnesses.add(Witness::VBAccumulatorMembership(MembershipWit {
        element: accum_member_1,
        witness: mem_1_wit,
    }));
    witnesses.add(Witness::VBAccumulatorMembership(MembershipWit {
        element: accum_member_2,
        witness: mem_2_wit,
    }));
    witnesses.add(Witness::VBAccumulatorNonMembership(NonMembershipWit {
        element: accum_non_member,
        witness: non_mem_wit,
    }));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements,
        all_setup_params,
        context,
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

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
    println!("Time to verify proof with a PS signature and 3 accumulator membership and non-membership checks: {:?}", start.elapsed());

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
    println!("Time to verify proof with a PS signature and 3 accumulator membership and non-membership checks with randomized pairing check: {:?}", start.elapsed());
}

#[test]
fn pok_of_knowledge_in_pedersen_commitment_and_ps_sig() {
    // Prove knowledge of commitment in Pedersen commitments and equality with a PS signature.
    // Useful when requesting a blind signature and proving knowledge of a signature along with
    // some the equality of certain messages in the commitment and signature

    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 6;
    let (secret_key, public_key, sig_params, msgs) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count);
    let sig = Signature::new(&mut rng, msgs.as_slice(), &secret_key, &sig_params).unwrap();

    let bases = (0..5)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let mut scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    // Make 2 of the messages in the commitment same as in the signature
    scalars[1] = msgs[0];
    scalars[4] = msgs[5];
    let commitment = G1Projective::msm_unchecked(&bases, &scalars).into_affine();

    let mut statements = Statements::new();
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key,
        BTreeMap::new(),
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases, commitment,
    ));

    test_serialization!(Statements<Bls12_381>, statements);

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

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKPSSignature::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(scalars.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

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

    let proof_spec_invalid =
        ProofSpec::new(statements.clone(), meta_statements_wrong, vec![], context);

    let proof = Proof::new::<StdRng, Blake2b512>(
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
fn requesting_partially_blind_ps_sig() {
    // Request a partially blind signature by first proving knowledge of values in a Pedersen commitment. The
    // requester then unblinds the signature and verifies it.

    let mut rng = StdRng::seed_from_u64(0u64);

    // The total number of messages in the signature
    let total_msg_count = 10;

    // Setup params and messages
    let (secret_key, public_key, sig_params, msgs) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, total_msg_count);

    // Message indices hidden from signer. Here signer does not know msgs[0], msgs[4] and msgs[6]
    let committed_indices = vec![0, 4, 6].into_iter().collect::<BTreeSet<usize>>();

    let commit_msgs: Vec<_> = committed_indices.iter().map(|i| msgs[*i]).collect();

    let blinding = rand(&mut rng);
    let blinding_m_pairs: OwnedPairs<_, _> = n_rand(&mut rng, committed_indices.len())
        .zip(commit_msgs.iter().cloned())
        .collect();

    let h_m_pairs = Pairs::new_truncate_to_min(&sig_params.h, &commit_msgs);
    // Commitment to all hidden messages
    let multi_message_commitment =
        MultiMessageCommitment::<Bls12_381>::new(h_m_pairs, &sig_params.g, &blinding);

    // Generate `h` by hashing the commitment to all hidden messages
    let mut comm_bytes = vec![];
    multi_message_commitment
        .serialize_compressed(&mut comm_bytes)
        .unwrap();
    let h = affine_group_elem_from_try_and_incr::<_, Blake2b512>(&comm_bytes);

    let commitments: Vec<_> =
        MessageCommitment::new_iter(blinding_m_pairs.as_ref(), &h, &sig_params).collect();

    // Requester proves knowledge of committed messages
    let mut statements = Statements::new();
    for comm in &commitments {
        statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![sig_params.g, h],
            **comm,
        ));
    }
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        MultiMessageCommitment::<Bls12_381>::bases(&sig_params.g, h_m_pairs.left()).collect(),
        *multi_message_commitment,
    ));

    test_serialization!(Statements<Bls12_381>, statements);

    let context = Some(b"test".to_vec());
    let wit_eq = commit_msgs
        .iter()
        .enumerate()
        .map(|(idx, _)| BTreeSet::from_iter([(idx, 1), (commit_msgs.len(), idx + 1)]))
        .map(EqualWitnesses)
        .map(MetaStatement::WitnessEquality)
        .collect();
    let proof_spec = ProofSpec::new(statements.clone(), MetaStatements(wit_eq), vec![], context);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    for (&blinding, &msg) in blinding_m_pairs.iter() {
        witnesses.add(Witness::PedersenCommitment(vec![blinding, msg]));
    }
    witnesses.add(Witness::PedersenCommitment(
        MultiMessageCommitment::<Bls12_381>::exps(&blinding, commit_msgs).collect(),
    ));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, nonce, Default::default())
        .unwrap();

    // Now requester picks the messages he is revealing to the signer and prepares `uncommitted_messages`
    // to request the blind signature
    let mut coms_iter = commitments.iter();
    let messages = (0..total_msg_count).map(|i| {
        if committed_indices.contains(&i) {
            CommitmentOrMessage::BlindedMessage(*coms_iter.next().unwrap())
        } else {
            CommitmentOrMessage::RevealedMessage(msgs[i])
        }
    });

    // Signer creates the blind signature using the commitment
    let blinded_sig = BlindSignature::<Bls12_381>::new(messages, &secret_key, &h).unwrap();

    let sig = blinded_sig
        .unblind(
            committed_indices
                .iter()
                .copied()
                .zip(blinding_m_pairs.as_ref().left()),
            &public_key,
            &h,
        )
        .unwrap();
    sig.verify(&msgs, &public_key, &sig_params).unwrap();
}

#[test]
fn proof_spec_modification() {
    // Prover modifies the proof spec like removing meta-statements or statements but proof verification should detect that

    let mut rng = StdRng::seed_from_u64(0u64);

    // 1st PS sig
    let msg_count_1 = 6;
    let (secret_key_1, public_key_1, sig_params_1, msgs_1) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count_1);

    let sig_1 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_1, &secret_key_1, &sig_params_1).unwrap();

    // 2nd PS sig
    let msg_count_2 = 10;
    let (secret_key_2, public_key_2, sig_params_2, mut msgs_2) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count_2);

    msgs_2[9] = msgs_1[5];

    let sig_2 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_2, &secret_key_2, &sig_params_2).unwrap();
    sig_2.verify(&msgs_2, &public_key_2, &sig_params_2).unwrap();

    let mut statements = Statements::<Bls12_381>::new();
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1.clone(),
        public_key_1.clone(),
        BTreeMap::new(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_2.clone(),
        public_key_2,
        BTreeMap::new(),
    ));

    let invalid_eq_wit = EqualWitnesses(vec![(0, 1)].into_iter().collect::<BTreeSet<WitnessRef>>());
    assert!(!invalid_eq_wit.is_valid());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(invalid_eq_wit);

    let invalid_proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], None);
    assert!(invalid_proof_spec.validate().is_err());

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_1.clone(),
        msgs_1
            .clone()
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_2,
        msgs_2
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));

    assert!(Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec,
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
    assert!(Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec,
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
    assert!(Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        invalid_proof_spec,
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
    let invalid_proof = Proof::new::<StdRng, Blake2b512>(
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
        .verify::<StdRng, Blake2b512>(&mut rng, modified_proof_spec, None, Default::default())
        .unwrap();
    assert!(invalid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .is_err());

    // Proof created using original proof spec will be valid
    let valid_proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        orig_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;
    valid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec, None, Default::default())
        .unwrap();

    // Verifier creates proof spec with 2 statements, prover modifies it to remove a statement
    let orig_proof_spec = ProofSpec::new(statements.clone(), MetaStatements::new(), vec![], None);

    // Prover's modified proof spec
    let mut only_1_statement = Statements::<Bls12_381>::new();
    only_1_statement.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1.clone(),
        public_key_1,
        BTreeMap::new(),
    ));
    let modified_proof_spec = ProofSpec::new(
        only_1_statement.clone(),
        MetaStatements::new(),
        vec![],
        None,
    );

    let mut only_1_witness = Witnesses::new();
    only_1_witness.add(PoKPSSignature::new_as_witness(
        sig_1,
        msgs_1
            .into_iter()
            .enumerate()
            .collect::<BTreeMap<usize, Fr>>(),
    ));

    // Proof created using modified proof spec wont be a valid
    let invalid_proof = Proof::new::<StdRng, Blake2b512>(
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
        .verify::<StdRng, Blake2b512>(&mut rng, modified_proof_spec, None, Default::default())
        .unwrap();
    assert!(invalid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec.clone(), None, Default::default())
        .is_err());

    // Proof created using original proof spec will be valid
    let valid_proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        orig_proof_spec.clone(),
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;
    valid_proof
        .verify::<StdRng, Blake2b512>(&mut rng, orig_proof_spec, None, Default::default())
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
    let (secret_key, public_key, sig_params, msgs) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count);
    let sig = Signature::new(&mut rng, msgs.as_slice(), &secret_key, &sig_params).unwrap();

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
    statements_1.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key.clone(),
        BTreeMap::new(),
    ));
    statements_1.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_1.clone(),
        reg_commit_1,
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
        context,
    );
    proof_spec_1.validate().unwrap();

    let mut witnesses_1 = Witnesses::new();
    witnesses_1.add(PoKPSSignature::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses_1.add(Witness::PedersenCommitment(vec![msgs[1], blinding_1]));

    let proof_1 = Proof::new::<StdRng, Blake2b512>(
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
    statements_2.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key.clone(),
        BTreeMap::new(),
    ));
    statements_2.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_2,
        reg_commit_2,
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
        context,
    );
    proof_spec_2.validate().unwrap();

    let mut witnesses_2 = Witnesses::new();
    witnesses_2.add(PoKPSSignature::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses_2.add(Witness::PedersenCommitment(vec![msgs[1], blinding_2]));

    let proof_2 = Proof::new::<StdRng, Blake2b512>(
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
    statements_3.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params.clone(),
        public_key,
        revealed_msgs,
    ));
    statements_3.add(PedersenCommitmentStmt::new_statement_from_params(
        gens_1,
        reg_commit_1,
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
        context,
    );
    proof_spec_3.validate().unwrap();

    let mut witnesses_3 = Witnesses::new();
    witnesses_3.add(PoKPSSignature::new_as_witness(sig, unrevealed_msgs));
    witnesses_3.add(Witness::PedersenCommitment(vec![msgs[1], blinding_1]));

    let proof_3 = Proof::new::<StdRng, Blake2b512>(
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
fn pok_of_ps_sig_with_reusing_setup_params() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (secret_key_1, public_key_1, sig_params_1, msgs_1) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count);
    let (secret_key_2, public_key_2, sig_params_2, msgs_2) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, msg_count);
    let sig_1 = Signature::new(&mut rng, msgs_1.as_slice(), &secret_key_1, &sig_params_1).unwrap();
    let sig_2 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_2, &secret_key_2, &sig_params_2).unwrap();

    let msgs_3: Vec<Fr> = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect();
    let sig_3 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_3, &secret_key_1, &sig_params_1).unwrap();
    let msgs_4: Vec<Fr> = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect();
    let sig_4 =
        Signature::<Bls12_381>::new(&mut rng, &msgs_4, &secret_key_2, &sig_params_2).unwrap();

    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::PSSignatureParams(sig_params_1.clone()));
    all_setup_params.push(SetupParams::PSSignaturePublicKey(public_key_1));
    all_setup_params.push(SetupParams::PSSignatureParams(sig_params_2.clone()));
    all_setup_params.push(SetupParams::PSSignaturePublicKey(public_key_2));

    test_serialization!(Vec<SetupParams<Bls12_381>>, all_setup_params);

    let mut statements = Statements::new();
    statements.add(PoKPSSignatureStatement::new_statement_from_params_ref(
        0,
        1,
        BTreeMap::new(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params_ref(
        0,
        1,
        BTreeMap::new(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params_ref(
        2,
        3,
        BTreeMap::new(),
    ));
    statements.add(PoKPSSignatureStatement::new_statement_from_params_ref(
        2,
        3,
        BTreeMap::new(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);

    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), all_setup_params, None);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_1,
        msgs_1
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_3,
        msgs_3
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_2,
        msgs_2
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKPSSignature::new_as_witness(
        sig_4,
        msgs_4
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof = Proof::new::<StdRng, Blake2b512>(
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
        "Time to verify proof with 4 PS signatures: {:?}",
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
        "Time to verify proof with 4 PS signatures with randomized pairing check: {:?}",
        start.elapsed()
    );
}

#[test]
fn proof_spec_validation() {
    // Catch invalid proof spec like with invalid witness equality or revealing a message while also referencing it in witness equality

    let mut rng = StdRng::seed_from_u64(0u64);

    let (_secret_key_1, public_key_1, sig_params_1, msgs_1) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 5);
    let (_secret_key_2, public_key_2, sig_params_2, msgs_2) =
        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 6);

    let mut statements_1 = Statements::<Bls12_381>::new();
    statements_1.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1.clone(),
        public_key_1.clone(),
        BTreeMap::new(),
    ));

    let invalid_wit_eq = EqualWitnesses(vec![(0, 5)].into_iter().collect::<BTreeSet<WitnessRef>>());
    assert!(!invalid_wit_eq.is_valid());

    let mut meta_statements_1 = MetaStatements::new();
    meta_statements_1.add_witness_equality(invalid_wit_eq);

    let ps_1 = ProofSpec::new(statements_1, meta_statements_1, vec![], None);
    assert!(ps_1.validate().is_err());

    let mut revealed = BTreeMap::new();
    revealed.insert(1, msgs_1[1]);
    let mut statements_2 = Statements::<Bls12_381>::new();
    statements_2.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1.clone(),
        public_key_1.clone(),
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
    revealed_1.insert(3, msgs_2[3]);
    let mut statements_3 = Statements::<Bls12_381>::new();
    statements_3.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_1,
        public_key_1,
        BTreeMap::new(),
    ));
    statements_3.add(PoKPSSignatureStatement::new_statement_from_params(
        sig_params_2,
        public_key_2,
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
