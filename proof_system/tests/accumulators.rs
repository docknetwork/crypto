use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use proof_system::{
    meta_statement::{EqualWitnesses, MetaStatements, WitnessRef},
    proof::Proof,
    proof_spec::ProofSpec,
    setup_params::SetupParams,
    statement::{
        accumulator::cdh::{
            KBPositiveAccumulatorMembershipCDH, KBUniversalAccumulatorMembershipCDHProver,
            KBUniversalAccumulatorMembershipCDHVerifier,
            KBUniversalAccumulatorNonMembershipCDHProver,
            KBUniversalAccumulatorNonMembershipCDHVerifier, VBAccumulatorMembershipCDHProver,
            VBAccumulatorMembershipCDHVerifier, VBAccumulatorNonMembershipCDHProver,
            VBAccumulatorNonMembershipCDHVerifier,
        },
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        Statements,
    },
    verifier::VerifierConfig,
    witness::{
        KBPosMembership, KBUniMembership as KBUniMembershipWit,
        KBUniNonMembership as KBUniNonMembershipWit, Membership as MembershipWit,
        NonMembership as NonMembershipWit, PoKBBSSignatureG1 as PoKSignatureBBSG1Wit, Witness,
        Witnesses,
    },
};
use short_group_sig::common::ProvingKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use test_utils::{accumulators::*, bbs::*, test_serialization};
use vb_accumulator::positive::Accumulator;

#[test]
fn pok_of_bbs_plus_sig_and_vb_and_kb_universal_accumulator_with_cdh_proof() {
    // Prove knowledge of BBS+ signature and one of the message's membership and non-membership in accumulators
    let mut rng = StdRng::seed_from_u64(0u64);

    let max = 10;
    let (pos_accum_params, pos_accum_keypair, mut pos_accumulator, mut pos_state) =
        setup_positive_accum(&mut rng);

    let (uni_accum_params, uni_accum_keypair, mut uni_accumulator, initial_elements, mut uni_state) =
        setup_universal_accum(&mut rng, max);

    let msg_count = 6;
    let (msgs, sig_params, sig_keypair, sig) = bbs_plus_sig_setup(&mut rng, msg_count as u32);

    let mut domain = msgs.clone();
    while domain.len() < max as usize {
        domain.push(Fr::rand(&mut rng));
    }
    let (kb_accum_params, kb_keypair, mut kb_accumulator, mut kb_mem_state, mut kb_non_mem_state) =
        setup_kb_universal_accum_given_domain(&mut rng, domain.clone());

    let Q = G1Affine::rand(&mut rng);

    let (
        kb_pos_accum_params,
        kb_pos_accum_sk,
        kb_pos_accum_pk,
        kb_pos_accumulator,
        mut kb_pos_state,
    ) = setup_kb_positive_accum(&mut rng);

    let prk = ProvingKey::generate_using_rng(&mut rng);

    // Message with index `accum_member_1_idx` is added in the positive VB accumulator
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
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(VBAccumulatorMembershipCDHProver::new(
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
    let proof_spec = ProofSpec::new(statements, meta_statements.clone(), vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        VBAccumulatorMembershipCDHVerifier::new_statement_from_params(
            pos_accum_params.clone(),
            pos_accum_keypair.public_key.clone(),
            *pos_accumulator.value(),
        ),
    );

    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

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
        "Time to verify proof with a BBS+ signature and VB positive accumulator membership: {:?}",
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
    println!("Time to verify proof with a BBS+ signature and VB positive accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and membership of message with index `accum_member_2_idx` in universal accumulator
    let accum_member_2_idx = 2;
    let accum_member_2 = msgs[accum_member_2_idx];

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
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(VBAccumulatorMembershipCDHProver::new(
        *uni_accumulator.value(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
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

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        VBAccumulatorMembershipCDHVerifier::new_statement_from_params(
            uni_accum_params.clone(),
            uni_accum_keypair.public_key.clone(),
            *uni_accumulator.value(),
        ),
    );

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

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
        "Time to verify proof with a BBS+ signature and VB universal accumulator membership: {:?}",
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
    println!("Time to verify proof with a BBS+ signature and VB universal accumulator membership with randomized pairing check: {:?}", start.elapsed());

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
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        VBAccumulatorNonMembershipCDHProver::new_statement_from_params(
            *uni_accumulator.value(),
            Q.clone(),
            uni_accum_params.clone(),
        ),
    );

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
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

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        VBAccumulatorNonMembershipCDHVerifier::new_statement_from_params(
            uni_accum_params.clone(),
            uni_accum_keypair.public_key.clone(),
            *uni_accumulator.value(),
            Q.clone(),
        ),
    );

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

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
        "Time to verify proof with a BBS+ signature and VB universal accumulator non-membership: {:?}",
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
    println!("Time to verify proof with a BBS+ signature and VB universal accumulator non-membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and membership of message with index `accum_member_3_idx` in KB universal accumulator
    let accum_member_3_idx = 3;
    let accum_member_3 = msgs[accum_member_3_idx];

    kb_accumulator = kb_accumulator
        .add(
            accum_member_3,
            &kb_keypair.secret_key,
            &mut kb_mem_state,
            &mut kb_non_mem_state,
        )
        .unwrap();
    let mem_3_wit = kb_accumulator
        .get_membership_witness(&accum_member_3, &kb_keypair.secret_key, &kb_mem_state)
        .unwrap();
    assert!(kb_accumulator.verify_membership(
        &accum_member_3,
        &mem_3_wit,
        &kb_keypair.public_key,
        &kb_accum_params
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(KBUniversalAccumulatorMembershipCDHProver::new(
        *kb_accumulator.mem_value(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(Witness::KBUniAccumulatorMembership(KBUniMembershipWit {
        element: accum_member_3,
        witness: mem_3_wit.clone(),
    }));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_3_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let proof_spec = ProofSpec::new(statements, meta_statements.clone(), vec![], context.clone());
    proof_spec.validate().unwrap();

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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        KBUniversalAccumulatorMembershipCDHVerifier::new_statement_from_params(
            kb_accum_params.clone(),
            kb_keypair.public_key.clone(),
            *kb_accumulator.mem_value(),
        ),
    );

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

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
        "Time to verify proof with a BBS+ signature and KB universal accumulator membership: {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    proof
        .clone()
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec,
            nonce.clone(),
            VerifierConfig {
                use_lazy_randomized_pairing_checks: Some(false),
            },
        )
        .unwrap();
    println!("Time to verify proof with a BBS+ signature and KB universal accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and non-membership of message with index `accum_non_member_idx` in KB universal accumulator
    let accum_non_member_2_idx = 4;
    let accum_non_member_2 = msgs[accum_non_member_2_idx];
    let non_mem_wit_2 = kb_accumulator
        .get_non_membership_witness(
            &accum_non_member_2,
            &kb_keypair.secret_key,
            &kb_non_mem_state,
        )
        .unwrap();
    assert!(kb_accumulator.verify_non_membership(
        &accum_non_member_2,
        &non_mem_wit_2,
        &kb_keypair.public_key,
        &kb_accum_params
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(KBUniversalAccumulatorNonMembershipCDHProver::new(
        *kb_accumulator.non_mem_value(),
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(Witness::KBUniAccumulatorNonMembership(
        KBUniNonMembershipWit {
            element: accum_non_member_2,
            witness: non_mem_wit_2.clone(),
        },
    ));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_non_member_2_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
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

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        KBUniversalAccumulatorNonMembershipCDHVerifier::new_statement_from_params(
            kb_accum_params.clone(),
            kb_keypair.public_key.clone(),
            *kb_accumulator.non_mem_value(),
        ),
    );

    let proof_spec = ProofSpec::new(statements.clone(), meta_statements, vec![], context.clone());
    proof_spec.validate().unwrap();

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
"Time to verify proof with a BBS+ signature and KB universal accumulator non-membership: {:?}",
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
    println!("Time to verify proof with a BBS+ signature and KB universal accumulator non-membership with randomized pairing check: {:?}", start.elapsed());

    // Message with index `accum_member_4` is added in the KB positive accumulator
    let accum_member_4_idx = 1;
    let accum_member_4 = msgs[accum_member_4_idx];

    let mem_4_wit = kb_pos_accumulator
        .add::<Blake2b512>(
            &accum_member_4,
            &kb_pos_accum_sk,
            &kb_pos_accum_params,
            &mut kb_pos_state,
        )
        .unwrap();
    kb_pos_accumulator
        .verify_membership(
            &accum_member_4,
            &mem_4_wit,
            &kb_pos_accum_pk,
            &kb_pos_accum_params,
        )
        .unwrap();

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        KBPositiveAccumulatorMembershipCDH::new_statement_from_params(
            kb_pos_accum_params.clone(),
            kb_pos_accum_pk.clone(),
            prk.clone(),
            *kb_pos_accumulator.value(),
        ),
    );

    // Create meta statement describing that message in the signature at index `accum_member_1_idx` is
    // same as the accumulator member
    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![
            (0, accum_member_4_idx),
            (1, 0), // Since accumulator (non)membership has only one (for applications) which is the (non)member, that witness is at index 0.
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, prover_statements);
    test_serialization!(MetaStatements, meta_statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(KBPosMembership::new_as_witness(
        accum_member_4,
        mem_4_wit.clone(),
    ));
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test-nonce".to_vec());

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec,
        witnesses.clone(),
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        KBPositiveAccumulatorMembershipCDH::new_statement_from_params(
            kb_pos_accum_params.clone(),
            kb_pos_accum_pk.clone(),
            prk.clone(),
            *kb_pos_accumulator.value(),
        ),
    );
    let proof_spec = ProofSpec::new(
        verifier_statements,
        meta_statements,
        vec![],
        context.clone(),
    );

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
        "Time to verify proof with a BBS+ signature and KB positive accumulator membership: {:?}",
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
    println!("Time to verify proof with a BBS+ signature and KB positive accumulator membership with randomized pairing check: {:?}", start.elapsed());

    // Prove knowledge of signature and
    // - membership of message with index `accum_member_1_idx` in VB positive accumulator
    // - membership of message with index `accum_member_2_idx` in VB universal accumulator
    // - non-membership of message with index `accum_non_member_idx` VB in universal accumulator
    // - membership of message with index `accum_member_3_idx` in KB universal accumulator
    // - non-membership of message with index `accum_non_member_2_idx` KB in universal accumulator
    // - membership of message with index `accum_member_4_idx` in KB positive accumulator
    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::VbAccumulatorParams(uni_accum_params));
    all_setup_params.push(SetupParams::VbAccumulatorPublicKey(
        uni_accum_keypair.public_key.clone(),
    ));
    all_setup_params.push(SetupParams::VbAccumulatorParams(kb_accum_params));
    all_setup_params.push(SetupParams::VbAccumulatorPublicKey(
        kb_keypair.public_key.clone(),
    ));
    all_setup_params.push(SetupParams::BBSigProvingKey(prk));
    all_setup_params.push(SetupParams::KBPositiveAccumulatorParams(
        kb_pos_accum_params,
    ));
    all_setup_params.push(SetupParams::KBPositiveAccumulatorPublicKey(
        kb_pos_accum_pk.clone(),
    ));

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    statements.add(VBAccumulatorMembershipCDHProver::new(
        *pos_accumulator.value(),
    ));
    statements.add(VBAccumulatorMembershipCDHProver::new(
        *uni_accumulator.value(),
    ));
    statements.add(
        VBAccumulatorNonMembershipCDHProver::new_statement_from_params_ref(
            0,
            *uni_accumulator.value(),
            Q,
        ),
    );
    statements.add(KBUniversalAccumulatorMembershipCDHProver::new(
        *kb_accumulator.mem_value(),
    ));
    statements.add(KBUniversalAccumulatorNonMembershipCDHProver::new(
        *kb_accumulator.non_mem_value(),
    ));
    statements.add(
        KBPositiveAccumulatorMembershipCDH::new_statement_from_params_ref(
            5,
            6,
            4,
            *kb_pos_accumulator.value(),
        ),
    );

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
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_3_idx), (4, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_non_member_2_idx), (5, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_4_idx), (6, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.into_iter().enumerate().collect(),
    ));
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
    witnesses.add(Witness::KBUniAccumulatorMembership(KBUniMembershipWit {
        element: accum_member_3,
        witness: mem_3_wit,
    }));
    witnesses.add(Witness::KBUniAccumulatorNonMembership(
        KBUniNonMembershipWit {
            element: accum_non_member_2,
            witness: non_mem_wit_2,
        },
    ));
    witnesses.add(Witness::KBPosAccumulatorMembership(KBPosMembership {
        element: accum_member_4,
        witness: mem_4_wit,
    }));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec::new(
        statements,
        meta_statements.clone(),
        all_setup_params.clone(),
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec,
        witnesses,
        nonce.clone(),
        Default::default(),
    )
    .unwrap()
    .0;

    test_serialization!(Proof<Bls12_381>, proof);

    let mut statements = Statements::new();
    statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params,
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(
        VBAccumulatorMembershipCDHVerifier::new_statement_from_params(
            pos_accum_params,
            pos_accum_keypair.public_key.clone(),
            *pos_accumulator.value(),
        ),
    );
    statements.add(
        VBAccumulatorMembershipCDHVerifier::new_statement_from_params_ref(
            0,
            1,
            *uni_accumulator.value(),
        ),
    );
    statements.add(
        VBAccumulatorNonMembershipCDHVerifier::new_statement_from_params_ref(
            0,
            1,
            *uni_accumulator.value(),
            Q,
        ),
    );
    statements.add(
        KBUniversalAccumulatorMembershipCDHVerifier::new_statement_from_params_ref(
            2,
            3,
            *kb_accumulator.mem_value(),
        ),
    );
    statements.add(
        KBUniversalAccumulatorNonMembershipCDHVerifier::new_statement_from_params_ref(
            2,
            3,
            *kb_accumulator.non_mem_value(),
        ),
    );
    statements.add(
        KBPositiveAccumulatorMembershipCDH::new_statement_from_params_ref(
            5,
            6,
            4,
            *kb_pos_accumulator.value(),
        ),
    );

    let proof_spec = ProofSpec::new(statements, meta_statements, all_setup_params, context);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

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
    println!("Time to verify proof with a BBS+ signature and 6 accumulator membership and non-membership checks: {:?}", start.elapsed());

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
    println!("Time to verify proof with a BBS+ signature and 6 accumulator membership and non-membership checks with randomized pairing check: {:?}", start.elapsed());
}
