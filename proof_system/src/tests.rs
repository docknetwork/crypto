use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::signature::SignatureG1;
use blake2::Blake2b;
use vb_accumulator::positive::Accumulator;
use vb_accumulator::proofs::{MembershipProvingKey, NonMembershipProvingKey};

use crate::meta_statement::{EqualWitnesses, MetaStatement, MetaStatements, WitnessRef};
use crate::proof::Proof;
use crate::proof_spec::ProofSpec;
use crate::statement::{
    AccumulatorMembership as AccumulatorMembershipStmt,
    AccumulatorNonMembership as AccumulatorNonMembershipStmt,
    PedersenCommitment as PedersenCommitmentStmt, PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    Statement, Statements,
};
use crate::witness::{
    Membership as MembershipWit, NonMembership as NonMembershipWit,
    PoKBBSSignatureG1 as PoKSignatureBBSG1Wit, Witness, Witnesses,
};

use crate::test_serialization;
use crate::test_utils::{setup_positive_accum, setup_universal_accum, sig_setup};

type Fr = <Bls12_381 as PairingEngine>::Fr;
type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

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
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_1.clone(),
        keypair_1.public_key.clone(),
        revealed_msgs_1.clone(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_2.clone(),
        keypair_2.public_key.clone(),
        revealed_msgs_2.clone(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_3.clone(),
        keypair_3.public_key.clone(),
        BTreeMap::new(),
    ));

    // Since 3 of the messages are being proven equal, add a `MetaStatement` describing that
    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 5), (1, 9), (2, 9)] // 0th statement's 5th witness is equal to 1st statement's 9th witness and 2nd statement's 9th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 4), (1, 8), (2, 8)] // 0th statement's 4th witness is equal to 1st statement's 8th witness and 2nd statement's 8th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 3), (1, 7), (2, 7)] // 0th statement's 3rd witness is equal to 1st statement's 7th witness and 2nd statement's 7th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(2, 5), (2, 7)] // 0th statement's 1th witness is equal to 2nd statement's 9th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    // Create a proof spec, this is shared between prover and verifier
    // Context must be known to both prover and verifier
    let context = Some(b"test".to_vec());
    let proof_spec =
        ProofSpec::new_with_statements_and_meta_statements(statements, meta_statements, context);
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

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
    let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses, nonce.clone()).unwrap();

    // Proof with no nonce shouldn't verify
    assert!(proof.clone().verify(proof_spec.clone(), None).is_err());

    // Proof with invalid nonce shouldn't verify
    assert!(proof
        .clone()
        .verify(proof_spec.clone(), Some(b"random...".to_vec()))
        .is_err());

    test_serialization!(ProofG1, proof);
    // Verifier verifies the proof
    proof.verify(proof_spec, nonce).unwrap();
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
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(AccumulatorMembershipStmt::new_as_statement(
        pos_accum_params.clone(),
        pos_accum_keypair.public_key.clone(),
        mem_prk.clone(),
        pos_accumulator.value().clone(),
    ));

    // Create meta statement describing that message in the signature at index `accum_member_1_idx` is
    // same as the accumulator member
    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![
            (0, accum_member_1_idx),
            (1, 0), // Since accumulator (non)membership has only one (for applications) which is the (non)member, that witness is at index 0.
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements,
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

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

    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec.clone(), nonce.clone()).unwrap();

    // Wrong witness reference fails to verify
    let mut meta_statements_incorrect = MetaStatements::new();
    meta_statements_incorrect.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec_incorrect = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements_incorrect,
        context: context.clone(),
    };
    let proof = ProofG1::new(
        &mut rng,
        proof_spec_incorrect.clone(),
        witnesses,
        nonce.clone(),
    )
    .unwrap();
    assert!(proof.verify(proof_spec_incorrect, nonce.clone()).is_err());

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
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![
            (0, 2), // 2nd message from BBS+ sig in accumulator
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<WitnessRef>>(),
    )));
    let proof_spec = ProofSpec {
        statements,
        meta_statements,
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());
    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses_incorrect,
        nonce.clone(),
    )
    .unwrap();
    assert!(proof.verify(proof_spec, nonce.clone()).is_err());

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
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::AccumulatorMembership(
        AccumulatorMembershipStmt {
            params: uni_accum_params.clone(),
            public_key: uni_accum_keypair.public_key.clone(),
            proving_key: derived_mem_prk.clone(),
            accumulator_value: uni_accumulator.value().clone(),
        },
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
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, accum_member_2_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements,
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce.clone()).unwrap();

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
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::AccumulatorNonMembership(
        AccumulatorNonMembershipStmt {
            params: uni_accum_params.clone(),
            public_key: uni_accum_keypair.public_key.clone(),
            proving_key: non_mem_prk.clone(),
            accumulator_value: uni_accumulator.value().clone(),
        },
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
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, accum_non_member_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    test_serialization!(MetaStatements, meta_statements);
    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements,
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce.clone()).unwrap();

    // Prove knowledge of signature and
    // - membership of message with index `accum_member_1_idx` in positive accumulator
    // - -membership of message with index `accum_member_2_idx` in universal accumulator
    // - non-membership of message with index `accum_non_member_idx` in universal accumulator
    let mut statements = Statements::new();
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::AccumulatorMembership(
        AccumulatorMembershipStmt {
            params: pos_accum_params.clone(),
            public_key: pos_accum_keypair.public_key.clone(),
            proving_key: mem_prk.clone(),
            accumulator_value: pos_accumulator.value().clone(),
        },
    ));
    statements.add(Statement::AccumulatorMembership(
        AccumulatorMembershipStmt {
            params: uni_accum_params.clone(),
            public_key: uni_accum_keypair.public_key.clone(),
            proving_key: derived_mem_prk.clone(),
            accumulator_value: uni_accumulator.value().clone(),
        },
    ));
    statements.add(Statement::AccumulatorNonMembership(
        AccumulatorNonMembershipStmt {
            params: uni_accum_params.clone(),
            public_key: uni_accum_keypair.public_key.clone(),
            proving_key: non_mem_prk.clone(),
            accumulator_value: uni_accumulator.value().clone(),
        },
    ));

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, accum_member_1_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, accum_member_2_idx), (2, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, accum_non_member_idx), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
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

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements,
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce.clone()).unwrap();
}

#[test]
fn pok_of_knowledge_in_pedersen_commitment_and_equality() {
    // Prove knowledge of commitment in Pedersen commitments and equality between committed elements
    let mut rng = StdRng::seed_from_u64(0u64);

    let bases_1 = (0..5)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let scalars_1 = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let commitment_1 = VariableBaseMSM::multi_scalar_mul(
        &bases_1,
        &scalars_1.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
    )
    .into_affine();

    let bases_2 = (0..10)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let mut scalars_2 = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    // Make 2 of the scalars same
    scalars_2[1] = scalars_1[3].clone();
    scalars_2[4] = scalars_1[0].clone();
    let commitment_2 = VariableBaseMSM::multi_scalar_mul(
        &bases_2,
        &scalars_2.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
    )
    .into_affine();

    let mut statements = Statements::new();
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_1.clone(),
        commitment: commitment_1.clone(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_2.clone(),
        commitment: commitment_2.clone(),
    }));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 3), (1, 1)] // 0th statement's 3rd witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let context = Some(b"test".to_vec());

    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements.clone(),
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let nonce = Some(b"test nonce".to_vec());
    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce.clone()).unwrap();

    // Wrong commitment should fail to verify
    let mut statements_wrong = Statements::new();
    statements_wrong.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_1.clone(),
        commitment: commitment_1.clone(),
    }));
    // The commitment is wrong
    statements_wrong.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases_2.clone(),
        commitment: commitment_1.clone(),
    }));

    let proof_spec_invalid = ProofSpec {
        statements: statements_wrong.clone(),
        meta_statements: meta_statements.clone(),
        context: context.clone(),
    };
    assert!(proof_spec_invalid.is_valid());

    let proof = ProofG1::new(
        &mut rng,
        proof_spec_invalid.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();
    assert!(proof.verify(proof_spec_invalid, nonce.clone()).is_err());

    // Wrong message equality should fail to verify
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 3), (1, 0)] // this equality doesn't hold
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let proof_spec_invalid = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements_wrong,
        context: context.clone(),
    };

    let proof = ProofG1::new(
        &mut rng,
        proof_spec_invalid.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    assert!(proof.verify(proof_spec_invalid, nonce).is_err());
}

#[test]
fn pok_of_knowledge_in_pedersen_commitment_and_BBS_plus_sig() {
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
    let commitment = VariableBaseMSM::multi_scalar_mul(
        &bases,
        &scalars.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
    )
    .into_affine();

    let mut statements = Statements::new();
    statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases.clone(),
        commitment: commitment.clone(),
    }));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 0), (1, 1)] // 0th statement's 0th witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 5), (1, 4)] // 0th statement's 5th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements.clone(),
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses.add(Witness::PedersenCommitment(scalars.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce.clone()).unwrap();

    // Wrong message equality should fail to verify
    let mut meta_statements_wrong = MetaStatements::new();
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 3), (1, 0)] // this equality doesn't hold
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 5), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let proof_spec_invalid = ProofSpec {
        statements: statements.clone(),
        meta_statements: meta_statements_wrong,
        context: nonce.clone(),
    };

    let proof = ProofG1::new(
        &mut rng,
        proof_spec_invalid.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    assert!(proof.verify(proof_spec_invalid, nonce).is_err());
}

#[test]
fn requesting_partially_blind_BBS_plus_sig() {
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
    statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: bases.clone(),
        commitment: commitment.clone(),
    }));

    test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec {
        statements: statements.clone(),
        meta_statements: MetaStatements::new(),
        context: context.clone(),
    };
    assert!(proof_spec.is_valid());

    test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(committed_msgs));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let nonce = Some(b"test nonce".to_vec());
    let proof = ProofG1::new(
        &mut rng,
        proof_spec.clone(),
        witnesses.clone(),
        nonce.clone(),
    )
    .unwrap();

    test_serialization!(ProofG1, proof);

    proof.verify(proof_spec, nonce).unwrap();

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

    let mut statements = Statements::<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>::new();
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_2.clone(),
        keypair_2.public_key.clone(),
        BTreeMap::new(),
    ));

    let invalid_eq_wit = EqualWitnesses(vec![(0, 1)].into_iter().collect::<BTreeSet<WitnessRef>>());
    assert!(!invalid_eq_wit.is_valid());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(invalid_eq_wit));

    let invalid_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements,
        None,
    );
    assert!(!invalid_proof_spec.is_valid());

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

    assert!(ProofG1::new(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None
    )
    .is_err());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 5), (2, 4)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let invalid_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements,
        None,
    );
    assert!(ProofG1::new(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None
    )
    .is_err());

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 8), (1, 4)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    let invalid_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements,
        None,
    );
    assert!(ProofG1::new(
        &mut rng,
        invalid_proof_spec.clone(),
        witnesses.clone(),
        None
    )
    .is_err());

    // Verifier creates proof spec with meta statements, prover modifies it to remove meta-statement
    let valid_eq_wit = EqualWitnesses(
        vec![(0, 5), (1, 9)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add(MetaStatement::WitnessEquality(valid_eq_wit));

    // Verifier's created proof spec
    let orig_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        meta_statements,
        None,
    );

    // Prover's modified proof spec
    let modified_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        MetaStatements::new(),
        None,
    );

    // Proof created using modified proof spec wont be a valid
    let invalid_proof = ProofG1::new(
        &mut rng,
        modified_proof_spec.clone(),
        witnesses.clone(),
        None,
    )
    .unwrap();

    // Above proof is valid if verified using the modified proof spec but not with the original proof spec
    invalid_proof
        .clone()
        .verify(modified_proof_spec.clone(), None)
        .unwrap();
    assert!(invalid_proof.verify(orig_proof_spec.clone(), None).is_err());

    // Proof created using original proof spec will be valid
    let valid_proof =
        ProofG1::new(&mut rng, orig_proof_spec.clone(), witnesses.clone(), None).unwrap();
    valid_proof.verify(orig_proof_spec.clone(), None).unwrap();

    // Verifier creates proof spec with 2 statements, prover modifies it to remove a statement
    let orig_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        statements.clone(),
        MetaStatements::new(),
        None,
    );

    // Prover's modified proof spec
    let mut only_1_statement =
        Statements::<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>::new();
    only_1_statement.add(PoKSignatureBBSG1Stmt::new_as_statement(
        params_1.clone(),
        keypair_1.public_key.clone(),
        BTreeMap::new(),
    ));
    let modified_proof_spec = ProofSpec::new_with_statements_and_meta_statements(
        only_1_statement.clone(),
        MetaStatements::new(),
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
    let invalid_proof = ProofG1::new(
        &mut rng,
        modified_proof_spec.clone(),
        only_1_witness.clone(),
        None,
    )
    .unwrap();

    // Above proof is valid if verified using the modified proof spec but not with the original proof spec
    invalid_proof
        .clone()
        .verify(modified_proof_spec.clone(), None)
        .unwrap();
    assert!(invalid_proof.verify(orig_proof_spec.clone(), None).is_err());

    // Proof created using original proof spec will be valid
    let valid_proof =
        ProofG1::new(&mut rng, orig_proof_spec.clone(), witnesses.clone(), None).unwrap();
    valid_proof.verify(orig_proof_spec.clone(), None).unwrap();
}

#[test]
fn verifier_local_linkability() {
    // A verifier wants to attach a unique identifier to a prover without either learning anything unintended (by prover) from the prover's signature nor can that unique identifier be used by other verifiers to identify the prover,
    // eg. a seller (as a verifier) should be able to identify repeat customers (prover) by using a unique identifier but he should not be able to share that unique identifier with other sellers using their own identifier for that prover.
    // This is done by making the prover go through a one-time registration process with the verifier by creating a Pedersen commitment to some value in the signature(s) which the verifier persists, lets call it registration commitment.
    // At each subsequent proof, the prover resends the commitment with the proof that commitment contains message from the prover's signature (prover had persisted commitment and randomness) and the verifier checks that the commitment is
    // same as the one during registration. The registration commitment serves as an identifier.

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
        VariableBaseMSM::multi_scalar_mul(&gens_1, &[msgs[1].into_repr(), blinding_1.into_repr()])
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
        VariableBaseMSM::multi_scalar_mul(&gens_2, &[msgs[1].into_repr(), blinding_2.into_repr()])
            .into_affine();

    // The prover must persist `blinding_2` and `commitment_2` as long as he ever wants to interact with verifier 2.

    // The commitments are different for both verifiers for the same message
    assert_ne!(reg_commit_1, reg_commit_2);

    // Prover proves to verifier 1
    let mut statements_1 = Statements::new();
    statements_1.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements_1.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: gens_1.clone(),
        commitment: reg_commit_1.clone(),
    }));

    let mut meta_statements_1 = MetaStatements::new();
    meta_statements_1.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let context = Some(b"For verifier 1".to_vec());
    let proof_spec_1 = ProofSpec {
        statements: statements_1.clone(),
        meta_statements: meta_statements_1.clone(),
        context: context.clone(),
    };
    assert!(proof_spec_1.is_valid());

    let mut witnesses_1 = Witnesses::new();
    witnesses_1.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_1.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_1.clone(),
    ]));

    let proof_1 = ProofG1::new(&mut rng, proof_spec_1.clone(), witnesses_1.clone(), None).unwrap();

    proof_1.verify(proof_spec_1, None).unwrap();

    // Prover proves to verifier 2
    let mut statements_2 = Statements::new();
    statements_2.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: BTreeMap::new(),
    }));
    statements_2.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: gens_2.clone(),
        commitment: reg_commit_2.clone(),
    }));

    let mut meta_statements_2 = MetaStatements::new();
    meta_statements_2.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let context = Some(b"For verifier 2".to_vec());
    let proof_spec_2 = ProofSpec {
        statements: statements_2.clone(),
        meta_statements: meta_statements_2.clone(),
        context: context.clone(),
    };
    assert!(proof_spec_2.is_valid());

    let mut witnesses_2 = Witnesses::new();
    witnesses_2.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().map(|t| t).collect(),
    ));
    witnesses_2.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_2.clone(),
    ]));

    let proof_2 = ProofG1::new(&mut rng, proof_spec_2.clone(), witnesses_2.clone(), None).unwrap();

    proof_2.verify(proof_spec_2, None).unwrap();

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
    statements_3.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
        params: sig_params.clone(),
        public_key: sig_keypair.public_key.clone(),
        revealed_messages: revealed_msgs,
    }));
    statements_3.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
        bases: gens_1.clone(),
        commitment: reg_commit_1.clone(),
    }));

    let mut meta_statements_3 = MetaStatements::new();
    meta_statements_3.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(0, 1), (1, 0)] // 0th statement's 0th witness is equal to 1st statement's 0th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let context = Some(b"For verifier 1, revealing messages this time".to_vec());
    let proof_spec_3 = ProofSpec {
        statements: statements_3.clone(),
        meta_statements: meta_statements_3.clone(),
        context: context.clone(),
    };
    assert!(proof_spec_3.is_valid());

    let mut witnesses_3 = Witnesses::new();
    witnesses_3.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        unrevealed_msgs,
    ));
    witnesses_3.add(Witness::PedersenCommitment(vec![
        msgs[1].clone(),
        blinding_1.clone(),
    ]));

    let proof_3 = ProofG1::new(&mut rng, proof_spec_3.clone(), witnesses_3.clone(), None).unwrap();

    proof_3.verify(proof_spec_3, None).unwrap();
}
