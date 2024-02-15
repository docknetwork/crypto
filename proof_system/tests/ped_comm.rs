use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::BTreeSet,
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use proof_system::{
    prelude::{EqualWitnesses, MetaStatement, MetaStatements, Witness, WitnessRef, Witnesses},
    proof::Proof,
    proof_spec::ProofSpec,
    setup_params::SetupParams,
    statement::{ped_comm::PedersenCommitment as PedersenCommitmentStmt, Statements},
};

use test_utils::test_serialization;

#[test]
fn pok_of_knowledge_in_pedersen_commitment_and_equality() {
    // Prove knowledge of commitment in Pedersen commitments and equality between committed elements
    let mut rng = StdRng::seed_from_u64(0u64);

    let bases_1 = (0..5)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let scalars_1 = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let commitment_1 = G1Projective::msm_bigint(
        &bases_1,
        &scalars_1
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let bases_2 = (0..10)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let mut scalars_2 = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    // Make 2 of the scalars same
    scalars_2[1] = scalars_1[3];
    scalars_2[4] = scalars_1[0];
    let commitment_2 = G1Projective::msm_bigint(
        &bases_2,
        &scalars_2
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let bases_3 = (0..5)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let commitment_3 = G2Projective::msm_bigint(
        &bases_3,
        &scalars_1
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let bases_4 = (0..10)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let commitment_4 = G2Projective::msm_bigint(
        &bases_4,
        &scalars_2
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let mut statements = Statements::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases_1.clone(),
        commitment_1,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases_2.clone(),
        commitment_2,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_g2(
        bases_3.clone(),
        commitment_3,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_g2(
        bases_4.clone(),
        commitment_4,
    ));

    test_serialization!(Statements<Bls12_381>, statements);

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
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(2, 3), (3, 1)] // 0th statement's 3rd witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(2, 0), (3, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let context = Some(b"test".to_vec());

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

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

    // Wrong commitment should fail to verify
    let mut statements_wrong = Statements::new();
    statements_wrong.add(PedersenCommitmentStmt::new_statement_from_params(
        bases_1,
        commitment_1,
    ));
    // The commitment is wrong
    statements_wrong.add(PedersenCommitmentStmt::new_statement_from_params(
        bases_2,
        commitment_1,
    ));
    statements_wrong.add(PedersenCommitmentStmt::new_statement_from_params_g2(
        bases_3,
        commitment_3,
    ));
    statements_wrong.add(PedersenCommitmentStmt::new_statement_from_params_g2(
        bases_4,
        commitment_4,
    ));

    let proof_spec_invalid = ProofSpec::new(
        statements_wrong.clone(),
        meta_statements.clone(),
        vec![],
        context.clone(),
    );
    proof_spec_invalid.validate().unwrap();

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
        .verify::<StdRng, Blake2b512>(
            &mut rng,
            proof_spec_invalid,
            nonce.clone(),
            Default::default()
        )
        .is_err());

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
fn pok_of_knowledge_in_pedersen_commitment_and_equality_with_commitment_key_reuse() {
    // Prove knowledge of commitment in Pedersen commitments and equality between committed elements using
    // setup params
    let mut rng = StdRng::seed_from_u64(0u64);

    let count = 5;
    let bases = (0..count)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let bases_2 = (0..count)
        .map(|_| G2Projective::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();

    let scalars_1 = (0..count).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let mut scalars_2 = (0..count).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    // Make 2 of the scalars same
    scalars_2[1] = scalars_1[3];
    scalars_2[4] = scalars_1[0];
    let scalars_3 = (0..count).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let commitment_1 = G1Projective::msm_bigint(
        &bases,
        &scalars_1
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();
    let commitment_2 = G1Projective::msm_bigint(
        &bases,
        &scalars_2
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();
    let commitment_3 = G1Projective::msm_bigint(
        &bases,
        &scalars_3
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let commitment_4 = G2Projective::msm_bigint(
        &bases_2,
        &scalars_1
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();
    let commitment_5 = G2Projective::msm_bigint(
        &bases_2,
        &scalars_2
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();
    let commitment_6 = G2Projective::msm_bigint(
        &bases_2,
        &scalars_3
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>(),
    )
    .into_affine();

    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::PedersenCommitmentKey(bases));
    all_setup_params.push(SetupParams::PedersenCommitmentKeyG2(bases_2));

    test_serialization!(Vec<SetupParams<Bls12_381>>, all_setup_params);

    let mut statements = Statements::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs(
        0,
        commitment_1,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs(
        0,
        commitment_2,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs(
        0,
        commitment_3,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs_g2(
        1,
        commitment_4,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs_g2(
        1,
        commitment_5,
    ));
    statements.add(PedersenCommitmentStmt::new_statement_from_params_refs_g2(
        1,
        commitment_6,
    ));

    test_serialization!(Statements<Bls12_381>, statements);

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
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(3, 3), (4, 1)] // 0th statement's 3rd witness is equal to 1st statement's 1st witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));
    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
        vec![(3, 0), (4, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    )));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_3.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));
    witnesses.add(Witness::PedersenCommitment(scalars_3.clone()));

    test_serialization!(Witnesses<Bls12_381>, witnesses);

    let context = Some(b"test".to_vec());

    let proof_spec = ProofSpec::new(
        statements.clone(),
        meta_statements.clone(),
        all_setup_params,
        context,
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

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
}
