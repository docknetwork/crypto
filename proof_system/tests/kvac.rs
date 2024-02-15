use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use kvac::bddt_2016::mac::MAC;
use proof_system::{
    meta_statement::{EqualWitnesses, MetaStatements, WitnessRef},
    proof::Proof,
    proof_spec::ProofSpec,
    setup_params::SetupParams,
    statement::{
        accumulator::keyed_verification::{
            VBAccumulatorMembershipKV, VBAccumulatorMembershipKVFullVerifier,
        },
        bddt16_kvac::{PoKOfMAC, PoKOfMACFullVerifier},
        Statements,
    },
    witness::{Membership as MembershipWit, PoKOfBDDT16MAC, Witnesses},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use test_utils::{accumulators::setup_positive_accum, kvac::bddt16_mac_setup, test_serialization};
use vb_accumulator::positive::Accumulator;

#[test]
fn proof_of_knowledge_of_macs_and_equality_of_messages_and_kv_accumulator() {
    // Prove knowledge of 3 KVAC and membership in accumulator. Membership proof verification is keyed
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count_1 = 6;
    let (msgs_1, params_1, sk_1, mac_1) = bddt16_mac_setup(&mut rng, msg_count_1 as u32);

    let msg_count_2 = 10;
    let (mut msgs_2, params_2, sk_2, _) = bddt16_mac_setup(&mut rng, msg_count_2 as u32);

    let msg_count_3 = 12;
    let (mut msgs_3, params_3, sk_3, _) = bddt16_mac_setup(&mut rng, msg_count_3 as u32);

    // Make 3 messages same
    msgs_2[9] = msgs_1[5];
    msgs_3[9] = msgs_1[5];
    msgs_2[8] = msgs_1[4];
    msgs_3[8] = msgs_1[4];
    msgs_2[7] = msgs_1[3];
    msgs_3[7] = msgs_1[3];

    msgs_3[5] = msgs_3[7];

    let mac_2 = MAC::<G1Affine>::new(&mut rng, &msgs_2, &sk_2, &params_2).unwrap();
    mac_2.verify(&msgs_2, &sk_2, &params_2).unwrap();

    let mac_3 = MAC::<G1Affine>::new(&mut rng, &msgs_3, &sk_3, &params_3).unwrap();
    mac_3.verify(&msgs_3, &sk_3, &params_3).unwrap();

    let (_, pos_accum_keypair, mut pos_accumulator, mut pos_state) = setup_positive_accum(&mut rng);

    // Message with index `accum_member_1_idx` is added in the positive VB accumulator
    let accum_member_1_idx = 1;
    let accum_member_1 = msgs_1[accum_member_1_idx];
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

    // Prepare revealed messages for the proof of knowledge of 1st MAC
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

    // Prepare revealed messages for the proof of knowledge of 2nd MAC
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

    // Prove knowledge of 3 MACs, add 3 statements
    let mut statements = Statements::new();
    statements.add(PoKOfMAC::new_statement_from_params(
        params_1.clone(),
        revealed_msgs_1.clone(),
    ));
    statements.add(PoKOfMAC::new_statement_from_params(
        params_2.clone(),
        revealed_msgs_2.clone(),
    ));
    statements.add(PoKOfMAC::new_statement_from_params(
        params_3.clone(),
        BTreeMap::new(),
    ));
    statements.add(VBAccumulatorMembershipKV::new(*pos_accumulator.value()));

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

    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, accum_member_1_idx), (3, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));

    test_serialization!(Statements<Bls12_381>, statements);
    test_serialization!(MetaStatements, meta_statements);

    // Create a proof spec, this is shared between prover and verifier
    // Context must be known to both prover and verifier
    let context = Some(b"test".to_vec());
    let proof_spec = ProofSpec::new(statements, meta_statements.clone(), vec![], context.clone());
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    // Prover now creates/loads it witnesses corresponding to the proof spec
    let mut witnesses = Witnesses::new();
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_1,
        unrevealed_msgs_1.clone(),
    ));
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_2,
        unrevealed_msgs_2.clone(),
    ));
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(mac_3, unrevealed_msgs_3));
    witnesses.add(MembershipWit::new_as_witness(
        accum_member_1,
        mem_1_wit.clone(),
    ));

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
    println!("Time to verify proof with 3 MACs: {:?}", start.elapsed());

    let mut statements = Statements::new();
    statements.add(PoKOfMACFullVerifier::new_statement_from_params(
        sk_1,
        params_1,
        revealed_msgs_1.clone(),
    ));
    statements.add(PoKOfMACFullVerifier::new_statement_from_params(
        sk_2,
        params_2,
        revealed_msgs_2.clone(),
    ));
    statements.add(PoKOfMACFullVerifier::new_statement_from_params(
        sk_3,
        params_3,
        BTreeMap::new(),
    ));
    statements.add(VBAccumulatorMembershipKVFullVerifier::new(
        *pos_accumulator.value(),
        pos_accum_keypair.secret_key.clone(),
    ));
    let proof_spec = ProofSpec::new(statements, meta_statements, vec![], context);
    proof_spec.validate().unwrap();

    // Verifier verifies the full proof
    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, nonce, Default::default())
        .unwrap();
    println!(
        "Time to verify full proof with 3 MACs: {:?}",
        start.elapsed()
    );
}

#[test]
fn pok_of_knowledge_of_macs_with_reusing_setup_params() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let msg_count = 5;
    let (msgs_1, params_1, sk_1, mac_1) = bddt16_mac_setup(&mut rng, msg_count as u32);
    let (msgs_2, params_2, sk_2, mac_2) = bddt16_mac_setup(&mut rng, msg_count as u32);

    let msgs_3: Vec<Fr> = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect();
    let mac_3 = MAC::<G1Affine>::new(&mut rng, &msgs_3, &sk_1, &params_1).unwrap();
    let msgs_4: Vec<Fr> = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect();
    let mac_4 = MAC::<G1Affine>::new(&mut rng, &msgs_4, &sk_2, &params_2).unwrap();

    let mut all_setup_params = vec![];
    all_setup_params.push(SetupParams::BDDT16MACParams(params_1.clone()));
    all_setup_params.push(SetupParams::BDDT16MACParams(params_2.clone()));

    test_serialization!(Vec<SetupParams<Bls12_381>>, all_setup_params);

    let mut statements = Statements::new();
    statements.add(PoKOfMAC::new_statement_from_params_ref(0, BTreeMap::new()));
    statements.add(PoKOfMAC::new_statement_from_params_ref(0, BTreeMap::new()));
    statements.add(PoKOfMAC::new_statement_from_params_ref(1, BTreeMap::new()));
    statements.add(PoKOfMAC::new_statement_from_params_ref(1, BTreeMap::new()));

    test_serialization!(Statements<Bls12_381>, statements);

    let proof_spec = ProofSpec::new(
        statements,
        MetaStatements::new(),
        all_setup_params.clone(),
        None,
    );
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_1,
        msgs_1
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_3,
        msgs_3
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_2,
        msgs_2
            .iter()
            .enumerate()
            .map(|(i, m)| (i, *m))
            .collect::<BTreeMap<_, _>>(),
    ));
    witnesses.add(PoKOfBDDT16MAC::new_as_witness(
        mac_4,
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
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
        .unwrap();
    println!("Time to verify proof with 4 MACs: {:?}", start.elapsed());

    let mut statements = Statements::new();
    statements.add(PoKOfMACFullVerifier::new_statement_from_params_ref(
        sk_1.clone(),
        0,
        BTreeMap::new(),
    ));
    statements.add(PoKOfMACFullVerifier::new_statement_from_params_ref(
        sk_1,
        0,
        BTreeMap::new(),
    ));
    statements.add(PoKOfMACFullVerifier::new_statement_from_params_ref(
        sk_2.clone(),
        1,
        BTreeMap::new(),
    ));
    statements.add(PoKOfMACFullVerifier::new_statement_from_params_ref(
        sk_2,
        1,
        BTreeMap::new(),
    ));

    let proof_spec = ProofSpec::new(statements, MetaStatements::new(), all_setup_params, None);
    proof_spec.validate().unwrap();

    test_serialization!(ProofSpec<Bls12_381>, proof_spec);

    let start = Instant::now();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
        .unwrap();
    println!(
        "Time to verify full proof with 4 MACs: {:?}",
        start.elapsed()
    );
}