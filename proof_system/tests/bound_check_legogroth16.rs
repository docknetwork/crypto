use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{prelude::StdRng, SeedableRng},
};
use blake2::Blake2b512;
use std::time::Instant;

use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, Proof, ProofSpec, ProverConfig, VerifierConfig, Witness,
        WitnessRef, Witnesses,
    },
    prover::OldLegoGroth16Proof,
    setup_params::SetupParams,
    statement::{
        bbs_23::{
            PoKBBSSignature23G1Prover as PoKSignatureBBS23G1ProverStmt,
            PoKBBSSignature23G1Verifier as PoKSignatureBBS23G1VerifierStmt,
        },
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        bound_check_legogroth16::{
            BoundCheckLegoGroth16Prover as BoundCheckProverStmt,
            BoundCheckLegoGroth16Verifier as BoundCheckVerifierStmt,
        },
        Statements,
    },
    sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check,
    witness::{
        PoKBBSSignature23G1 as PoKSignatureBBS23G1Wit, PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
    },
};

use test_utils::{bbs::*, test_serialization};

macro_rules! gen_tests {
    ($test1_name: ident, $test2_name: ident, $setup_fn_name: ident, $prover_stmt: ident, $verifier_stmt: ident, $wit: ident) => {
        #[test]
        fn $test1_name() {
            // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message < max.
            let mut rng = StdRng::seed_from_u64(0u64);

            let min = 100;
            let max = 200;
            let msg_count = 5;
            let msgs = (0..msg_count)
                .map(|i| Fr::from(min + 1 + i as u64))
                .collect::<Vec<_>>();
            let (sig_params, sig_keypair, sig) = $setup_fn_name(&mut rng, &msgs);

            // Verifier sets up LegoGroth16 public parameters for bound check circuit. Ideally this should be
            // done only once per verifier and can be published by the verifier for any proofs submitted to him
            let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

            // Following message's bounds will be checked
            let msg_idx = 1;
            let msg = msgs[msg_idx];

            let mut prover_statements = Statements::new();
            prover_statements.add($prover_stmt::new_statement_from_params(
                sig_params.clone(),
                BTreeMap::new(),
            ));
            prover_statements
                .add(BoundCheckProverStmt::new_statement_from_params(min, max, snark_pk.clone()).unwrap());

            let mut meta_statements = MetaStatements::new();
            meta_statements.add_witness_equality(EqualWitnesses(
                vec![(0, msg_idx), (1, 0)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            ));

            test_serialization!(Statements<Bls12_381>, prover_statements);
            test_serialization!(MetaStatements, meta_statements);

            let proof_spec_prover = ProofSpec::new(
                prover_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            proof_spec_prover.validate().unwrap();
            let start = Instant::now();
            test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);
            println!(
                "Testing serialization for 1 bound check takes {:?}",
                start.elapsed()
            );

            let mut witnesses = Witnesses::new();
            witnesses.add($wit::new_as_witness(
                sig.clone(),
                msgs.clone().into_iter().enumerate().collect(),
            ));
            witnesses.add(Witness::BoundCheckLegoGroth16(msg));

            test_serialization!(Witnesses<Bls12_381>, witnesses);

            let start = Instant::now();
            let (proof, comm_rand) = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                proof_spec_prover.clone(),
                witnesses.clone(),
                None,
                Default::default(),
            )
            .unwrap();
            println!(
                "Time taken to create proof of LegoGroth16 bound check of 1 message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );

            test_serialization!(Proof<Bls12_381>, proof);

            let mut verifier_statements = Statements::new();
            verifier_statements.add($verifier_stmt::new_statement_from_params(
                sig_params,
                sig_keypair.public_key.clone(),
                BTreeMap::new(),
            ));
            verifier_statements
                .add(BoundCheckVerifierStmt::new_statement_from_params(min, max, snark_pk.vk).unwrap());

            test_serialization!(Statements<Bls12_381>, verifier_statements);

            let verifier_proof_spec = ProofSpec::new(
                verifier_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            verifier_proof_spec.validate().unwrap();

            test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

            let start = Instant::now();
            proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec.clone(),
                    None,
                    Default::default(),
                )
                .unwrap();
            println!(
                "Time taken to verify proof of LegoGroth16 bound check of 1 message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );
            proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec.clone(),
                    None,
                    VerifierConfig {
                        use_lazy_randomized_pairing_checks: Some(false),
                    },
                )
                .unwrap();

            let start = Instant::now();
            let mut m = BTreeMap::new();
            let p = proof.get_legogroth16_proof(1).unwrap();
            m.insert(
                1,
                OldLegoGroth16Proof(*(comm_rand.get(&1).unwrap()), (*p).clone()),
            );
            let config = ProverConfig::<Bls12_381> {
                reuse_saver_proofs: None,
                reuse_legogroth16_proofs: Some(m),
            };
            let proof = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                proof_spec_prover.clone(),
                witnesses.clone(),
                None,
                config,
            )
            .unwrap()
            .0;
            println!(
                "Time taken to create proof with re-randomization of bound check of 1 message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );
            proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec.clone(),
                    None,
                    Default::default(),
                )
                .unwrap();
            proof
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec.clone(),
                    None,
                    VerifierConfig {
                        use_lazy_randomized_pairing_checks: Some(false),
                    },
                )
                .unwrap();

            // Correct message used in proof creation but meta statement is specifying equality with another message
            let mut meta_statements_wrong = MetaStatements::new();
            meta_statements_wrong.add_witness_equality(EqualWitnesses(
                vec![(0, 0), (1, 0)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            ));
            let proof_spec_prover = ProofSpec::new(
                prover_statements.clone(),
                meta_statements_wrong.clone(),
                vec![],
                None,
            );
            proof_spec_prover.validate().unwrap();

            let proof = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                proof_spec_prover,
                witnesses.clone(),
                None,
                Default::default(),
            )
            .unwrap()
            .0;

            let proof_spec_verifier = ProofSpec::new(
                verifier_statements.clone(),
                meta_statements_wrong,
                vec![],
                None,
            );
            proof_spec_verifier.validate().unwrap();
            assert!(proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    proof_spec_verifier.clone(),
                    None,
                    Default::default()
                )
                .is_err());
            assert!(proof
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    proof_spec_verifier,
                    None,
                    VerifierConfig {
                        use_lazy_randomized_pairing_checks: Some(false),
                    },
                )
                .is_err());

            // Prove bound over a message which was not signed
            let mut witnesses_wrong = Witnesses::new();
            witnesses_wrong.add($wit::new_as_witness(
                sig,
                msgs.clone().into_iter().enumerate().collect(),
            ));
            witnesses_wrong.add(Witness::BoundCheckLegoGroth16(Fr::from(min)));

            let proof_spec_prover =
                ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);
            proof_spec_prover.validate().unwrap();

            let proof = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                proof_spec_prover,
                witnesses_wrong,
                None,
                Default::default(),
            )
            .unwrap()
            .0;
            let proof_spec_verifier = ProofSpec::new(verifier_statements, meta_statements, vec![], None);
            proof_spec_verifier.validate().unwrap();
            assert!(proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    proof_spec_verifier.clone(),
                    None,
                    Default::default()
                )
                .is_err());
            assert!(proof
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    proof_spec_verifier,
                    None,
                    VerifierConfig {
                        use_lazy_randomized_pairing_checks: Some(false),
                    },
                )
                .is_err());
        }

        #[test]
        fn $test2_name() {
            // Prove knowledge of BBS+ signature and certain messages satisfy some bounds.
            fn check(reuse_key: bool) {
                let mut rng = StdRng::seed_from_u64(0u64);

                let min_1 = 50;
                let max_1 = 200;
                let min_2 = 40;
                let max_2 = 300;
                let min_3 = 30;
                let max_3 = 380;
                let msg_count = 5;
                let msgs = (0..msg_count)
                    .map(|i| Fr::from(101u64 + i as u64))
                    .collect::<Vec<_>>();
                let (sig_params, sig_keypair, sig) = $setup_fn_name(&mut rng, &msgs);

                // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
                // verifier and can be published by the verifier for any proofs submitted to him
                let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

                // Following messages' bounds will be checked
                let msg_idx_1 = 1;
                let msg_idx_2 = 2;
                let msg_idx_3 = 4;
                let msg_1 = msgs[msg_idx_1];
                let msg_2 = msgs[msg_idx_2];
                let msg_3 = msgs[msg_idx_3];

                let mut prover_setup_params = vec![];
                if reuse_key {
                    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(snark_pk.clone()));
                    test_serialization!(Vec<SetupParams<Bls12_381>>, prover_setup_params);
                }

                let mut prover_statements = Statements::new();
                prover_statements.add($prover_stmt::new_statement_from_params(
                    sig_params.clone(),
                    BTreeMap::new(),
                ));
                if reuse_key {
                    prover_statements
                        .add(BoundCheckProverStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap());
                    prover_statements
                        .add(BoundCheckProverStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap());
                    prover_statements
                        .add(BoundCheckProverStmt::new_statement_from_params_ref(min_3, max_3, 0).unwrap());
                } else {
                    prover_statements.add(
                        BoundCheckProverStmt::new_statement_from_params(min_1, max_1, snark_pk.clone())
                            .unwrap(),
                    );
                    prover_statements.add(
                        BoundCheckProverStmt::new_statement_from_params(min_2, max_2, snark_pk.clone())
                            .unwrap(),
                    );
                    prover_statements.add(
                        BoundCheckProverStmt::new_statement_from_params(min_3, max_3, snark_pk.clone())
                            .unwrap(),
                    );
                }

                test_serialization!(Statements<Bls12_381>, prover_statements);

                let mut meta_statements = MetaStatements::new();
                meta_statements.add_witness_equality(EqualWitnesses(
                    vec![(0, msg_idx_1), (1, 0)]
                        .into_iter()
                        .collect::<BTreeSet<WitnessRef>>(),
                ));
                meta_statements.add_witness_equality(EqualWitnesses(
                    vec![(0, msg_idx_2), (2, 0)]
                        .into_iter()
                        .collect::<BTreeSet<WitnessRef>>(),
                ));
                meta_statements.add_witness_equality(EqualWitnesses(
                    vec![(0, msg_idx_3), (3, 0)]
                        .into_iter()
                        .collect::<BTreeSet<WitnessRef>>(),
                ));

                let prover_proof_spec = ProofSpec::new(
                    prover_statements.clone(),
                    meta_statements.clone(),
                    prover_setup_params,
                    None,
                );
                prover_proof_spec.validate().unwrap();

                test_serialization!(ProofSpec<Bls12_381>, prover_proof_spec);

                let mut witnesses = Witnesses::new();
                witnesses.add($wit::new_as_witness(
                    sig,
                    msgs.clone().into_iter().enumerate().collect(),
                ));
                witnesses.add(Witness::BoundCheckLegoGroth16(msg_1));
                witnesses.add(Witness::BoundCheckLegoGroth16(msg_2));
                witnesses.add(Witness::BoundCheckLegoGroth16(msg_3));

                let start = Instant::now();
                let (proof, comm_rand) = Proof::new::<StdRng, Blake2b512>(
                    &mut rng,
                    prover_proof_spec.clone(),
                    witnesses.clone(),
                    None,
                    Default::default(),
                )
                .unwrap();
                println!(
                    "Time taken to create proof of bound check of 3 messages in signature over {} messages: {:?}",
                    msg_count,
                    start.elapsed()
                );

                test_serialization!(Proof<Bls12_381>, proof);

                let mut verifier_setup_params = vec![];
                if reuse_key {
                    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(snark_pk.vk.clone()));
                    test_serialization!(Vec<SetupParams<Bls12_381>>, verifier_setup_params);
                }

                let mut verifier_statements = Statements::new();
                verifier_statements.add($verifier_stmt::new_statement_from_params(
                    sig_params,
                    sig_keypair.public_key.clone(),
                    BTreeMap::new(),
                ));
                if reuse_key {
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params_ref(min_1, max_1, 0).unwrap(),
                    );
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params_ref(min_2, max_2, 0).unwrap(),
                    );
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params_ref(min_3, max_3, 0).unwrap(),
                    );
                } else {
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params(
                            min_1,
                            max_1,
                            snark_pk.vk.clone(),
                        )
                        .unwrap(),
                    );
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params(
                            min_2,
                            max_2,
                            snark_pk.vk.clone(),
                        )
                        .unwrap(),
                    );
                    verifier_statements.add(
                        BoundCheckVerifierStmt::new_statement_from_params(min_3, max_3, snark_pk.vk)
                            .unwrap(),
                    );
                }

                test_serialization!(Statements<Bls12_381>, verifier_statements);

                let verifier_proof_spec = ProofSpec::new(
                    verifier_statements.clone(),
                    meta_statements.clone(),
                    verifier_setup_params,
                    None,
                );
                verifier_proof_spec.validate().unwrap();

                test_serialization!(ProofSpec<Bls12_381>, verifier_proof_spec);

                let start = Instant::now();
                proof
                    .clone()
                    .verify::<StdRng, Blake2b512>(
                        &mut rng,
                        verifier_proof_spec.clone(),
                        None,
                        Default::default(),
                    )
                    .unwrap();
                println!(
                    "Time taken to verify proof of bound check of 3 messages in signature over {} messages: {:?}",
                    msg_count,
                    start.elapsed()
                );
                let start = Instant::now();
                proof
                    .clone()
                    .verify::<StdRng, Blake2b512>(
                        &mut rng,
                        verifier_proof_spec.clone(),
                        None,
                        VerifierConfig {
                            use_lazy_randomized_pairing_checks: Some(false),
                        },
                    )
                    .unwrap();
                println!(
                    "Time taken to verify proof of bound check of 3 messages in signature over {} messages with randomized pairing check: {:?}",
                    msg_count,
                    start.elapsed()
                );

                let start = Instant::now();
                let mut m = BTreeMap::new();
                for i in 1..=3 {
                    let p = proof.get_legogroth16_proof(i).unwrap();
                    m.insert(
                        i,
                        OldLegoGroth16Proof(*(comm_rand.get(&i).unwrap()), (*p).clone()),
                    );
                }
                let config = ProverConfig::<Bls12_381> {
                    reuse_saver_proofs: None,
                    reuse_legogroth16_proofs: Some(m),
                };
                let proof = Proof::new::<StdRng, Blake2b512>(
                    &mut rng,
                    prover_proof_spec.clone(),
                    witnesses.clone(),
                    None,
                    config,
                )
                .unwrap()
                .0;
                println!(
                    "Time taken to create proof with re-randomization of bound check of 3 messages in signature over {} messages: {:?}",
                    msg_count,
                    start.elapsed()
                );
                proof
                    .verify::<StdRng, Blake2b512>(
                        &mut rng,
                        verifier_proof_spec.clone(),
                        None,
                        Default::default(),
                    )
                    .unwrap();
            }
            check(false);
            check(true);
        }
    }
}

gen_tests!(
    pok_of_bbs_plus_sig_and_bounded_message,
    pok_of_bbs_plus_sig_and_many_bounded_messages,
    bbs_plus_sig_setup_given_messages,
    PoKSignatureBBSG1ProverStmt,
    PoKSignatureBBSG1VerifierStmt,
    PoKSignatureBBSG1Wit
);
gen_tests!(
    pok_of_bbs_sig_and_bounded_message,
    pok_of_bbs_sig_and_many_bounded_messages,
    bbs_sig_setup_given_messages,
    PoKSignatureBBS23G1ProverStmt,
    PoKSignatureBBS23G1VerifierStmt,
    PoKSignatureBBS23G1Wit
);

#[test]
fn pok_of_bbs_plus_sig_and_message_same_as_bound() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message < max.
    // Here message set as min
    let mut rng = StdRng::seed_from_u64(0u64);

    let min = 100;
    let max = 200;
    let msg_count = 5;
    let msgs = (0..msg_count)
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();
    let (sig_params, sig_keypair, sig) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs);

    // Verifier sets up LegoGroth16 public parameters. Ideally this should be done only once per
    // verifier and can be published by the verifier for any proofs submitted to him
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();

    // Following message's bounds will be checked
    let msg_idx = 1;
    let msg = msgs[msg_idx];

    // Message same as minimum
    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        BoundCheckProverStmt::new_statement_from_params(
            msg.into_bigint().as_ref()[0],
            max,
            snark_pk.clone(),
        )
        .unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, msg_idx), (1, 0)]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
    ));
    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_prover.validate().unwrap();

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig.clone(),
        msgs.clone().into_iter().enumerate().collect(),
    ));
    witnesses.add(Witness::BoundCheckLegoGroth16(msg));

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params.clone(),
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));
    verifier_statements.add(
        BoundCheckVerifierStmt::new_statement_from_params(
            msg.into_bigint().as_ref()[0],
            max,
            snark_pk.vk.clone(),
        )
        .unwrap(),
    );
    let proof_spec_verifier = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    proof_spec_verifier.validate().unwrap();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec_verifier, None, Default::default())
        .unwrap();
}
