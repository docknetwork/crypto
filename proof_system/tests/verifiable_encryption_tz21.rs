use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use dock_crypto_utils::elgamal::keygen;
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, VerifierConfig, Witness, WitnessRef, Witnesses,
    },
    proof::Proof,
    setup_params::ElgamalEncryptionParams,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        verifiable_encryption_tz_21::VerifiableEncryptionTZ21,
        Statements,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
use test_utils::{bbs::*, test_serialization};

macro_rules! gen_tests {
    ($test1_name: ident, $test2_name: ident, $stmt_func_name: ident, $wit_variant: ident, $cptxt_getter: ident) => {
        #[test]
        fn $test1_name() {
            let mut rng = StdRng::seed_from_u64(0u64);
            let enc_gen = G1Affine::rand(&mut rng);
            let (dec_key, enc_key) = keygen::<_, G1Affine>(&mut rng, &enc_gen);

            let msg_count = 5;
            let (msgs, sig_params, sig_keypair, sig) = bbs_plus_sig_setup(&mut rng, msg_count);

            // Message with index `enc_msg_idx` is verifiably encrypted
            let enc_msg_idx = 1;
            let enc_msg = msgs[enc_msg_idx];

            // +1 as the commitment to the encrypted message will have the randomness as well which is encrypted as well.
            let comm_key_for_ve = (0..1 + 1)
                .map(|_| G1Affine::rand(&mut rng))
                .collect::<Vec<_>>();

            let mut prover_statements = Statements::new();
            prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
                sig_params.clone(),
                BTreeMap::new(),
            ));
            prover_statements.add(VerifiableEncryptionTZ21::$stmt_func_name(
                ElgamalEncryptionParams {
                    g: enc_gen,
                    public_key: enc_key.0,
                },
                comm_key_for_ve.clone(),
            ));

            let mut meta_statements = MetaStatements::new();
            meta_statements.add_witness_equality(EqualWitnesses(
                vec![(0, enc_msg_idx), (1, 0)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            ));

            test_serialization!(Statements<Bls12_381>, prover_statements);
            test_serialization!(MetaStatements, meta_statements);

            let prover_proof_spec = ProofSpec::new(
                prover_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            prover_proof_spec.validate().unwrap();

            let mut witnesses = Witnesses::new();
            witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
                sig.clone(),
                msgs.clone().into_iter().enumerate().collect(),
            ));
            witnesses.add(Witness::$wit_variant(vec![enc_msg]));

            test_serialization!(Witnesses<Bls12_381>, witnesses);

            let start = Instant::now();
            let (proof, _) = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                prover_proof_spec.clone(),
                witnesses.clone(),
                None,
                Default::default(),
            )
            .unwrap();

            println!(
                "Time taken to create proof of 1 encrypted message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );

            test_serialization!(Proof<Bls12_381>, proof);

            let mut verifier_statements = Statements::new();
            verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
                sig_params,
                sig_keypair.public_key.clone(),
                BTreeMap::new(),
            ));
            verifier_statements.add(VerifiableEncryptionTZ21::$stmt_func_name(
                ElgamalEncryptionParams {
                    g: enc_gen,
                    public_key: enc_key.0,
                },
                comm_key_for_ve.clone(),
            ));

            let verifier_proof_spec = ProofSpec::new(
                verifier_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            verifier_proof_spec.validate().unwrap();

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
                "Time taken to verify proof of 1 encrypted message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );

            let start = Instant::now();
            let (ct, comm) = proof
                .$cptxt_getter::<Blake2b512>(1)
                .unwrap();
            println!(
                "Time taken to get (compressed) ciphertext of 1 encrypted message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );

            let start = Instant::now();
            assert_eq!(
                ct.decrypt::<Blake2b512>(&dec_key.0, &comm, &comm_key_for_ve)
                    .unwrap()[..1],
                [enc_msg]
            );
            println!(
                "Time taken to decrypt ciphertext of 1 encrypted message in signature over {} messages {:?}",
                msg_count,
                start.elapsed()
            );

            // Correct message verifiably encrypted but meta statement is specifying equality with another message
            let mut meta_statements_wrong = MetaStatements::new();
            meta_statements_wrong.add_witness_equality(EqualWitnesses(
                vec![(0, 0), (1, 0)]
                    .into_iter()
                    .collect::<BTreeSet<WitnessRef>>(),
            ));
            let prover_proof_spec = ProofSpec::new(
                prover_statements.clone(),
                meta_statements_wrong.clone(),
                vec![],
                None,
            );
            prover_proof_spec.validate().unwrap();

            let proof = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                prover_proof_spec,
                witnesses.clone(),
                None,
                Default::default(),
            )
            .unwrap()
            .0;

            let verifier_proof_spec = ProofSpec::new(
                verifier_statements.clone(),
                meta_statements_wrong,
                vec![],
                None,
            );
            verifier_proof_spec.validate().unwrap();
            assert!(proof
                .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
                .is_err());

            // Verifiably encrypt a message which was not signed
            let mut witnesses_wrong = Witnesses::new();
            witnesses_wrong.add(PoKSignatureBBSG1Wit::new_as_witness(
                sig,
                msgs.into_iter().enumerate().collect(),
            ));
            witnesses_wrong.add(Witness::$wit_variant(vec![Fr::rand(&mut rng)]));

            let prover_proof_spec =
                ProofSpec::new(prover_statements, meta_statements.clone(), vec![], None);
            prover_proof_spec.validate().unwrap();

            let proof = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                prover_proof_spec,
                witnesses_wrong,
                None,
                Default::default(),
            )
            .unwrap()
            .0;

            let verifier_proof_spec =
                ProofSpec::new(verifier_statements.clone(), meta_statements, vec![], None);
            verifier_proof_spec.validate().unwrap();
            assert!(proof
                .clone()
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec.clone(),
                    None,
                    Default::default()
                )
                .is_err());
            assert!(proof
                .verify::<StdRng, Blake2b512>(
                    &mut rng,
                    verifier_proof_spec,
                    None,
                    VerifierConfig {
                        use_lazy_randomized_pairing_checks: Some(false),
                    },
                )
                .is_err());
        }

        #[test]
        fn $test2_name() {
            let mut rng = StdRng::seed_from_u64(0u64);
            let enc_gen = G1Affine::rand(&mut rng);
            let (dec_key, enc_key) = keygen::<_, G1Affine>(&mut rng, &enc_gen);

            let msg_count = 5;
            let (msgs, sig_params, sig_keypair, sig) = bbs_plus_sig_setup(&mut rng, msg_count);

            // Message with following indices are verifiably encrypted
            let enc_msg_indices = vec![0, 2, 3];
            let enc_msgs = enc_msg_indices.iter().map(|i| msgs[*i]).collect::<Vec<_>>();

            // +1 as the commitment to the encrypted messages will have the randomness as well which is encrypted as well.
            let comm_key_for_ve = (0..enc_msgs.len() + 1)
                .map(|_| G1Affine::rand(&mut rng))
                .collect::<Vec<_>>();

            let mut prover_statements = Statements::new();
            prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
                sig_params.clone(),
                BTreeMap::new(),
            ));
            prover_statements.add(VerifiableEncryptionTZ21::$stmt_func_name(
                ElgamalEncryptionParams {
                    g: enc_gen,
                    public_key: enc_key.0,
                },
                comm_key_for_ve.clone(),
            ));

            let mut meta_statements = MetaStatements::new();
            for (i, j) in enc_msg_indices.iter().enumerate() {
                meta_statements.add_witness_equality(EqualWitnesses(
                    vec![(0, *j), (1, i)]
                        .into_iter()
                        .collect::<BTreeSet<WitnessRef>>(),
                ));
            }

            let prover_proof_spec = ProofSpec::new(
                prover_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            prover_proof_spec.validate().unwrap();

            let mut witnesses = Witnesses::new();
            witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
                sig.clone(),
                msgs.clone().into_iter().enumerate().collect(),
            ));
            witnesses.add(Witness::$wit_variant(enc_msgs.clone()));

            let start = Instant::now();
            let (proof, _) = Proof::new::<StdRng, Blake2b512>(
                &mut rng,
                prover_proof_spec.clone(),
                witnesses.clone(),
                None,
                Default::default(),
            )
            .unwrap();

            println!(
                "Time taken to create proof of {} encrypted message in signature over {} messages {:?}",
                enc_msg_indices.len(),
                msg_count,
                start.elapsed()
            );

            test_serialization!(Proof<Bls12_381>, proof);

            let mut verifier_statements = Statements::new();
            verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
                sig_params,
                sig_keypair.public_key.clone(),
                BTreeMap::new(),
            ));
            verifier_statements.add(VerifiableEncryptionTZ21::$stmt_func_name(
                ElgamalEncryptionParams {
                    g: enc_gen,
                    public_key: enc_key.0,
                },
                comm_key_for_ve.clone(),
            ));

            let verifier_proof_spec = ProofSpec::new(
                verifier_statements.clone(),
                meta_statements.clone(),
                vec![],
                None,
            );
            verifier_proof_spec.validate().unwrap();

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
                "Time taken to verify proof of {} encrypted message in signature over {} messages {:?}",
                enc_msg_indices.len(),
                msg_count,
                start.elapsed()
            );

            let start = Instant::now();
            let (ct, comm) = proof
                .$cptxt_getter::<Blake2b512>(1)
                .unwrap();
            println!(
                "Time taken to get (compressed) ciphertext of {} encrypted message in signature over {} messages {:?}",
                enc_msg_indices.len(),
                msg_count,
                start.elapsed()
            );

            let start = Instant::now();
            assert_eq!(
                ct.decrypt::<Blake2b512>(&dec_key.0, &comm, &comm_key_for_ve)
                    .unwrap()[..enc_msg_indices.len()]
                    .to_vec(),
                enc_msgs
            );
            println!(
                "Time taken to decrypt ciphertext of {} encrypted message in signature over {} messages {:?}",
                enc_msg_indices.len(),
                msg_count,
                start.elapsed()
            );
        }
    }
}

gen_tests!(
    pok_of_bbs_plus_sig_and_verifiable_encryption_using_tz21,
    pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages_using_tz21,
    new_statement_from_params,
    VeTZ21,
    get_tz21_ciphertext_and_commitment
);

gen_tests!(
    pok_of_bbs_plus_sig_and_verifiable_encryption_using_tz21_robust,
    pok_of_bbs_plus_sig_and_verifiable_encryption_of_many_messages_using_tz21_robust,
    new_statement_from_params_for_robust,
    VeTZ21Robust,
    get_tz21_robust_ciphertext_and_commitment
);
