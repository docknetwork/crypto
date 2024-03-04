use crate::r1cs::get_r1cs_and_wasm_bytes;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::{
    prelude::{KeypairG2, SignatureG1},
    setup::SignatureParamsG1,
};
use blake2::Blake2b512;
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, SetupParams, Statements,
        Witness, WitnessRef, Witnesses,
    },
    proof::Proof,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        r1cs_legogroth16::{
            R1CSCircomProver as R1CSProverStmt, R1CSCircomVerifier as R1CSVerifierStmt,
        },
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[test]
fn pok_of_bbs_plus_sigs_and_sum_of_certain_attributes_less_than_check() {
    // Prove knowledge of 12 signatures and prove that the sum of certain message from each signature satisfies
    // a public upper bound (sum < given public value)

    let mut rng = StdRng::seed_from_u64(0);

    let msg_per_sig = 4;
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, msg_per_sig);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params);

    // Following message index in each signature will be included in the sum
    let msg_idx = 3;
    let mut msgs = vec![];
    let mut sigs = vec![];

    let mut sum = Fr::zero();

    // Generate 12 message-sets, each set will be signed
    for i in 0..12 {
        msgs.push(vec![]);
        for j in 0..msg_per_sig as usize {
            msgs[i].push(Fr::from(u64::rand(&mut rng)));
            if j == msg_idx {
                sum += msgs[i][j];
            }
        }
        sigs.push(
            SignatureG1::<Bls12_381>::new(&mut rng, &msgs[i], &keypair.secret_key, &params)
                .unwrap(),
        );
    }

    // The sum of messages should be less than this value
    let sum_bound = sum + Fr::one();

    // All 12 messages whose sum is being taken should be committed to
    let commit_witness_count = 12;

    let start = Instant::now();
    // Circom code for following in tests/r1cs/circom/circuits/sum_12_less_than_public.circom
    let (sum_snark_pk, sum_r1cs, sum_wasm_bytes) = get_r1cs_and_wasm_bytes(
        "tests/r1cs/circom/bls12-381/sum_12_less_than_public.r1cs",
        "tests/r1cs/circom/bls12-381/sum_12_less_than_public.wasm",
        commit_witness_count,
        &mut rng,
    );
    println!(
        "Creating circuit and proving key for bounded sum takes {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_setup_params = Vec::<SetupParams<Bls12_381>>::new();
    prover_setup_params.push(SetupParams::BBSPlusSignatureParams(params.clone()));
    prover_setup_params.push(SetupParams::BBSPlusPublicKey(keypair.public_key.clone()));
    prover_setup_params.push(SetupParams::R1CS(sum_r1cs));
    prover_setup_params.push(SetupParams::Bytes(sum_wasm_bytes));
    prover_setup_params.push(SetupParams::LegoSnarkProvingKey(sum_snark_pk.clone()));

    let mut prover_statements = Statements::new();

    for _ in 0..12 {
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params_ref(
            0,
            BTreeMap::new(),
        ));
    }

    prover_statements.add(R1CSProverStmt::new_statement_from_params_ref(2, 3, 4).unwrap());

    let mut meta_statements = MetaStatements::new();
    // Enforce equality between the R1CS witness and BBS+ signed message included in the sum
    for i in 0..12 {
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(i, msg_idx), (12, i)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));
    }

    let proof_spec_prover = ProofSpec::new(
        prover_statements.clone(),
        meta_statements.clone(),
        prover_setup_params,
        None,
    );
    proof_spec_prover.validate().unwrap();

    let mut witnesses = Witnesses::new();
    for i in 0..12 {
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sigs[i].clone(),
            msgs[i].clone().into_iter().enumerate().collect(),
        ));
    }

    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    let mut wits = vec![];
    for i in 0..12 {
        wits.push(msgs[i][msg_idx]);
    }
    // All the messages to add are given as in array
    r1cs_wit.set_private("in".to_string(), wits);
    // The bound is public
    r1cs_wit.set_public("max".to_string(), vec![sum_bound]);
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover,
        witnesses.clone(),
        None,
        Default::default(),
    )
    .unwrap()
    .0;

    println!("Creating proof for bounded sum takes {:?}", start.elapsed());

    let start = Instant::now();
    let mut verifier_setup_params = vec![];
    verifier_setup_params.push(SetupParams::BBSPlusSignatureParams(params));
    verifier_setup_params.push(SetupParams::BBSPlusPublicKey(keypair.public_key.clone()));
    verifier_setup_params.push(SetupParams::LegoSnarkVerifyingKey(sum_snark_pk.vk));
    verifier_setup_params.push(SetupParams::FieldElemVec(vec![Fr::one(), sum_bound]));

    let mut verifier_statements = Statements::new();

    for _ in 0..12 {
        verifier_statements.add(
            PoKSignatureBBSG1VerifierStmt::new_statement_from_params_ref(0, 1, BTreeMap::new()),
        );
    }

    verifier_statements.add(R1CSVerifierStmt::new_statement_from_params_ref(3, 2).unwrap());

    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        verifier_setup_params,
        None,
    );
    verifier_proof_spec.validate().unwrap();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
        .unwrap();
    println!(
        "Verifying proof for bounded sum takes {:?}",
        start.elapsed()
    );
}
