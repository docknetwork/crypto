use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{One, Zero};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use legogroth16::circom::{CircomCircuit, R1CS};
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, ProofSpec, R1CSCircomWitness, Statements, Witness,
        WitnessRef, Witnesses,
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
use std::collections::{BTreeMap, BTreeSet};

use crate::r1cs::abs_path;
use test_utils::bbs::*;

#[test]
fn pok_of_bbs_plus_sig_and_set_membership() {
    // Prove knowledge of a signature and that a specific signed message member/non-member of a public set

    let mut rng = StdRng::seed_from_u64(0u64);
    let msg_count = 7;
    let (msgs, sig_params, sig_keypair, sig) = bbs_plus_sig_setup(&mut rng, msg_count);

    // A public set which will not contain any of the signed messages
    let mut public_set = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    // This message index's membership/non-membership will be checked
    let member_msg_idx = 3;

    let commit_witness_count = 1;
    // Circom code for following in tests/r1cs/circom/circuits/set_membership_5_public.circom
    let r1cs_file_path = "tests/r1cs/circom/bls12-381/set_membership_5_public.r1cs";
    let wasm_file_path = "tests/r1cs/circom/bls12-381/set_membership_5_public.wasm";
    let circuit = CircomCircuit::<Bls12_381>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();
    let snark_pk = circuit
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    let r1cs = R1CS::from_file(abs_path(r1cs_file_path)).unwrap();
    let wasm_bytes = std::fs::read(abs_path(wasm_file_path)).unwrap();

    let mut prover_statements = Statements::new();
    prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
        sig_params.clone(),
        BTreeMap::new(),
    ));
    prover_statements.add(
        R1CSProverStmt::new_statement_from_params(r1cs, wasm_bytes, snark_pk.clone()).unwrap(),
    );

    let mut meta_statements = MetaStatements::new();
    meta_statements.add_witness_equality(EqualWitnesses(
        vec![(0, member_msg_idx), (1, 0)]
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
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("x".to_string(), vec![msgs[member_msg_idx]]);
    r1cs_wit.set_public("set".to_string(), public_set.clone());
    witnesses.add(Witness::R1CSLegoGroth16(r1cs_wit));

    let proof = Proof::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec_prover.clone(),
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

    // The 1st public input will be 0 indicating that the message is not present in the set
    let mut public_inputs = vec![Fr::zero()];
    public_inputs.extend(&public_set);

    verifier_statements.add(
        R1CSVerifierStmt::new_statement_from_params(public_inputs, snark_pk.vk.clone()).unwrap(),
    );
    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
        .unwrap();

    // -------------------------------------------------------------------------------------- //

    // Update set to contain the signed message
    public_set[2] = msgs[member_msg_idx];

    let mut witnesses = Witnesses::new();
    witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
        sig,
        msgs.clone().into_iter().enumerate().collect(),
    ));
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    r1cs_wit.set_private("x".to_string(), vec![msgs[member_msg_idx]]);
    r1cs_wit.set_public("set".to_string(), public_set.clone());
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

    let mut verifier_statements = Statements::new();
    verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
        sig_params,
        sig_keypair.public_key.clone(),
        BTreeMap::new(),
    ));

    // The 1st public input will be 1 indicating that the message is present in the set
    let mut public_inputs = vec![Fr::one()];
    public_inputs.extend(&public_set);

    verifier_statements
        .add(R1CSVerifierStmt::new_statement_from_params(public_inputs, snark_pk.vk).unwrap());
    let verifier_proof_spec = ProofSpec::new(
        verifier_statements.clone(),
        meta_statements.clone(),
        vec![],
        None,
    );
    verifier_proof_spec.validate().unwrap();
    proof
        .verify::<StdRng, Blake2b512>(&mut rng, verifier_proof_spec, None, Default::default())
        .unwrap();
}
