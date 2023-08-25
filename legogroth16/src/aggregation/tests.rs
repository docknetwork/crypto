use crate::{
    aggregation::{groth16, legogroth16, srs, srs::PreparedProverSRS},
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{Field, One};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};
use ark_snark::SNARK;
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
use std::{marker::PhantomData, time::Instant};

pub struct Benchmark<F: Field> {
    num_constraints: usize,
    _engine: PhantomData<F>,
}

impl<F: Field> Benchmark<F> {
    pub fn new(num_constraints: usize) -> Self {
        Self {
            num_constraints,
            _engine: PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for Benchmark<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut assignments = Vec::new();
        let mut a_val = F::one();
        let mut a_var = cs.new_input_variable(|| Ok(a_val))?;
        assignments.push((a_val, a_var));

        let mut b_val = F::one();
        let mut b_var = cs.new_input_variable(|| Ok(b_val))?;
        assignments.push((a_val, a_var));

        for i in 0..self.num_constraints - 1 {
            if i % 2 != 0 {
                let c_val = a_val * &b_val;
                let c_var = cs.new_witness_variable(|| Ok(c_val))?;

                cs.enforce_constraint(lc!() + a_var, lc!() + b_var, lc!() + c_var)?;

                assignments.push((c_val, c_var));
                a_val = b_val;
                a_var = b_var;
                b_val = c_val;
                b_var = c_var;
            } else {
                let c_val = a_val + &b_val;
                let c_var = cs.new_witness_variable(|| Ok(c_val))?;

                cs.enforce_constraint(lc!() + a_var + b_var, lc!() + Variable::One, lc!() + c_var)?;

                assignments.push((c_val, c_var));
                a_val = b_val;
                a_var = b_var;
                b_val = c_val;
                b_var = c_var;
            }
        }

        let mut a_lc = LinearCombination::zero();
        let mut b_lc = LinearCombination::zero();
        let mut c_val = F::zero();

        for (val, var) in assignments {
            a_lc = a_lc + var;
            b_lc = b_lc + var;
            c_val = c_val + &val;
        }
        c_val = c_val.square();

        let c_var = cs.new_witness_variable(|| Ok(c_val))?;

        cs.enforce_constraint(lc!() + a_lc, lc!() + b_lc, lc!() + c_var)?;

        Ok(())
    }
}

pub struct Multiply<F: Field> {
    pub num_constraints: usize,
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for Multiply<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        for _ in 0..self.num_constraints {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }
        Ok(())
    }
}

#[test]
fn legogroth16_aggregation() {
    let num_constraints = 1000;
    let nproofs = 8;
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = {
        let c = Benchmark::<Fr>::new(num_constraints);
        generate_random_parameters::<Bls12_381, _, _>(c, 10, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = prepare_verifying_key(&params.vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    let prepared_srs = PreparedProverSRS::from(prover_srs.clone());

    // create all the proofs
    // let mut vs = vec![];
    let proofs = (0..nproofs)
        .map(|_| {
            let c = Benchmark::new(num_constraints);
            let v = Fr::rand(&mut rng);
            create_random_proof(c, v, &params, &mut rng).expect("proof creation failed")
        })
        .collect::<Vec<_>>();
    // verify we can at least verify one
    let inputs: Vec<_> = [Fr::one(); 2].to_vec();
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>();

    let start = Instant::now();
    for i in 0..nproofs as usize {
        verify_proof(&pvk, &proofs[i], &inputs).unwrap();
    }
    println!(
        "Time to verify {} LegoGroth16 proofs one by one {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof_ =
        legogroth16::aggregate_proofs(prover_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGroth16 proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof =
        legogroth16::aggregate_proofs(prepared_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGroth16 proofs using prepared SRS: {:?}",
        nproofs,
        start.elapsed()
    );
    assert_eq!(aggregate_proof, aggregate_proof_);

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    legogroth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} LegoGroth16 proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let (aggregate_proof_, d_) = legogroth16::using_groth16::aggregate_proofs(
        prover_srs.clone(),
        &mut prover_transcript,
        &proofs,
    )
    .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} proofs using groth16 scheme: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let (aggregate_proof, d) = legogroth16::using_groth16::aggregate_proofs(
        prepared_srs.clone(),
        &mut prover_transcript,
        &proofs,
    )
    .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} proofs using groth16 scheme and prepared SRS: {:?}",
        nproofs,
        start.elapsed()
    );
    assert_eq!(aggregate_proof, aggregate_proof_);
    assert_eq!(d, d_);

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    legogroth16::using_groth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &d,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} proofs using groth16 scheme: {:?}",
        nproofs,
        start.elapsed()
    );
}

#[test]
fn legogroth16_aggregation_multiply() {
    let num_constraints = 1000;
    let nproofs = 32;
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = {
        let c = Multiply {
            num_constraints,
            a: None,
            b: None,
        };
        generate_random_parameters::<Bls12_381, _, _>(c, 2, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = prepare_verifying_key(&params.vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    let prepared_srs = PreparedProverSRS::from(prover_srs.clone());

    // create all the proofs
    let mut all_inputs = vec![];
    let proofs = (1..=nproofs)
        .map(|i| {
            let a = Fr::from(10 * i as u64);
            let b = Fr::from(20 * i as u64);
            all_inputs.push(vec![a * b]);
            let v = Fr::rand(&mut rng);
            create_random_proof(
                Multiply {
                    num_constraints,
                    a: Some(a),
                    b: Some(b),
                },
                v,
                &params,
                &mut rng,
            )
            .expect("proof creation failed")
        })
        .collect::<Vec<_>>();

    // verify one by one
    let start = Instant::now();
    for i in 0..nproofs as usize {
        verify_proof(&pvk, &proofs[i], &all_inputs[i]).unwrap();
    }
    println!(
        "Time to verify {} LegoGroth16 proofs one by one {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof_ =
        legogroth16::aggregate_proofs(prover_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGroth16 proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof =
        legogroth16::aggregate_proofs(prepared_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGroth16 proofs using prepared SRS: {:?}",
        nproofs,
        start.elapsed()
    );
    assert_eq!(aggregate_proof, aggregate_proof_);

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    legogroth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let (aggregate_proof_, d_) = legogroth16::using_groth16::aggregate_proofs(
        prover_srs.clone(),
        &mut prover_transcript,
        &proofs,
    )
    .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGorth16 proofs using groth16 scheme: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let (aggregate_proof, d) = legogroth16::using_groth16::aggregate_proofs(
        prepared_srs.clone(),
        &mut prover_transcript,
        &proofs,
    )
    .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} LegoGorth16 proofs using groth16 scheme using prepared SRS: {:?}",
        nproofs,
        start.elapsed()
    );
    assert_eq!(aggregate_proof, aggregate_proof_);
    assert_eq!(d, d_);

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    legogroth16::using_groth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &d,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} proofs using groth16 scheme: {:?}",
        nproofs,
        start.elapsed()
    );
}

#[test]
fn groth16_aggregation() {
    let num_constraints = 1000;
    let nproofs = 8;
    let mut rng = StdRng::seed_from_u64(0u64);
    let (pk, vk) = {
        let c = Benchmark::<Fr>::new(num_constraints);
        ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(c, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    let prepared_srs = PreparedProverSRS::from(prover_srs.clone());

    // create all the proofs
    // let mut vs = vec![];
    let proofs = (0..nproofs)
        .map(|_| {
            let c = Benchmark::new(num_constraints);
            ark_groth16::Groth16::<Bls12_381>::prove(&pk, c, &mut rng)
                .expect("proof creation failed")
        })
        .collect::<Vec<_>>();
    // verify we can at least verify one
    let inputs: Vec<_> = [Fr::one(); 2].to_vec();
    let all_inputs = (0..nproofs).map(|_| inputs.clone()).collect::<Vec<_>>();

    let start = Instant::now();
    for i in 0..nproofs as usize {
        ark_groth16::Groth16::<Bls12_381>::verify_proof(&pvk, &proofs[i], &inputs).unwrap();
    }
    println!(
        "Time to verify {} proofs one by one {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof =
        groth16::aggregate_proofs(prepared_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    groth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} proofs: {:?}",
        nproofs,
        start.elapsed()
    );
}

#[test]
fn groth16_aggregation_multiply() {
    let num_constraints = 1000;
    let nproofs = 32;
    let mut rng = StdRng::seed_from_u64(0u64);
    let (pk, vk) = {
        let c = Multiply {
            num_constraints,
            a: None,
            b: None,
        };
        ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(c, &mut rng).unwrap()
    };
    // prepare the verification key
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    // prepare the SRS needed for snarkpack - specialize after to the right
    // number of proofs
    let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, nproofs);
    let (prover_srs, ver_srs) = srs.specialize(nproofs);
    let prepared_srs = PreparedProverSRS::from(prover_srs.clone());

    // create all the proofs
    let mut all_inputs = vec![];
    let proofs = (1..=nproofs)
        .map(|i| {
            let a = Fr::from(10 * i as u64);
            let b = Fr::from(20 * i as u64);
            all_inputs.push(vec![a * b]);
            ark_groth16::Groth16::<Bls12_381>::prove(
                &pk,
                Multiply {
                    num_constraints,
                    a: Some(a),
                    b: Some(b),
                },
                &mut rng,
            )
            .expect("proof creation failed")
        })
        .collect::<Vec<_>>();

    // verify one by one
    let start = Instant::now();
    for i in 0..nproofs as usize {
        ark_groth16::Groth16::<Bls12_381>::verify_proof(&pvk, &proofs[i], &all_inputs[i]).unwrap();
    }
    println!(
        "Time to verify {} proofs one by one {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut prover_transcript = new_merlin_transcript(b"test aggregation");
    prover_transcript.append(b"public-inputs", &all_inputs);
    let aggregate_proof =
        groth16::aggregate_proofs(prepared_srs.clone(), &mut prover_transcript, &proofs)
            .expect("error in aggregation");
    println!(
        "Time to create aggregate proofs from {} proofs: {:?}",
        nproofs,
        start.elapsed()
    );

    let start = Instant::now();
    let mut ver_transcript = new_merlin_transcript(b"test aggregation");
    ver_transcript.append(b"public-inputs", &all_inputs);
    groth16::verify_aggregate_proof(
        &ver_srs,
        &pvk,
        &all_inputs,
        &aggregate_proof,
        &mut rng,
        &mut ver_transcript,
        None,
    )
    .expect("error in verification");
    println!(
        "Time to verify aggregate proofs from {} proofs: {:?}",
        nproofs,
        start.elapsed()
    );
}
