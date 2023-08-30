use crate::{
    circom::{
        circuit::{tests::set_circuit_wires, CircomCircuit},
        witness::WitnessCalculator,
    },
    create_random_proof, generate_random_parameters_incl_cp_link, prepare_verifying_key,
    tests::get_link_public_gens,
    verify_proof, verify_witness_commitment, ProvingKey, ProvingKeyWithLink,
};
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use std::{
    collections::{BTreeSet, HashMap},
    ops::AddAssign,
    path::PathBuf,
};

/// Given path relative to this crate, return absolute disk path
pub fn abs_path(relative_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative_path);
    path.to_string_lossy().to_string()
}

pub fn gen_params<E: Pairing>(
    commit_witness_count: u32,
    circuit: CircomCircuit<E>,
) -> (ProvingKeyWithLink<E>, ProvingKey<E>) {
    let mut rng = StdRng::seed_from_u64(0);
    let link_gens = get_link_public_gens(&mut rng, commit_witness_count + 1);
    let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
        circuit.clone(),
        link_gens.clone(),
        commit_witness_count,
        &mut rng,
    )
    .unwrap();
    // Parameters for generating proof without CP_link
    let params = circuit
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();
    (params_link, params)
}

pub fn prove_and_verify_circuit<E: Pairing>(
    circuit: CircomCircuit<E>,
    params: &ProvingKey<E>,
    commit_witness_count: u32,
) -> Vec<E::ScalarField> {
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    let public_inputs = circuit.get_public_inputs().unwrap();
    let committed_witnesses = circuit
        .wires
        .clone()
        .unwrap()
        .into_iter()
        .skip(1 + public_inputs.len())
        .take(commit_witness_count as usize)
        .collect::<Vec<_>>();
    // Randomness for the committed witness in proof.d
    let mut rng = StdRng::seed_from_u64(300u64);
    let v = E::ScalarField::rand(&mut rng);
    let proof = create_random_proof(circuit, v, params, &mut rng).unwrap();
    println!("Proof generated");

    let pvk = prepare_verifying_key::<E>(&params.vk);
    // Prover verifies the openings of the commitments in proof.d
    verify_witness_commitment(
        &params.vk,
        &proof,
        public_inputs.len(),
        &committed_witnesses,
        &v,
    )
    .unwrap();
    verify_proof(&pvk, &proof, &public_inputs).unwrap();
    println!("Proof verified");
    return public_inputs;
}

pub fn generate_params_prove_and_verify<
    E: Pairing,
    I: IntoIterator<Item = (String, Vec<E::ScalarField>)>,
>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    inputs: I,
    num_inputs: u32,
) -> Vec<E::ScalarField> {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(commit_witness_count, circuit.clone());
    println!("Params generated");

    let mut wits_calc = WitnessCalculator::<E>::from_wasm_file(wasm_file_path).unwrap();
    let all_wires = wits_calc.calculate_witnesses::<I>(inputs, true).unwrap();

    assert_eq!(
        wits_calc
            .instance
            .get_input_count(&mut wits_calc.store)
            .unwrap(),
        num_inputs
    );

    circuit.set_wires(all_wires);
    prove_and_verify_circuit(circuit, &params, commit_witness_count)
}

fn multiply2<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), vec![a]);
    inputs.insert("b".to_string(), vec![b]);

    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        2,
        inputs.clone().into_iter(),
        2,
    );

    assert_eq!(public.len(), 1);
    assert_eq!(a * b, public[0]);
}

fn test3<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str) {
    let mut rng = StdRng::seed_from_u64(100);
    let x = E::ScalarField::rand(&mut rng);
    let y = E::ScalarField::rand(&mut rng);
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let c = E::ScalarField::rand(&mut rng);
    let d = E::ScalarField::rand(&mut rng);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), vec![x]);
    inputs.insert("y".to_string(), vec![y]);
    inputs.insert("a".to_string(), vec![a]);
    inputs.insert("b".to_string(), vec![b]);
    inputs.insert("c".to_string(), vec![c]);
    inputs.insert("d".to_string(), vec![d]);

    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        4,
        inputs.clone().into_iter(),
        6,
    );

    assert_eq!(public.len(), 4);
    let expected_z1 = a * x + b * y + c * d;
    assert_eq!(expected_z1, public[0]);
    let expected_z2 = c * x + d * y;
    assert_eq!(expected_z2, public[1]);
    assert_eq!(x, public[2]);
    assert_eq!(y, public[3]);
}

fn test4<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let x = E::ScalarField::rand(&mut rng);
    let y = E::ScalarField::rand(&mut rng);
    let p = E::ScalarField::rand(&mut rng);
    let q = E::ScalarField::rand(&mut rng);
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let r = E::ScalarField::rand(&mut rng);
    let s = E::ScalarField::rand(&mut rng);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), vec![x]);
    inputs.insert("y".to_string(), vec![y]);
    inputs.insert("p".to_string(), vec![p]);
    inputs.insert("q".to_string(), vec![q]);
    inputs.insert("a".to_string(), vec![a]);
    inputs.insert("b".to_string(), vec![b]);
    inputs.insert("r".to_string(), vec![r]);
    inputs.insert("s".to_string(), vec![s]);
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        4,
        inputs.clone().into_iter(),
        8,
    );

    assert_eq!(public.len(), 6);

    let expected_z1 = a * x + b * y + E::ScalarField::from(10u64) * p * q
        - E::ScalarField::from(19u64) * r.square() * r * p
        + E::ScalarField::from(55u64) * s.square().square() * q.square() * q
        - E::ScalarField::from(3u64) * x.square()
        + E::ScalarField::from(6u64) * x * y
        - E::ScalarField::from(13u64) * y.square() * y
        - r * s * x
        + E::ScalarField::from(5u64) * a * b * y
        - E::ScalarField::from(32u64) * a * x * y
        - E::ScalarField::from(2u64) * x * y * p * q
        - E::ScalarField::from(100u64);
    assert_eq!(expected_z1, public[0]);

    let expected_z2 = a.square() * a * y + E::ScalarField::from(3u64) * b.square() * x
        - E::ScalarField::from(20u64) * x.square() * y.square()
        + E::ScalarField::from(45u64);
    assert_eq!(expected_z2, public[1]);

    assert_eq!(a, public[2]);
    assert_eq!(b, public[3]);
    assert_eq!(r, public[4]);
    assert_eq!(s, public[5]);
}

fn nconstraints<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    input: E::ScalarField,
    commit_witness_count: u32,
    num_constraints: u32,
) {
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), vec![input.clone()]);
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        1,
    );
    let mut accum = input;
    for i in 1..num_constraints {
        // accum = accum * accum + i;
        accum.square_in_place();
        accum.add_assign(E::ScalarField::from(i));
    }
    assert_eq!(public[0], accum);
}

fn multiply_n<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    input_arr_size: u32,
) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let mut inputs = HashMap::new();
    let inp = (0..input_arr_size)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();
    inputs.insert("in".to_string(), inp.clone());
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        input_arr_size as u32,
    );
    let mut expected = E::ScalarField::from(1u64);
    for i in inp {
        expected *= i;
    }
    assert_eq!(public[0], expected);
}

fn multiply_2_bounded<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let mut inputs = HashMap::new();
    let mut a = u64::rand(&mut rng);
    while a == 0 {
        a = u64::rand(&mut rng);
    }
    let mut b = u64::rand(&mut rng);
    while b == 0 {
        b = u64::rand(&mut rng);
    }
    inputs.insert("a".to_string(), vec![E::ScalarField::from(a)]);
    inputs.insert("b".to_string(), vec![E::ScalarField::from(b)]);
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        2,
    );
    assert_eq!(public[0], E::ScalarField::from(a as u128 * b as u128));
}

fn mimc<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    input_arr_size: u32,
) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let mut inputs = HashMap::new();
    let inp = (0..input_arr_size)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();
    inputs.insert("in".to_string(), inp.clone());
    inputs.insert("k".to_string(), vec![E::ScalarField::from(0u64)]);
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        input_arr_size as u32 + 1,
    );
    assert_eq!(public.len(), 1);
}

fn mimcsponge<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    input_arr_size: u32,
    output_arr_size: u32,
) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let mut inputs = HashMap::new();
    let inp = (0..input_arr_size)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();
    inputs.insert("in".to_string(), inp.clone());
    inputs.insert("k".to_string(), vec![E::ScalarField::from(0u64)]);
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        input_arr_size as u32 + 1,
    );
    assert_eq!(public.len(), output_arr_size as usize);
}

fn poseidon<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
    input_arr_size: u32,
) {
    let mut rng = StdRng::seed_from_u64(100u64);
    let mut inputs = HashMap::new();
    let inp = (0..input_arr_size)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();
    inputs.insert("in".to_string(), inp.clone());
    let public = generate_params_prove_and_verify::<E, _>(
        r1cs_file_path,
        wasm_file_path,
        commit_witness_count,
        inputs.into_iter(),
        1,
    );
    assert_eq!(public.len(), 1);
}

fn less_than_32_bits<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(commit_witness_count, circuit.clone());

    let mut rng = StdRng::seed_from_u64(100u64);
    for _ in 0..10 {
        let (a, b) = {
            let a = u32::rand(&mut rng);
            let b = u32::rand(&mut rng);
            if a < b {
                (
                    E::ScalarField::from(a as u64),
                    E::ScalarField::from(b as u64),
                )
            } else {
                (
                    E::ScalarField::from(b as u64),
                    E::ScalarField::from(a as u64),
                )
            }
        };

        // `a < b` so output of less_than_32 circuit should be 1.
        let mut inputs = HashMap::new();
        inputs.insert("a".to_string(), vec![a]);
        inputs.insert("b".to_string(), vec![b]);
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 1);
        assert!(public[0].is_one());

        // `a > b` so output of less_than_32 circuit should be 0.
        inputs.insert("a".to_string(), vec![b]);
        inputs.insert("b".to_string(), vec![a]);
        set_circuit_wires(&mut circuit, wasm_file_path, inputs);
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 1);
        assert!(public[0].is_zero());
    }
}

fn all_different_10<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let mut rng = StdRng::seed_from_u64(100u64);
    let params = circuit
        .clone()
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    for _ in 0..10 {
        let mut inp = BTreeSet::new();
        while inp.len() != 10 {
            inp.insert(E::ScalarField::rand(&mut rng));
        }
        let mut inp = inp.into_iter().collect::<Vec<_>>();
        let mut inputs = HashMap::new();
        inputs.insert("in".to_string(), inp.clone());

        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 1);
        assert!(public[0].is_one());

        // Make 1 input same
        inp[5] = inp[1].clone();
        inputs.insert("in".to_string(), inp.clone());
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 1);
        assert!(public[0].is_zero());

        // Make 2 inputs same
        inp[9] = inp[1].clone();
        inputs.insert("in".to_string(), inp.clone());
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 1);
        assert!(public[0].is_zero());
    }
}

fn not_equal_public<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let mut rng = StdRng::seed_from_u64(100u64);
    let params = circuit
        .clone()
        .generate_proving_key(commit_witness_count, &mut rng)
        .unwrap();

    for _ in 0..10 {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut inputs = HashMap::new();

        // Inputs are unequal
        inputs.insert("in".to_string(), vec![a]);
        inputs.insert("pub".to_string(), vec![b]);

        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 2);
        assert!(public[0].is_one());
        assert_eq!(public[1], b);

        // Make inputs equal to make test fail
        inputs.insert("pub".to_string(), vec![a]);
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        assert_eq!(public.len(), 2);
        assert!(public[0].is_zero());
        assert_eq!(public[1], a);
    }
}

fn less_than_public_64_bits<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    commit_witness_count: u32,
) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(commit_witness_count, circuit.clone());

    let mut rng = StdRng::seed_from_u64(100u64);
    for _ in 0..10 {
        let (a, b) = {
            let a = u64::rand(&mut rng);
            let b = u64::rand(&mut rng);
            if a < b {
                (E::ScalarField::from(a), E::ScalarField::from(b))
            } else {
                (E::ScalarField::from(b), E::ScalarField::from(a))
            }
        };

        // `a < b` so output of less_than_32 circuit should be 1.
        let mut inputs = HashMap::new();
        inputs.insert("a".to_string(), vec![a]);
        inputs.insert("b".to_string(), vec![b]);
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        // 2 because there is 1 output signal and 1 public input `b`
        assert_eq!(public.len(), 2);
        assert!(public[0].is_one());
        assert_eq!(public[1], b);

        // `a > b` so output of less_than_32 circuit should be 0.
        inputs.insert("a".to_string(), vec![b]);
        inputs.insert("b".to_string(), vec![a]);
        set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
        let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);
        // 2 because there is 1 output signal and 1 public input `a`
        assert_eq!(public.len(), 2);
        assert!(public[0].is_zero());
        assert_eq!(public[1], a);
    }
}

fn average_n<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str, n: u32) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(n, circuit.clone());

    let mut rng = StdRng::seed_from_u64(100);

    let mut inp = vec![];
    let mut sum = 0u128;
    for _ in 0..n {
        let e = u64::rand(&mut rng);
        sum += e as u128;
        inp.push(E::ScalarField::from(e));
    }

    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), inp);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, n);

    assert_eq!(public.len(), 1);
    assert_eq!(public[0], E::ScalarField::from(sum / n as u128));
}

fn average_n_less_than_public<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str, n: u32) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(n, circuit.clone());

    let mut rng = StdRng::seed_from_u64(100);

    let mut inp = vec![];
    let mut inp_ = vec![];
    let mut sum = 0u128;
    for _ in 0..n {
        let e = u64::rand(&mut rng);
        sum += e as u128;
        inp_.push(e);
        inp.push(E::ScalarField::from(e));
    }

    let max = (sum / n as u128) + 1;

    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), inp);
    inputs.insert("max".to_string(), vec![E::ScalarField::from(max)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    for w in circuit.wires.clone().unwrap().into_iter().take(10) {
        println!("{:?}", w.into_bigint());
    }

    let public = prove_and_verify_circuit(circuit.clone(), &params, n);

    assert_eq!(public.len(), 2);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(max));

    // Using a number greater than 64-bit shouldn't work as the circuit only supports 64 bit inputs
    let greater_than_64_bit = E::ScalarField::from(u64::MAX) + E::ScalarField::from(10u64);
    let mut sum = greater_than_64_bit.clone();
    let mut inp = vec![];
    inp.push(greater_than_64_bit);
    for i in 1..n {
        inp.push(E::ScalarField::from(i));
        sum += inp[i as usize];
    }

    let max = sum;
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), inp);
    inputs.insert("max".to_string(), vec![max]);
    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

fn sum_n_less_than_public<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str, n: u32) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(n, circuit.clone());

    let mut rng = StdRng::seed_from_u64(100);

    let mut inp = vec![];
    let mut sum = 0u128;
    for _ in 1..=n {
        let e = u64::rand(&mut rng);
        sum += e as u128;
        inp.push(E::ScalarField::from(e));
    }
    let max = sum + 1;

    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), inp);
    inputs.insert("max".to_string(), vec![E::ScalarField::from(max)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, n);

    assert_eq!(public.len(), 2);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(max));

    // Using a very large input shouldn't work even when it will make the sum smaller than max
    let p_minus_5 = E::ScalarField::from(0u64) - E::ScalarField::from(5u64); // curve order - 5
    let mut inp = vec![];
    inp.push(p_minus_5);
    for i in 1..n {
        inp.push(E::ScalarField::from(i));
    }
    let max = E::ScalarField::from(300u64);
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), inp);
    inputs.insert("max".to_string(), vec![max]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let cs = ConstraintSystem::<E::ScalarField>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

fn set_membership<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str, set_size: u32) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let (_, params) = gen_params::<E>(1, circuit.clone());

    let mut rng = StdRng::seed_from_u64(0);

    let x = E::ScalarField::rand(&mut rng);
    let mut set = vec![];
    for _ in 1..set_size {
        let e = E::ScalarField::rand(&mut rng);
        set.push(e);
    }
    set.push(x);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), vec![x]);
    inputs.insert("set".to_string(), set.clone());

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, 1);

    assert_eq!(public.len(), 6);
    assert_eq!(public[0], E::ScalarField::one());
    for i in 0..set_size as usize {
        assert_eq!(public[i + 1], set[i]);
    }

    let mut set = vec![];
    for _ in 0..set_size {
        let e = E::ScalarField::rand(&mut rng);
        assert!(x != e);
        set.push(e);
    }

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), vec![x]);
    inputs.insert("set".to_string(), set.clone());

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, 1);

    assert_eq!(public.len(), 6);
    assert_eq!(public[0], E::ScalarField::zero());
    for i in 0..set_size as usize {
        assert_eq!(public[i + 1], set[i]);
    }
}

fn difference_of_array_sum<E: Pairing>(
    r1cs_file_path: &str,
    wasm_file_path: &str,
    arr1_size: u32,
    arr2_size: u32,
) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let commit_witness_count = (arr1_size + arr2_size) as u32;
    let (_, params) = gen_params::<E>(commit_witness_count, circuit.clone());

    let mut rng = StdRng::seed_from_u64(0);

    let mut inp1 = vec![];
    let mut sum1 = 0u128;
    for _ in 0..arr1_size {
        let e = u64::rand(&mut rng);
        sum1 += e as u128;
        inp1.push(E::ScalarField::from(e));
    }

    let mut inp2 = vec![];
    let mut sum2 = 0u128;
    for _ in 0..arr2_size {
        let e = u64::rand(&mut rng);
        sum2 += e as u128;
        inp2.push(E::ScalarField::from(e));
    }

    assert_ne!(sum2, sum1);

    let (inp_a, inp_b, sum_a, sum_b) = if sum2 > sum1 {
        (&inp2, &inp1, sum2, sum1)
    } else {
        (&inp1, &inp2, sum1, sum2)
    };

    // Expecting some difference
    assert!((sum_a - sum_b) > 1);
    let min = sum_a - sum_b - 1u128;

    let mut inputs = HashMap::new();
    inputs.insert("inA".to_string(), inp_a.to_vec());
    inputs.insert("inB".to_string(), inp_b.to_vec());
    inputs.insert("min".to_string(), vec![E::ScalarField::from(min)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);

    assert_eq!(public.len(), 2);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(min));
}

fn greater_than_or_public<E: Pairing>(r1cs_file_path: &str, wasm_file_path: &str) {
    let mut circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

    let commit_witness_count = 2;
    let (_, params) = gen_params::<E>(commit_witness_count, circuit.clone());

    let mut rng = StdRng::seed_from_u64(0);
    let a = u64::rand(&mut rng);
    let b = u64::rand(&mut rng);
    let c = u64::rand(&mut rng);
    let d = u64::rand(&mut rng);

    assert_ne!(a, b);
    assert_ne!(c, d);

    let (big1, small1) = if a > b { (a, b) } else { (b, a) };
    let (big2, small2) = if c > d { (c, d) } else { (d, c) };

    // Both greater than checks satisfy
    let mut inputs = HashMap::new();
    inputs.insert("in1".to_string(), vec![E::ScalarField::from(big1)]);
    inputs.insert("in2".to_string(), vec![E::ScalarField::from(big2)]);
    inputs.insert("in3".to_string(), vec![E::ScalarField::from(small1)]);
    inputs.insert("in4".to_string(), vec![E::ScalarField::from(small2)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);

    assert_eq!(public.len(), 3);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(small1));
    assert_eq!(public[2], E::ScalarField::from(small2));

    // Only 1st greater than check satisfies
    let mut inputs = HashMap::new();
    inputs.insert("in1".to_string(), vec![E::ScalarField::from(big1)]);
    inputs.insert("in2".to_string(), vec![E::ScalarField::from(small2)]);
    inputs.insert("in3".to_string(), vec![E::ScalarField::from(small1)]);
    inputs.insert("in4".to_string(), vec![E::ScalarField::from(big2)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);

    assert_eq!(public.len(), 3);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(small1));
    assert_eq!(public[2], E::ScalarField::from(big2));

    // Only 2nd greater than check satisfies
    let mut inputs = HashMap::new();
    inputs.insert("in1".to_string(), vec![E::ScalarField::from(small1)]);
    inputs.insert("in2".to_string(), vec![E::ScalarField::from(big2)]);
    inputs.insert("in3".to_string(), vec![E::ScalarField::from(big1)]);
    inputs.insert("in4".to_string(), vec![E::ScalarField::from(small2)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);

    assert_eq!(public.len(), 3);
    assert_eq!(public[0], E::ScalarField::from(1u64));
    assert_eq!(public[1], E::ScalarField::from(big1));
    assert_eq!(public[2], E::ScalarField::from(small2));

    // Both greater than checks fail
    let mut inputs = HashMap::new();
    inputs.insert("in1".to_string(), vec![E::ScalarField::from(small1)]);
    inputs.insert("in2".to_string(), vec![E::ScalarField::from(small2)]);
    inputs.insert("in3".to_string(), vec![E::ScalarField::from(big1)]);
    inputs.insert("in4".to_string(), vec![E::ScalarField::from(big2)]);

    set_circuit_wires(&mut circuit, wasm_file_path, inputs.clone());
    let public = prove_and_verify_circuit(circuit.clone(), &params, commit_witness_count);

    assert_eq!(public.len(), 3);
    assert_eq!(public[0], E::ScalarField::from(0u64));
    assert_eq!(public[1], E::ScalarField::from(big1));
    assert_eq!(public[2], E::ScalarField::from(big2));
}

#[test]
fn multiply2_bn128() {
    let r1cs_file_path = "test-vectors/bn128/multiply2.r1cs";
    let wasm_file_path = "test-vectors/bn128/multiply2.wasm";
    multiply2::<Bn254>(r1cs_file_path, wasm_file_path)
}

#[test]
fn multiply2_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/multiply2.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/multiply2.wasm";
    multiply2::<Bls12_381>(r1cs_file_path, wasm_file_path)
}

#[test]
fn test_3_bn128() {
    let r1cs_file_path = "test-vectors/bn128/test3.r1cs";
    let wasm_file_path = "test-vectors/bn128/test3.wasm";
    test3::<Bn254>(r1cs_file_path, wasm_file_path)
}

#[test]
fn test_3_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/test3.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/test3.wasm";
    test3::<Bls12_381>(r1cs_file_path, wasm_file_path)
}

#[test]
fn test_4_bn128() {
    let r1cs_file_path = "test-vectors/bn128/test4.r1cs";
    let wasm_file_path = "test-vectors/bn128/test4.wasm";
    test4::<Bn254>(r1cs_file_path, wasm_file_path)
}

#[test]
fn test_4_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/test4.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/test4.wasm";
    test4::<Bls12_381>(r1cs_file_path, wasm_file_path)
}

#[test]
fn nconstraints_bn128() {
    let r1cs_file_path = "test-vectors/bn128/nconstraints.r1cs";
    let wasm_file_path = "test-vectors/bn128/nconstraints.wasm";
    let num_constraints = 2500;
    let mut rng = StdRng::seed_from_u64(100u64);
    nconstraints::<Bn254>(
        r1cs_file_path,
        wasm_file_path,
        <Bn254 as Pairing>::ScalarField::rand(&mut rng),
        1,
        num_constraints,
    );
}

#[test]
fn nconstraints_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/nconstraints.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/nconstraints.wasm";
    let num_constraints = 2500;
    let mut rng = StdRng::seed_from_u64(100u64);
    nconstraints::<Bls12_381>(
        r1cs_file_path,
        wasm_file_path,
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        1,
        num_constraints,
    );
}

#[test]
fn multiply_n_bn128() {
    let r1cs_file_path = "test-vectors/bn128/multiply_n.r1cs";
    let wasm_file_path = "test-vectors/bn128/multiply_n.wasm";
    let input_arr_size = 300;
    multiply_n::<Bn254>(
        r1cs_file_path,
        wasm_file_path,
        input_arr_size,
        input_arr_size,
    );
}

#[test]
fn multiply_n_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/multiply_n.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/multiply_n.wasm";
    let input_arr_size = 300;
    multiply_n::<Bls12_381>(
        r1cs_file_path,
        wasm_file_path,
        input_arr_size,
        input_arr_size,
    );
}

#[test]
fn multiply2_bounded_bn128() {
    let r1cs_file_path = "test-vectors/bn128/multiply2_bounded.r1cs";
    let wasm_file_path = "test-vectors/bn128/multiply2_bounded.wasm";
    multiply_2_bounded::<Bn254>(r1cs_file_path, wasm_file_path, 2);
}

#[test]
fn multiply2_bounded_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/multiply2_bounded.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/multiply2_bounded.wasm";
    multiply_2_bounded::<Bls12_381>(r1cs_file_path, wasm_file_path, 2);
}

#[test]
fn mimc_bn128() {
    let r1cs_file_path = "test-vectors/bn128/mimc_bn128.r1cs";
    let wasm_file_path = "test-vectors/bn128/mimc_bn128.wasm";
    mimc::<Bn254>(r1cs_file_path, wasm_file_path, 8, 8);
}

#[test]
fn mimc_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/mimc_bls12_381.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/mimc_bls12_381.wasm";
    mimc::<Bls12_381>(r1cs_file_path, wasm_file_path, 8, 8);
}

#[test]
fn mimcsponge_bn128() {
    let r1cs_file_path = "test-vectors/bn128/mimcsponge_bn128.r1cs";
    let wasm_file_path = "test-vectors/bn128/mimcsponge_bn128.wasm";
    mimcsponge::<Bn254>(r1cs_file_path, wasm_file_path, 8, 2, 3);
}

#[test]
fn mimcsponge_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/mimcsponge_bls12_381.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/mimcsponge_bls12_381.wasm";
    mimcsponge::<Bls12_381>(r1cs_file_path, wasm_file_path, 8, 2, 3);
}

// TODO: Fixme
#[ignore]
#[test]
fn poseidon_bn128() {
    let r1cs_file_path = "test-vectors/bn128/poseidon_bn128.r1cs";
    let wasm_file_path = "test-vectors/bn128/poseidon_bn128.wasm";
    poseidon::<Bn254>(r1cs_file_path, wasm_file_path, 5, 5);
}

#[test]
fn less_than_32_bits_bn128() {
    let r1cs_file_path = "test-vectors/bn128/less_than_32.r1cs";
    let wasm_file_path = "test-vectors/bn128/less_than_32.wasm";
    less_than_32_bits::<Bn254>(r1cs_file_path, wasm_file_path, 2);
    less_than_32_bits::<Bn254>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn less_than_32_bits_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/less_than_32.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/less_than_32.wasm";
    less_than_32_bits::<Bls12_381>(r1cs_file_path, wasm_file_path, 2);
    less_than_32_bits::<Bls12_381>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn all_different_10_bn128() {
    let r1cs_file_path = "test-vectors/bn128/all_different_10.r1cs";
    let wasm_file_path = "test-vectors/bn128/all_different_10.wasm";
    all_different_10::<Bn254>(r1cs_file_path, wasm_file_path, 10);
}

#[test]
fn all_different_10_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/all_different_10.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/all_different_10.wasm";
    all_different_10::<Bls12_381>(r1cs_file_path, wasm_file_path, 10);
}

#[test]
fn not_equal_public_bn128() {
    let r1cs_file_path = "test-vectors/bn128/not_equal_public.r1cs";
    let wasm_file_path = "test-vectors/bn128/not_equal_public.wasm";
    not_equal_public::<Bn254>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn not_equal_public_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/not_equal_public.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/not_equal_public.wasm";
    not_equal_public::<Bls12_381>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn less_than_public_64_bits_bn128() {
    let r1cs_file_path = "test-vectors/bn128/less_than_public_64.r1cs";
    let wasm_file_path = "test-vectors/bn128/less_than_public_64.wasm";
    less_than_public_64_bits::<Bn254>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn less_than_public_64_bits_bls12_381() {
    let r1cs_file_path = "test-vectors/bls12-381/less_than_public_64.r1cs";
    let wasm_file_path = "test-vectors/bls12-381/less_than_public_64.wasm";
    less_than_public_64_bits::<Bls12_381>(r1cs_file_path, wasm_file_path, 1);
}

#[test]
fn average_12() {
    average_n::<Bn254>(
        "test-vectors/bn128/average_12.r1cs",
        "test-vectors/bn128/average_12.wasm",
        12,
    );
    average_n::<Bls12_381>(
        "test-vectors/bls12-381/average_12.r1cs",
        "test-vectors/bls12-381/average_12.wasm",
        12,
    );
}

#[test]
fn average_24() {
    average_n::<Bn254>(
        "test-vectors/bn128/average_24.r1cs",
        "test-vectors/bn128/average_24.wasm",
        24,
    );
    average_n::<Bls12_381>(
        "test-vectors/bls12-381/average_24.r1cs",
        "test-vectors/bls12-381/average_24.wasm",
        24,
    );
}

#[test]
fn average_12_less_than_public() {
    average_n_less_than_public::<Bn254>(
        "test-vectors/bn128/average_12_less_than_public.r1cs",
        "test-vectors/bn128/average_12_less_than_public.wasm",
        12,
    );
    average_n_less_than_public::<Bls12_381>(
        "test-vectors/bls12-381/average_12_less_than_public.r1cs",
        "test-vectors/bls12-381/average_12_less_than_public.wasm",
        12,
    );
}

#[test]
fn average_24_less_than_public() {
    average_n_less_than_public::<Bn254>(
        "test-vectors/bn128/average_24_less_than_public.r1cs",
        "test-vectors/bn128/average_24_less_than_public.wasm",
        24,
    );
    average_n_less_than_public::<Bls12_381>(
        "test-vectors/bls12-381/average_24_less_than_public.r1cs",
        "test-vectors/bls12-381/average_24_less_than_public.wasm",
        24,
    );
}

#[test]
fn sum_12_less_than_public() {
    sum_n_less_than_public::<Bn254>(
        "test-vectors/bn128/sum_12_less_than_public.r1cs",
        "test-vectors/bn128/sum_12_less_than_public.wasm",
        12,
    );
    sum_n_less_than_public::<Bls12_381>(
        "test-vectors/bls12-381/sum_12_less_than_public.r1cs",
        "test-vectors/bls12-381/sum_12_less_than_public.wasm",
        12,
    );
}

#[test]
fn set_membership_5_public() {
    set_membership::<Bn254>(
        "test-vectors/bn128/set_membership_5_public.r1cs",
        "test-vectors/bn128/set_membership_5_public.wasm",
        5,
    );
    set_membership::<Bls12_381>(
        "test-vectors/bls12-381/set_membership_5_public.r1cs",
        "test-vectors/bls12-381/set_membership_5_public.wasm",
        5,
    );
}

#[test]
fn difference_of_array_sum_20_20() {
    difference_of_array_sum::<Bn254>(
        "test-vectors/bn128/difference_of_array_sum_20_20.r1cs",
        "test-vectors/bn128/difference_of_array_sum_20_20.wasm",
        20,
        20,
    );
    difference_of_array_sum::<Bls12_381>(
        "test-vectors/bls12-381/difference_of_array_sum_20_20.r1cs",
        "test-vectors/bls12-381/difference_of_array_sum_20_20.wasm",
        20,
        20,
    );
}

#[test]
fn greater_than_or_public_64() {
    greater_than_or_public::<Bn254>(
        "test-vectors/bn128/greater_than_or_public_64.r1cs",
        "test-vectors/bn128/greater_than_or_public_64.wasm",
    );
    greater_than_or_public::<Bls12_381>(
        "test-vectors/bls12-381/greater_than_or_public_64.r1cs",
        "test-vectors/bls12-381/greater_than_or_public_64.wasm",
    );
}
