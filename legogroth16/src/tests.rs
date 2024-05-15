use crate::{
    create_random_proof, create_random_proof_incl_cp_link, generate_random_parameters,
    generate_random_parameters_incl_cp_link, prepare_verifying_key, rerandomize_proof,
    rerandomize_proof_1, verify_proof, verify_proof_incl_cp_link, verify_witness_commitment,
    LinkPublicGenerators,
};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_std::{
    rand::{rngs::StdRng, RngCore, SeedableRng},
    vec::Vec,
    UniformRand,
};

use core::ops::MulAssign;

use crate::{error::Error, prover::verify_commitments};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};

/// Circuit for computation a * b
#[derive(Clone)]
struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

/// Circuit for computation a * b + c * d
#[derive(Clone)]
struct MyLessSillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
    d: Option<F>,
}

/// Circuit with 2 public inputs, 1st should be equal to a * b and 2nd to c * d
#[derive(Clone)]
struct MyLessSillyCircuit1<F: Field> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
    d: Option<F>,
}

// NOTE: It is necessary to allocate the witness variables that need to be committed before any other
// variable is allocated. This can however be a limitation when a commitment to some indirect witnesses
// (ones that are computed in the circuit) is needed.

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MyLessSillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_witness_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        let d = cs.new_witness_variable(|| self.d.ok_or(SynthesisError::AssignmentMissing))?;

        // a * b
        let e_value = if self.a.is_some() && self.b.is_some() {
            Some(self.a.unwrap().mul(self.b.unwrap()))
        } else {
            None
        };
        let e = cs.new_witness_variable(|| e_value.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + e)?;

        // c * d
        let f_value = if self.c.is_some() && self.d.is_some() {
            Some(self.c.unwrap().mul(self.d.unwrap()))
        } else {
            None
        };
        let f = cs.new_witness_variable(|| f_value.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + c, lc!() + d, lc!() + f)?;

        let y = cs.new_input_variable(|| {
            let e = e_value.ok_or(SynthesisError::AssignmentMissing)?;
            let f = f_value.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(e + f)
        })?;

        cs.enforce_constraint(lc!() + e + f, lc!() + Variable::One, lc!() + y)?;

        Ok(())
    }
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MyLessSillyCircuit1<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_witness_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        let d = cs.new_witness_variable(|| self.d.ok_or(SynthesisError::AssignmentMissing))?;

        let e = cs.new_input_variable(|| Ok(self.a.unwrap().mul(self.b.unwrap())))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + e)?;

        let f = cs.new_input_variable(|| Ok(self.c.unwrap().mul(self.d.unwrap())))?;
        cs.enforce_constraint(lc!() + c, lc!() + d, lc!() + f)?;

        Ok(())
    }
}

pub fn get_link_public_gens<R: RngCore, E: Pairing>(
    rng: &mut R,
    count: u32,
) -> LinkPublicGenerators<E> {
    let pedersen_gens = (0..count)
        .map(|_| E::G1::rand(rng).into_affine())
        .collect::<Vec<_>>();
    let g1 = E::G1::rand(rng).into_affine();
    let g2 = E::G2::rand(rng).into_affine();
    LinkPublicGenerators {
        pedersen_gens,
        g1,
        g2,
    }
}

fn test_prove_and_verify<E>(n_iters: usize)
where
    E: Pairing,
{
    fn run<E: Pairing>(n_iters: usize, commit_witness_count: u32) {
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = MySillyCircuit { a: None, b: None };

        // Generators for committing to witnesses and 1 more for randomness (`link_v` below)
        let link_gens = get_link_public_gens(&mut rng, commit_witness_count + 1);

        assert_eq!(
            generate_random_parameters_incl_cp_link::<E, _, _>(
                circuit.clone(),
                link_gens.clone(),
                3,
                &mut rng,
            )
            .unwrap_err(),
            Error::InsufficientWitnessesForCommitment(2, 3)
        );

        assert_eq!(
            generate_random_parameters::<E, _, _>(circuit.clone(), 3, &mut rng).unwrap_err(),
            Error::InsufficientWitnessesForCommitment(2, 3)
        );

        // Parameters for generating proof containing CP_link as well
        let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
            circuit.clone(),
            link_gens.clone(),
            commit_witness_count,
            &mut rng,
        )
        .unwrap();
        // Parameters for generating proof without CP_link
        let params =
            generate_random_parameters::<E, _, _>(circuit.clone(), commit_witness_count, &mut rng)
                .unwrap();

        // Verifying key for LegoGroth16 including the link public params
        let pvk_link = prepare_verifying_key::<E>(&params_link.vk.groth16_vk);
        // Verifying key for LegoGroth16
        let pvk = prepare_verifying_key::<E>(&params.vk);

        for _ in 0..n_iters {
            let a = E::ScalarField::rand(&mut rng);
            let b = E::ScalarField::rand(&mut rng);
            let mut c = a;
            c.mul_assign(&b);

            // Randomness for the committed witness in proof.d
            let v = E::ScalarField::rand(&mut rng);
            // Randomness for the committed witness in CP_link
            let link_v = E::ScalarField::rand(&mut rng);

            let circuit = MySillyCircuit {
                a: Some(a),
                b: Some(b),
            };

            // Create a LegoGro16 proof with CP_link.
            let proof_link = create_random_proof_incl_cp_link(
                circuit.clone(),
                v,
                link_v,
                &params_link,
                &mut rng,
            )
            .unwrap();
            // Create a LegoGro16 proof without CP_link.
            let proof = create_random_proof(circuit, v, &params, &mut rng).unwrap();

            // Prover verifies the openings of the commitments in both proof.d and CP_link
            if commit_witness_count == 2 {
                verify_commitments(&params_link.vk, &proof_link, 1, &[a, b], &v, &link_v).unwrap();
                assert!(
                    verify_commitments(&params_link.vk, &proof_link, 1, &[a], &v, &link_v).is_err()
                );
                assert!(
                    verify_commitments(&params_link.vk, &proof_link, 2, &[a, b], &v, &link_v)
                        .is_err()
                );
            }
            if commit_witness_count == 2 {
                verify_witness_commitment(&params.vk, &proof, 1, &[a, b], &v).unwrap();
                assert!(verify_witness_commitment(&params.vk, &proof, 1, &[b, a], &v).is_err());
                assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a], &v).is_err());
                assert!(verify_witness_commitment(&params.vk, &proof, 2, &[], &v).is_err());
            }
            if commit_witness_count == 1 {
                verify_witness_commitment(&params.vk, &proof, 1, &[a], &v).unwrap();
                assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a, b], &v).is_err());
                assert!(verify_witness_commitment(&params.vk, &proof, 2, &[a], &v).is_err());
            }
            if commit_witness_count == 0 {
                verify_witness_commitment(&params.vk, &proof, 1, &[], &v).unwrap();
                assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a, b], &v).is_err());
                assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a], &v).is_err());
                assert!(verify_witness_commitment(&params.vk, &proof, 2, &[], &v).is_err());
            }

            // Verify LegoGroth16 proof and CP_link proof
            verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[c]).unwrap();
            assert!(
                verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[]).is_err()
            );

            // Verify LegoGroth16 proof
            verify_proof(&pvk, &proof, &[c]).unwrap();
            assert!(verify_proof(&pvk, &proof, &[]).is_err());

            let re_rand_proof = rerandomize_proof(&proof, &params.vk, &mut rng);
            verify_proof(&pvk, &re_rand_proof, &[c]).unwrap();

            // rerandomize_proof does not keep D as a commitment to witnesses
            if commit_witness_count == 2 {
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof, 1, &[a, b], &v).is_err()
                );
            }
            if commit_witness_count == 1 {
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof, 1, &[a], &v).is_err()
                );
            }
            if commit_witness_count == 0 {
                assert!(verify_witness_commitment(&params.vk, &re_rand_proof, 1, &[], &v).is_err());
            }

            let new_v = E::ScalarField::rand(&mut rng);
            let re_rand_proof_1 = rerandomize_proof_1(
                &proof,
                v,
                new_v,
                &params.vk,
                &params.common.eta_delta_inv_g1,
                &mut rng,
            );
            verify_proof(&pvk, &re_rand_proof_1, &[c]).unwrap();

            // rerandomize_proof_1 does keep D as a commitment to witnesses
            if commit_witness_count == 2 {
                verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[a, b], &new_v)
                    .unwrap();
                assert!(verify_witness_commitment(
                    &params.vk,
                    &re_rand_proof_1,
                    1,
                    &[b, a],
                    &new_v
                )
                .is_err());
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[a], &new_v)
                        .is_err()
                );
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof_1, 2, &[], &new_v)
                        .is_err()
                );
            }
            if commit_witness_count == 1 {
                verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[a], &new_v).unwrap();
                assert!(verify_witness_commitment(
                    &params.vk,
                    &re_rand_proof_1,
                    1,
                    &[a, b],
                    &new_v
                )
                .is_err());
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof_1, 2, &[a], &new_v)
                        .is_err()
                );
            }
            if commit_witness_count == 0 {
                verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[], &new_v).unwrap();
                assert!(verify_witness_commitment(
                    &params.vk,
                    &re_rand_proof_1,
                    1,
                    &[a, b],
                    &new_v
                )
                .is_err());
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[a], &new_v)
                        .is_err()
                );
                assert!(
                    verify_witness_commitment(&params.vk, &re_rand_proof_1, 2, &[], &new_v)
                        .is_err()
                );
            }
        }
    }

    // Commit to both witnesses `a` and `b` in the proof
    run::<E>(n_iters, 2);
    // Commit to only 1 witness `a` in the proof
    run::<E>(n_iters, 1);
    // Don't commit to any witness in the proof
    run::<E>(n_iters, 0);
}

fn test_prove_and_verify_1<E>(n_iters: usize)
where
    E: Pairing,
{
    let mut rng = StdRng::seed_from_u64(0u64);

    // Commit to all 4 witnesses `a`, `b`, `c` and `d` in the proof
    let commit_witness_count = 4;

    // Generators for committing to witnesses and 1 more for randomness (`link_v` below)
    let link_gens = get_link_public_gens(&mut rng, commit_witness_count + 1);

    let circuit = MyLessSillyCircuit {
        a: None,
        b: None,
        c: None,
        d: None,
    };
    // Parameters for generating proof containing CP_link as well
    let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
        circuit.clone(),
        link_gens.clone(),
        commit_witness_count,
        &mut rng,
    )
    .unwrap();
    // Parameters for generating proof without CP_link
    let params =
        generate_random_parameters::<E, _, _>(circuit, commit_witness_count, &mut rng).unwrap();

    // Verifying key for LegoGroth16 including the link public params
    let pvk_link = prepare_verifying_key::<E>(&params_link.vk.groth16_vk);
    let pvk = prepare_verifying_key::<E>(&params.vk);

    for _ in 0..n_iters {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let c = E::ScalarField::rand(&mut rng);
        let d = E::ScalarField::rand(&mut rng);

        let e = a * b;

        let f = c * d;

        let y = e + f;

        // Randomness for the committed witness in proof.d
        let v = E::ScalarField::rand(&mut rng);
        // Randomness for the committed witness in CP_link
        let link_v = E::ScalarField::rand(&mut rng);

        // Create a LegoGro16 proof with our parameters.
        let circuit = MyLessSillyCircuit {
            a: Some(a),
            b: Some(b),
            c: Some(c),
            d: Some(d),
        };

        // Create a LegoGro16 proof with CP_link.
        let proof_link =
            create_random_proof_incl_cp_link(circuit.clone(), v, link_v, &params_link, &mut rng)
                .unwrap();
        // Create a LegoGro16 proof without CP_link.
        let proof = create_random_proof(circuit.clone(), v, &params, &mut rng).unwrap();

        // Prover verifies the openings of the commitments in both proof.d and CP_link
        verify_commitments(&params_link.vk, &proof_link, 1, &[a, b, c, d], &v, &link_v).unwrap();
        assert!(
            verify_commitments(&params_link.vk, &proof_link, 0, &[a, b, c, d], &v, &link_v)
                .is_err()
        );
        assert!(
            verify_commitments(&params_link.vk, &proof_link, 1, &[a, b, c], &v, &link_v).is_err()
        );

        // Prover verifies the openings of the commitments in proof.d
        verify_witness_commitment(&params.vk, &proof, 1, &[a, b, c, d], &v).unwrap();
        assert!(verify_witness_commitment(&params.vk, &proof, 0, &[a, b, c, d], &v).is_err());
        assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a, b, c], &v).is_err());

        // Verify LegoGroth16 proof and CP_link proof
        verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[y]).unwrap();
        assert!(verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[]).is_err());

        // Verify LegoGroth16 proof
        verify_proof(&pvk, &proof, &[y]).unwrap();
        assert!(verify_proof(&pvk, &proof, &[]).is_err());

        let re_rand_proof = rerandomize_proof(&proof, &params.vk, &mut rng);
        verify_proof(&pvk, &re_rand_proof, &[y]).unwrap();

        let new_v = E::ScalarField::rand(&mut rng);
        let re_rand_proof_1 = rerandomize_proof_1(
            &proof,
            v,
            new_v,
            &params.vk,
            &params.common.eta_delta_inv_g1,
            &mut rng,
        );
        verify_proof(&pvk, &re_rand_proof_1, &[y]).unwrap();
        verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[a, b, c, d], &new_v).unwrap();
    }
}

fn test_prove_and_verify_2<E>(n_iters: usize)
where
    E: Pairing,
{
    let mut rng = StdRng::seed_from_u64(0u64);

    // Commit to all 4 witnesses `a`, `b`, `c` and `d` in the proof
    let commit_witness_count = 4;

    // Generators for committing to witnesses and 1 more for randomness (`link_v` below)
    let link_gens = get_link_public_gens(&mut rng, commit_witness_count + 1);

    let circuit = MyLessSillyCircuit1 {
        a: None,
        b: None,
        c: None,
        d: None,
    };
    // Parameters for generating proof containing CP_link as well
    let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
        circuit.clone(),
        link_gens.clone(),
        4,
        &mut rng,
    )
    .unwrap();
    // Parameters for generating proof without CP_link
    let params = generate_random_parameters::<E, _, _>(circuit, 4, &mut rng).unwrap();

    // Verifying key for LegoGroth16 including the link public params
    let pvk_link = prepare_verifying_key::<E>(&params_link.vk.groth16_vk);
    // Verifying key for LegoGroth16
    let pvk = prepare_verifying_key::<E>(&params.vk);

    for _ in 0..n_iters {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let c = E::ScalarField::rand(&mut rng);
        let d = E::ScalarField::rand(&mut rng);

        let mut e = a;
        e.mul_assign(&b);

        let mut f = c;
        f.mul_assign(&d);

        // Randomness for the committed witness in proof.d
        let v = E::ScalarField::rand(&mut rng);
        // Randomness for the committed witness in CP_link
        let link_v = E::ScalarField::rand(&mut rng);

        // Create a LegoGro16 proof with our parameters.
        let circuit = MyLessSillyCircuit1 {
            a: Some(a),
            b: Some(b),
            c: Some(c),
            d: Some(d),
        };

        // Create a LegoGro16 proof with CP_link.
        let proof_link =
            create_random_proof_incl_cp_link(circuit.clone(), v, link_v, &params_link, &mut rng)
                .unwrap();
        // Create a LegoGro16 proof without CP_link.
        let proof = create_random_proof(circuit.clone(), v, &params, &mut rng).unwrap();

        // Prover verifies the openings of the commitments in both proof.d and CP_link
        verify_commitments(&params_link.vk, &proof_link, 2, &[a, b, c, d], &v, &link_v).unwrap();
        assert!(
            verify_commitments(&params_link.vk, &proof_link, 1, &[a, b, c, d], &v, &link_v)
                .is_err()
        );
        assert!(verify_commitments(&params_link.vk, &proof_link, 2, &[a, b], &v, &link_v).is_err());

        // Prover verifies the openings of the commitments in proof.d
        verify_witness_commitment(&params.vk, &proof, 2, &[a, b, c, d], &v).unwrap();
        assert!(verify_witness_commitment(&params.vk, &proof, 1, &[a, b, c, d], &v).is_err());
        assert!(verify_witness_commitment(&params.vk, &proof, 2, &[a, b], &v).is_err());

        // Verify LegoGroth16 proof and CP_link proof
        verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[e, f]).unwrap();
        assert!(verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[e]).is_err());
        assert!(verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[]).is_err());

        // Verify LegoGroth16 proof
        verify_proof(&pvk, &proof, &[e, f]).unwrap();
        assert!(verify_proof(&pvk, &proof, &[e]).is_err());
        assert!(verify_proof(&pvk, &proof, &[]).is_err());

        let re_rand_proof = rerandomize_proof(&proof, &params.vk, &mut rng);
        verify_proof(&pvk, &re_rand_proof, &[e, f]).unwrap();

        let new_v = E::ScalarField::rand(&mut rng);
        let re_rand_proof_1 = rerandomize_proof_1(
            &proof,
            v,
            new_v,
            &params.vk,
            &params.common.eta_delta_inv_g1,
            &mut rng,
        );
        verify_proof(&pvk, &re_rand_proof_1, &[e, f]).unwrap();
        verify_witness_commitment(&params.vk, &re_rand_proof_1, 2, &[a, b, c, d], &new_v).unwrap();
    }
}

mod bls12_377 {
    use super::*;
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(10);
    }

    #[test]
    fn prove_and_verify_1() {
        test_prove_and_verify_1::<Bls12_377>(10);
    }

    #[test]
    fn prove_and_verify_2() {
        test_prove_and_verify_2::<Bls12_377>(10);
    }
}

mod cp6_782 {
    use super::*;

    use ark_cp6_782::CP6_782;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<CP6_782>(1);
    }

    #[test]
    fn prove_and_verify_1() {
        test_prove_and_verify_1::<CP6_782>(1);
    }

    #[test]
    fn prove_and_verify_2() {
        test_prove_and_verify_2::<CP6_782>(1);
    }
}

mod bls12_381 {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_381>(10);
    }

    #[test]
    fn prove_and_verify_1() {
        test_prove_and_verify_1::<Bls12_381>(10);
    }

    #[test]
    fn prove_and_verify_2() {
        test_prove_and_verify_2::<Bls12_381>(10);
    }
}

mod bn254 {
    use super::*;
    use ark_bn254::Bn254;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bn254>(10);
    }

    #[test]
    fn prove_and_verify_1() {
        test_prove_and_verify_1::<Bn254>(10);
    }

    #[test]
    fn prove_and_verify_2() {
        test_prove_and_verify_2::<Bn254>(10);
    }
}
