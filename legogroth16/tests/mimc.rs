#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    unsafe_code
)]

// For randomness (during paramgen and proof generation)
use ark_std::UniformRand;

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;

// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};

use ark_std::rand::{rngs::StdRng, SeedableRng};
use legogroth16::{
    create_random_proof, generate_random_parameters, prover::verify_commitments, rerandomize_proof,
    rerandomize_proof_1, verify_proof, verify_witness_commitment,
};

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-377.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
#[derive(Clone)]
struct MiMCDemo<'a, F: Field> {
    xl: Option<F>,
    xr: Option<F>,
    constants: &'a [F],
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, F: Field> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl =
            cs.new_witness_variable(|| xl_value.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr =
            cs.new_witness_variable(|| xr_value.ok_or(SynthesisError::AssignmentMissing))?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let ns = ns!(cs, "round");
            let cs = ns.cs();

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square_in_place();
                e
            });
            let tmp =
                cs.new_witness_variable(|| tmp_value.ok_or(SynthesisError::AssignmentMissing))?;

            cs.enforce_constraint(
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + tmp,
            )?;

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.new_input_variable(|| new_xl_value.ok_or(SynthesisError::AssignmentMissing))?
            } else {
                cs.new_witness_variable(|| new_xl_value.ok_or(SynthesisError::AssignmentMissing))?
            };

            cs.enforce_constraint(
                lc!() + tmp,
                lc!() + xl + (self.constants[i], Variable::One),
                lc!() + new_xl - xr,
            )?;

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

fn mimc_legogroth16<E: Pairing>() {
    // We're going to use the LegoGroth16 proving system.
    // This proof has a commitment to both left and right inputs

    use legogroth16::{
        create_random_proof_incl_cp_link, data_structures::LinkPublicGenerators,
        generate_random_parameters_incl_cp_link, prepare_verifying_key, verify_proof_incl_cp_link,
    };

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = StdRng::seed_from_u64(0u64);

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();

    println!("Creating parameters...");

    // Need 3 bases, 2 for witnesses xl and xr and 1 for randomness (link_v)
    let pedersen_gens = (0..3)
        .map(|_| E::G1::rand(&mut rng).into_affine())
        .collect::<Vec<_>>();
    let g1 = E::G1::rand(&mut rng).into_affine();
    let g2 = E::G2::rand(&mut rng).into_affine();
    let link_gens = LinkPublicGenerators {
        pedersen_gens,
        g1,
        g2,
    };

    let c = MiMCDemo::<E::ScalarField> {
        xl: None,
        xr: None,
        constants: &constants,
    };

    // Parameters for generating proof containing CP_link as well
    let params_link =
        generate_random_parameters_incl_cp_link::<E, _, _>(c.clone(), link_gens, 2, &mut rng)
            .unwrap();
    // Parameters for generating proof without CP_link
    let params = generate_random_parameters::<E, _, _>(c, 2, &mut rng).unwrap();

    // Verifying key for LegoGroth16 including the link public params
    let pvk_link = prepare_verifying_key(&params_link.vk.groth16_vk);
    // Verifying key for LegoGroth16
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 50;
    let mut total_proving_inc_link = Duration::new(0, 0);
    let mut total_verifying_inc_link = Duration::new(0, 0);
    let mut total_proving = Duration::new(0, 0);
    let mut total_rerandomizing = Duration::new(0, 0);
    let mut total_rerandomizing_1 = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = E::ScalarField::rand(&mut rng);
        let xr = E::ScalarField::rand(&mut rng);
        let image = mimc(xl, xr, &constants);

        {
            // Create an instance of our circuit (with the
            // witness)
            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants,
            };

            // Randomness for the committed witness in proof.d
            let v = E::ScalarField::rand(&mut rng);
            // Randomness for the committed witness in CP_link
            let link_v = E::ScalarField::rand(&mut rng);

            let start = Instant::now();
            // Create a LegoGro16 proof with CP_link.
            let proof_link =
                create_random_proof_incl_cp_link(c.clone(), v, link_v, &params_link, &mut rng)
                    .unwrap();
            total_proving_inc_link += start.elapsed();

            let start = Instant::now();
            // Create a LegoGro16 proof without CP_link.
            let proof = create_random_proof(c, v, &params, &mut rng).unwrap();
            total_proving += start.elapsed();

            // Prover verifies the openings of the commitments in both proof.d and CP_link
            verify_commitments(&params_link.vk, &proof_link, 1, &[xl, xr], &v, &link_v).unwrap();
            // Prover verifies the openings of the commitments in proof.d
            verify_witness_commitment(&params.vk, &proof, 1, &[xl, xr], &v).unwrap();

            let start = Instant::now();
            // Verify LegoGroth16 proof and CP_link proof
            verify_proof_incl_cp_link(&pvk_link, &params_link.vk, &proof_link, &[image]).unwrap();
            total_verifying_inc_link += start.elapsed();

            let start = Instant::now();
            // Verify LegoGroth16 proof
            verify_proof(&pvk, &proof, &[image]).unwrap();
            total_verifying += start.elapsed();

            let start = Instant::now();
            let re_rand_proof = rerandomize_proof(&proof, &params.vk, &mut rng);
            total_rerandomizing += start.elapsed();

            verify_proof(&pvk, &re_rand_proof, &[image]).unwrap();

            let start = Instant::now();
            let new_v = E::ScalarField::rand(&mut rng);
            let re_rand_proof_1 = rerandomize_proof_1(
                &proof,
                v,
                new_v,
                &params.vk,
                &params.common.eta_delta_inv_g1,
                &mut rng,
            );
            total_rerandomizing_1 += start.elapsed();

            verify_proof(&pvk, &re_rand_proof_1, &[image]).unwrap();
            // Prover verifies the openings of the commitments in new proof.d
            verify_witness_commitment(&params.vk, &re_rand_proof_1, 1, &[xl, xr], &new_v).unwrap();
        }
    }

    fn avg(total: Duration) -> f64 {
        let avg = total / SAMPLES;
        avg.subsec_nanos() as f64 / 1_000_000_000f64 + (avg.as_secs() as f64)
    }

    println!(
        "Average proving time including link proof: {:?} seconds",
        avg(total_proving_inc_link)
    );
    println!(
        "Average verifying time including link proof: {:?} seconds",
        avg(total_verifying_inc_link)
    );
    println!("Average proving time: {:?} seconds", avg(total_proving));
    println!("Average verifying time: {:?} seconds", avg(total_verifying));
    println!(
        "Average re-randomizing proof time: {:?} seconds",
        avg(total_rerandomizing)
    );
    println!(
        "Average re-randomizing_1 proof time: {:?} seconds",
        avg(total_rerandomizing_1)
    );
}

mod bls12_377 {
    use super::*;
    use ark_bls12_377::Bls12_377;

    #[test]
    fn test_mimc_legogroth16() {
        mimc_legogroth16::<Bls12_377>();
    }
}

mod bls12_381 {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn test_mimc_legogroth16() {
        mimc_legogroth16::<Bls12_381>();
    }
}

mod bn254 {
    use super::*;
    use ark_bn254::Bn254;

    #[test]
    fn test_mimc_legogroth16() {
        mimc_legogroth16::<Bn254>();
    }
}
