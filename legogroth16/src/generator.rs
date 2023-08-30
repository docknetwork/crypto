use crate::{
    link::{PESubspaceSnark, SparseMatrix, SubspaceSnark, PP},
    r1cs_to_qap::LibsnarkReduction,
    LinkPublicGenerators, ProvingKey, ProvingKeyCommon, ProvingKeyWithLink, Vec, VerifyingKey,
    VerifyingKeyWithLink,
};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::{cfg_into_iter, cfg_iter, end_timer, rand::Rng, start_timer, vec};

use crate::r1cs_to_qap::R1CStoQAP;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// QUESTION: Does making link (link keys, link proof, etc) optional reduce the security? We don't need the
// link as of now, only the commitment to the witness is needed in the proof.

#[inline]
/// Generates a random common reference string for a circuit including CP_link evaluation and verification key.
/// `commit_witness_count` is the number of witnesses committed in proof as well as in CP_link
pub fn generate_random_parameters_incl_cp_link<E, C, R>(
    circuit: C,
    link_gens: LinkPublicGenerators<E>,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKeyWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
{
    generate_random_parameters_incl_cp_link_with_reduction::<E, C, R, LibsnarkReduction>(
        circuit,
        link_gens,
        commit_witness_count,
        rng,
    )
}

#[inline]
/// Generates a random common reference string for a circuit.
/// `commit_witness_count` is the number of witnesses committed in proof
pub fn generate_random_parameters<E, C, R>(
    circuit: C,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKey<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
{
    generate_random_parameters_with_reduction::<E, C, R, LibsnarkReduction>(
        circuit,
        commit_witness_count,
        rng,
    )
}

/// Generates a random common reference string for
/// a circuit.
/// `commit_witness_count` is the number of witnesses committed in proof
#[inline]
pub fn generate_random_parameters_with_reduction<E, C, R, QAP>(
    circuit: C,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKey<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
    QAP: R1CStoQAP,
{
    let (alpha, beta, gamma, delta, eta, g1_generator, g2_generator) =
        generate_randomness::<E, R>(rng);

    generate_parameters_with_qap::<E, C, R, QAP>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        eta,
        g1_generator,
        g2_generator,
        commit_witness_count,
        rng,
    )
}

/// Generates a random common reference string for a circuit.
/// `link_gens` are the bases (commitment key) for link (Pedersen) commitment to the first
/// `commit_witness_count` witnesses committed in CP_link as well as in proof
#[inline]
pub fn generate_random_parameters_incl_cp_link_with_reduction<E, C, R, QAP>(
    circuit: C,
    link_gens: LinkPublicGenerators<E>,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKeyWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
    QAP: R1CStoQAP,
{
    let (alpha, beta, gamma, delta, eta, g1_generator, g2_generator) =
        generate_randomness::<E, R>(rng);

    generate_parameters_incl_cp_link_with_qap::<E, C, R, QAP>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        eta,
        g1_generator,
        g2_generator,
        link_gens,
        commit_witness_count,
        rng,
    )
}

/// Create parameters for a circuit, given some toxic waste, R1CS to QAP calculator and group generators
#[inline]
pub fn generate_parameters_incl_cp_link_with_qap<E, C, R, QAP>(
    circuit: C,
    alpha: E::ScalarField,
    beta: E::ScalarField,
    gamma: E::ScalarField,
    delta: E::ScalarField,
    eta: E::ScalarField,
    g1_generator: E::G1,
    g2_generator: E::G2,
    link_gens: LinkPublicGenerators<E>,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKeyWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
    QAP: R1CStoQAP,
{
    let (groth16_pk, num_instance_variables) =
        generate_parameters_and_extra_info_with_qap::<E, C, R, QAP>(
            circuit,
            alpha,
            beta,
            gamma,
            delta,
            eta,
            g1_generator,
            g2_generator,
            commit_witness_count,
            rng,
        )?;

    // Setup public params for the Subspace Snark
    let link_rows = 2; // we're comparing two commitments, proof.d and proof.link_d
    let link_cols = commit_witness_count as u32 + 2; // we have `commit_witness_count` witnesses and 1 hiding factor per row
    let link_pp = PP::<E::G1Affine, E::G2Affine> {
        l: link_rows,
        t: link_cols,
        g1: link_gens.g1,
        g2: link_gens.g2,
    };

    let mut link_m = SparseMatrix::<E::G1Affine>::new(link_rows as usize, link_cols as usize);
    link_m.insert_row_slice(0, 0, link_gens.pedersen_gens.clone())?;
    link_m.insert_row_slice(
        1,
        0,
        groth16_pk.vk.gamma_abc_g1
            [num_instance_variables..num_instance_variables + commit_witness_count as usize]
            .to_vec(),
    )?;
    link_m.insert_row_slice(
        1,
        commit_witness_count as usize + 1,
        vec![groth16_pk.vk.eta_gamma_inv_g1],
    )?;

    let (link_ek, link_vk) = PESubspaceSnark::<E>::keygen(rng, &link_pp, &link_m)?;

    let vk = VerifyingKeyWithLink::<E> {
        groth16_vk: groth16_pk.vk,
        link_pp,
        link_bases: link_gens.pedersen_gens,
        link_vk,
    };

    Ok(ProvingKeyWithLink {
        vk,
        common: groth16_pk.common,
        link_ek,
    })
}

/// Create parameters for a circuit, given some toxic waste, R1CS to QAP calculator and group generators
#[inline]
pub fn generate_parameters_with_qap<E, C, R, QAP>(
    circuit: C,
    alpha: E::ScalarField,
    beta: E::ScalarField,
    gamma: E::ScalarField,
    delta: E::ScalarField,
    eta: E::ScalarField,
    g1_generator: E::G1,
    g2_generator: E::G2,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<ProvingKey<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
    QAP: R1CStoQAP,
{
    let (pk, _) = generate_parameters_and_extra_info_with_qap::<E, C, R, QAP>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        eta,
        g1_generator,
        g2_generator,
        commit_witness_count,
        rng,
    )?;
    Ok(pk)
}

/// Create parameters for a circuit, given some toxic waste, R1CS to QAP calculator and group generators.
/// Returns the proving key and the number of public inputs.
#[inline]
fn generate_parameters_and_extra_info_with_qap<E, C, R, QAP>(
    circuit: C,
    alpha: E::ScalarField,
    beta: E::ScalarField,
    gamma: E::ScalarField,
    delta: E::ScalarField,
    eta: E::ScalarField,
    g1_generator: E::G1,
    g2_generator: E::G2,
    commit_witness_count: u32,
    rng: &mut R,
) -> crate::Result<(ProvingKey<E>, usize)>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
    QAP: R1CStoQAP,
{
    type D<F> = GeneralEvaluationDomain<F>;

    let setup_time = start_timer!(|| "Groth16::Generator");
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(cs.clone())?;
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    cs.finalize();
    end_timer!(lc_time);

    ///////////////////////////////////////////////////////////////////////////
    let domain_time = start_timer!(|| "Constructing evaluation domain");

    let domain_size = cs.num_constraints() + cs.num_instance_variables();
    let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let t = domain.sample_element_outside_domain(rng);

    end_timer!(domain_time);
    ///////////////////////////////////////////////////////////////////////////

    let num_instance_variables = cs.num_instance_variables();
    if cs.num_witness_variables() < commit_witness_count as usize {
        return Err(crate::error::Error::InsufficientWitnessesForCommitment(
            cs.num_witness_variables(),
            commit_witness_count as usize,
        ));
    }

    let n = num_instance_variables + commit_witness_count as usize;

    let reduction_time = start_timer!(|| "R1CS to QAP Instance Map with Evaluation");
    let (a, b, c, zt, qap_num_variables, m_raw) = LibsnarkReduction::instance_map_with_evaluation::<
        E::ScalarField,
        D<E::ScalarField>,
    >(cs, &t)?;
    end_timer!(reduction_time);

    // Compute query densities
    let non_zero_a: usize = cfg_into_iter!(0..qap_num_variables)
        .map(|i| usize::from(!a[i].is_zero()))
        .sum();

    let non_zero_b: usize = cfg_into_iter!(0..qap_num_variables)
        .map(|i| usize::from(!b[i].is_zero()))
        .sum();

    let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

    let gamma_inverse = gamma.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
    let delta_inverse = delta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;

    let gamma_abc = cfg_iter!(a[..n])
        .zip(&b[..n])
        .zip(&c[..n])
        .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &gamma_inverse)
        .collect::<Vec<_>>();

    let l = cfg_iter!(a)
        .zip(&b)
        .zip(&c)
        .map(|((a, b), c)| (beta * a + &(alpha * b) + c) * &delta_inverse)
        .collect::<Vec<_>>();

    drop(c);

    // Compute B window table
    let g2_time = start_timer!(|| "Compute G2 table");
    let g2_window = FixedBase::get_mul_window_size(non_zero_b);
    let g2_table = FixedBase::get_window_table::<E::G2>(scalar_bits, g2_window, g2_generator);
    end_timer!(g2_time);

    // Compute the B-query in G2
    let b_g2_time = start_timer!(|| "Calculate B G2");
    let b_g2_query = FixedBase::msm::<E::G2>(scalar_bits, g2_window, &g2_table, &b);
    drop(g2_table);
    end_timer!(b_g2_time);

    // Compute G window table
    let g1_window_time = start_timer!(|| "Compute G1 window table");
    let g1_window =
        FixedBase::get_mul_window_size(non_zero_a + non_zero_b + qap_num_variables + m_raw + 1);
    let g1_table = FixedBase::get_window_table::<E::G1>(scalar_bits, g1_window, g1_generator);
    end_timer!(g1_window_time);

    // Generate the R1CS proving key
    let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

    let beta_repr = beta.into_bigint();
    let delta_repr = delta.into_bigint();

    let alpha_g1 = g1_generator.mul_bigint(alpha.into_bigint());
    let beta_g1 = g1_generator.mul_bigint(beta_repr);
    let beta_g2 = g2_generator.mul_bigint(beta_repr);
    let delta_g1 = g1_generator.mul_bigint(delta_repr);
    let delta_g2 = g2_generator.mul_bigint(delta_repr);

    // Compute the A-query
    let a_time = start_timer!(|| "Calculate A");
    let a_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &a);
    drop(a);
    end_timer!(a_time);

    // Compute the B-query in G1
    let b_g1_time = start_timer!(|| "Calculate B G1");
    let b_g1_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &b);
    drop(b);
    end_timer!(b_g1_time);

    // Compute the H-query
    let h_time = start_timer!(|| "Calculate H");
    let h_query = FixedBase::msm::<E::G1>(
        scalar_bits,
        g1_window,
        &g1_table,
        &QAP::h_query_scalars::<_, D<E::ScalarField>>(m_raw - 1, t, zt, delta_inverse)?,
    );

    end_timer!(h_time);

    // Compute the L-query
    let l_time = start_timer!(|| "Calculate L");
    let l_query = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &l[n..]);
    drop(l);
    end_timer!(l_time);

    end_timer!(proving_key_time);

    // Generate R1CS verification key
    let verifying_key_time = start_timer!(|| "Generate the R1CS verification key");
    let gamma_g2 = g2_generator.mul_bigint(gamma.into_bigint());
    let gamma_abc_g1 = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &gamma_abc);

    drop(g1_table);

    end_timer!(verifying_key_time);

    let eta_gamma_inv_g1 = g1_generator.mul_bigint((eta * &gamma_inverse).into_bigint());

    let gamma_abc_g1_affine = E::G1::normalize_batch(&gamma_abc_g1);
    let eta_gamma_inv_g1_affine = eta_gamma_inv_g1.into_affine();

    let vk = VerifyingKey::<E> {
        alpha_g1: alpha_g1.into_affine(),
        beta_g2: beta_g2.into_affine(),
        gamma_g2: gamma_g2.into_affine(),
        delta_g2: delta_g2.into_affine(),
        gamma_abc_g1: gamma_abc_g1_affine,
        eta_gamma_inv_g1: eta_gamma_inv_g1_affine,
        commit_witness_count,
    };

    let batch_normalization_time = start_timer!(|| "Convert proving key elements to affine");
    let a_query = E::G1::normalize_batch(&a_query);
    let b_g1_query = E::G1::normalize_batch(&b_g1_query);
    let b_g2_query = E::G2::normalize_batch(&b_g2_query);
    let h_query = E::G1::normalize_batch(&h_query);
    let l_query = E::G1::normalize_batch(&l_query);
    end_timer!(batch_normalization_time);
    end_timer!(setup_time);

    let eta_delta_inv_g1 = g1_generator.mul_bigint((eta * &delta_inverse).into_bigint());

    let common = ProvingKeyCommon {
        beta_g1: beta_g1.into_affine(),
        delta_g1: delta_g1.into_affine(),
        eta_delta_inv_g1: eta_delta_inv_g1.into_affine(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    };
    Ok((ProvingKey { vk, common }, num_instance_variables))
}

#[inline]
fn generate_randomness<E, R>(
    rng: &mut R,
) -> (
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::G1,
    E::G2,
)
where
    E: Pairing,
    R: Rng,
{
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let delta = E::ScalarField::rand(rng);
    let eta = E::ScalarField::rand(rng);

    let g1_generator = E::G1::rand(rng);
    let g2_generator = E::G2::rand(rng);
    (alpha, beta, gamma, delta, eta, g1_generator, g2_generator)
}
