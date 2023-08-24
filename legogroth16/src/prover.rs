use crate::{
    link::{PESubspaceSnark, SubspaceSnark},
    r1cs_to_qap::LibsnarkReduction,
    Proof, ProofWithLink, ProvingKey, ProvingKeyCommon, ProvingKeyWithLink, VerifyingKey,
    VerifyingKeyWithLink,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup, Group,
    VariableBaseMSM,
};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use ark_std::{
    cfg_into_iter, cfg_iter, end_timer,
    ops::{AddAssign, Mul},
    rand::Rng,
    start_timer, vec,
    vec::Vec,
};

use crate::{error::Error, r1cs_to_qap::R1CStoQAP};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Same as `create_random_proof` but returns the CP_link and its corresponding proof as well. `link_v`
/// is the blinding in CP_link
#[inline]
pub fn create_random_proof_incl_cp_link<E, C, R>(
    circuit: C,
    v: E::ScalarField,
    link_v: E::ScalarField,
    pk: &ProvingKeyWithLink<E>,
    rng: &mut R,
) -> crate::Result<ProofWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    create_proof_incl_cp_link::<E, C>(circuit, pk, r, s, v, link_v)
}

/// Create a LegoGroth16 proof that is zero-knowledge. `v` is the blinding used in the commitment to the witness.
/// This method samples randomness for zero knowledge via `rng`.
#[inline]
pub fn create_random_proof<E, C, R>(
    circuit: C,
    v: E::ScalarField,
    pk: &ProvingKey<E>,
    rng: &mut R,
) -> crate::Result<Proof<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    create_proof::<E, C>(circuit, pk, r, s, v)
}

#[inline]
/// Create a LegoGroth16 proof using randomness `r`, `s`, `v` and `link_v` where `v` is the blinding in
/// the witness commitment in proof and `link_v` is the blinding in the witness commitment in CP_link
pub fn create_proof_incl_cp_link<E, C>(
    circuit: C,
    pk: &ProvingKeyWithLink<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
    link_v: E::ScalarField,
) -> crate::Result<ProofWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    create_proof_incl_cp_link_with_reduction::<E, C, LibsnarkReduction>(
        circuit, pk, r, s, v, link_v,
    )
}

#[inline]
/// Create a LegoGroth16 proof using randomness `r`, `s` and `v` where `v` is the blinding in the witness
/// commitment in proof.
pub fn create_proof<E, C>(
    circuit: C,
    pk: &ProvingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
) -> crate::Result<Proof<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    create_proof_with_reduction::<E, C, LibsnarkReduction>(circuit, pk, r, s, v)
}

/// Create a LegoGroth16 proof using randomness `r` and `s`.
/// `v` is the randomness of the commitment `proof.d` and `link_v` is the randomness to CP_link commitment
#[inline]
pub fn create_proof_incl_cp_link_with_reduction<E, C, QAP>(
    circuit: C,
    pk: &ProvingKeyWithLink<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
    link_v: E::ScalarField,
) -> crate::Result<ProofWithLink<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    QAP: R1CStoQAP,
{
    let prover_time = start_timer!(|| "Groth16::Prover");
    let (cs, h) = synthesize_circuit::<E, C, QAP>(circuit)?;

    let prover = cs.borrow().unwrap();
    let proof = create_proof_incl_cp_link_with_assignment::<E, QAP>(
        pk,
        r,
        s,
        v,
        link_v,
        &h,
        &prover.instance_assignment,
        &prover.witness_assignment,
    )?;

    drop(prover);
    drop(cs);

    end_timer!(prover_time);

    Ok(proof)
}

/// Create a LegoGroth16 proof using randomness `r` and `s`.
/// `v` is the randomness of the commitment `proof.d`.
#[inline]
pub fn create_proof_with_reduction<E, C, QAP>(
    circuit: C,
    pk: &ProvingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
) -> crate::Result<Proof<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    QAP: R1CStoQAP,
{
    let prover_time = start_timer!(|| "Groth16::Prover");
    let (cs, h) = synthesize_circuit::<E, C, QAP>(circuit)?;

    let prover = cs.borrow().unwrap();
    let proof = create_proof_with_assignment::<E, QAP>(
        pk,
        r,
        s,
        v,
        &h,
        &prover.instance_assignment,
        &prover.witness_assignment,
    )?;

    drop(prover);
    drop(cs);

    end_timer!(prover_time);

    Ok(proof)
}

/// Create the proof including CP_link and its corresponding proof given the public and private input assignments
#[inline]
fn create_proof_incl_cp_link_with_assignment<E, QAP>(
    pk: &ProvingKeyWithLink<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
    link_v: E::ScalarField,
    h: &[E::ScalarField],
    input_assignment: &[E::ScalarField],
    witness_assignment: &[E::ScalarField],
) -> crate::Result<ProofWithLink<E>>
where
    E: Pairing,
    QAP: R1CStoQAP,
{
    let (proof, comm_wits) = create_proof_and_committed_witnesses_with_assignment::<E, QAP>(
        &pk.common,
        &pk.vk.groth16_vk,
        r,
        s,
        v,
        &h,
        input_assignment,
        witness_assignment,
    )?;

    let mut comm_wits_with_link_hider = cfg_iter!(comm_wits)
        .map(|w| w.into_bigint())
        .collect::<Vec<_>>();
    comm_wits_with_link_hider.push(link_v.into_bigint());

    let g_d_link = E::G1::msm_bigint(&pk.vk.link_bases, &comm_wits_with_link_hider);

    let mut ss_snark_witness = comm_wits;
    ss_snark_witness.push(link_v);
    ss_snark_witness.push(v);

    let link_time = start_timer!(|| "Compute CP_{link}");
    let link_pi = PESubspaceSnark::<E>::prove(&pk.vk.link_pp, &pk.link_ek, &ss_snark_witness)?;

    end_timer!(link_time);

    drop(comm_wits_with_link_hider);
    drop(ss_snark_witness);

    Ok(ProofWithLink {
        groth16_proof: proof,
        link_d: g_d_link.into_affine(),
        link_pi,
    })
}

/// Create the proof given the public and private input assignments
#[inline]
fn create_proof_with_assignment<E, QAP>(
    pk: &ProvingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
    h: &[E::ScalarField],
    input_assignment: &[E::ScalarField],
    witness_assignment: &[E::ScalarField],
) -> crate::Result<Proof<E>>
where
    E: Pairing,
    QAP: R1CStoQAP,
{
    let (proof, _comm_wits) = create_proof_and_committed_witnesses_with_assignment::<E, QAP>(
        &pk.common,
        &pk.vk,
        r,
        s,
        v,
        &h,
        input_assignment,
        witness_assignment,
    )?;
    drop(_comm_wits);
    Ok(proof)
}

/// Returns the proof and the committed witnesses.
#[inline]
fn create_proof_and_committed_witnesses_with_assignment<E, QAP>(
    pk_common: &ProvingKeyCommon<E>,
    vk: &VerifyingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    v: E::ScalarField,
    h: &[E::ScalarField],
    input_assignment: &[E::ScalarField],
    witness_assignment: &[E::ScalarField],
) -> crate::Result<(Proof<E>, Vec<E::ScalarField>)>
where
    E: Pairing,
    QAP: R1CStoQAP,
{
    let h_assignment = cfg_into_iter!(h)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    let c_acc_time = start_timer!(|| "Compute C");

    let h_acc = E::G1::msm_bigint(&pk_common.h_query, &h_assignment);
    drop(h_assignment);

    let v_repr = v.into_bigint();

    // Compute C
    let aux_assignment = cfg_iter!(witness_assignment)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();

    let committed_witnesses = &aux_assignment[..vk.commit_witness_count as usize];
    let uncommitted_witnesses = &aux_assignment[vk.commit_witness_count as usize..];

    let l_aux_acc = E::G1::msm_bigint(&pk_common.l_query, uncommitted_witnesses);

    let v_eta_delta_inv = pk_common.eta_delta_inv_g1.mul_bigint(v_repr);

    end_timer!(c_acc_time);

    let s_repr = s.into_bigint();
    let delta_g1_proj = pk_common.delta_g1.into_group();

    // There will be multiple multiplications with delta_g1_proj so creating a table
    let window_size = 3; // 3 because number of multiplications is < 32, see `FixedBase::get_mul_window_size`
    let scalar_size =
        <<E as Pairing>::G1Affine as AffineRepr>::ScalarField::MODULUS_BIT_SIZE as usize;
    let outerc = (scalar_size + window_size - 1) / window_size;
    let delta_g1_table = FixedBase::get_window_table(scalar_size, window_size, delta_g1_proj);

    let input_assignment_wth_one = cfg_iter!(input_assignment)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();

    let mut assignment = vec![];
    assignment.extend_from_slice(&input_assignment_wth_one[1..]);
    assignment.extend_from_slice(&aux_assignment);

    // Compute A
    let a_acc_time = start_timer!(|| "Compute A");
    let r_g1 = FixedBase::windowed_mul(outerc, window_size, &delta_g1_table, &r);
    let g_a = calculate_coeff(r_g1, &pk_common.a_query, vk.alpha_g1, &assignment);
    end_timer!(a_acc_time);

    // Compute B in G1 if needed
    let g1_b = if !r.is_zero() {
        let b_g1_acc_time = start_timer!(|| "Compute B in G1");
        let s_g1 = FixedBase::windowed_mul(outerc, window_size, &delta_g1_table, &s);
        let g1_b = calculate_coeff(s_g1, &pk_common.b_g1_query, pk_common.beta_g1, &assignment);
        end_timer!(b_g1_acc_time);

        g1_b
    } else {
        E::G1::zero()
    };

    // Compute B in G2
    let b_g2_acc_time = start_timer!(|| "Compute B in G2");
    let s_g2 = vk.delta_g2.into_group().mul_bigint(s_repr);
    let g2_b = calculate_coeff(s_g2, &pk_common.b_g2_query, vk.beta_g2, &assignment);
    drop(assignment);

    end_timer!(b_g2_acc_time);

    let c_time = start_timer!(|| "Finish C");
    let mut g_c = g_a.mul_bigint(s_repr);
    g_c += &g1_b.mul_bigint(r.into_bigint());
    g_c -= &FixedBase::windowed_mul::<E::G1>(outerc, window_size, &delta_g1_table, &(r * s));
    g_c += &l_aux_acc;
    g_c += &h_acc;
    g_c -= &v_eta_delta_inv;
    end_timer!(c_time);

    // Compute D
    let d_acc_time = start_timer!(|| "Compute D");

    let gamma_abc_inputs_source = &vk.gamma_abc_g1[input_assignment_wth_one.len()
        ..input_assignment_wth_one.len() + committed_witnesses.len()];
    let gamma_abc_inputs_acc = E::G1::msm_bigint(gamma_abc_inputs_source, &committed_witnesses);

    let v_eta_gamma_inv = vk.eta_gamma_inv_g1.into_group().mul_bigint(v_repr);

    let mut g_d = gamma_abc_inputs_acc;
    g_d += &v_eta_gamma_inv;
    end_timer!(d_acc_time);

    let committed_witnesses = witness_assignment[..vk.commit_witness_count as usize].to_vec();
    drop(aux_assignment);

    Ok((
        Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
            d: g_d.into_affine(),
        },
        committed_witnesses,
    ))
}

/// Check the opening of cp_link.
pub fn verify_link_commitment<E: Pairing>(
    cp_link_bases: &[E::G1Affine],
    link_d: &E::G1Affine,
    witnesses_expected_in_commitment: &[E::ScalarField],
    link_v: &E::ScalarField,
) -> crate::Result<()> {
    // Some witnesses are committed in `link_d` with randomness `link_v`
    if (witnesses_expected_in_commitment.len() + 1) > cp_link_bases.len() {
        return Err(Error::VectorLongerThanExpected(
            witnesses_expected_in_commitment.len() + 1,
            cp_link_bases.len(),
        ));
    }
    let mut committed = cfg_iter!(witnesses_expected_in_commitment)
        .map(|p| p.into_bigint())
        .collect::<Vec<_>>();
    committed.push(link_v.into_bigint());

    if *link_d != E::G1::msm_bigint(cp_link_bases, &committed).into_affine() {
        return Err(Error::InvalidLinkCommitment);
    }
    Ok(())
}

/// Check that the commitments in the proof open to the public inputs and the witnesses but with different
/// bases and randomness. This function is only called by the prover, the verifier does not
/// know `witnesses_expected_in_commitment` or `link_v`.
pub fn verify_commitments<E: Pairing>(
    vk: &VerifyingKeyWithLink<E>,
    proof: &ProofWithLink<E>,
    public_inputs_count: usize,
    witnesses_expected_in_commitment: &[E::ScalarField],
    v: &E::ScalarField,
    link_v: &E::ScalarField,
) -> crate::Result<()> {
    verify_link_commitment::<E>(
        &vk.link_bases,
        &proof.link_d,
        witnesses_expected_in_commitment,
        link_v,
    )?;
    verify_witness_commitment::<E>(
        &vk.groth16_vk,
        &proof.groth16_proof,
        public_inputs_count,
        witnesses_expected_in_commitment,
        v,
    )
}

/// Given the proof, verify that the commitment in it (`proof.d`) commits to the witness.
pub fn verify_witness_commitment<E: Pairing>(
    vk: &VerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs_count: usize,
    witnesses_expected_in_commitment: &[E::ScalarField],
    v: &E::ScalarField,
) -> crate::Result<()> {
    // Some witnesses are also committed in `proof.d` with randomness `v`
    if (public_inputs_count + witnesses_expected_in_commitment.len() + 1) > vk.gamma_abc_g1.len() {
        return Err(Error::VectorLongerThanExpected(
            public_inputs_count + witnesses_expected_in_commitment.len() + 1,
            vk.gamma_abc_g1.len(),
        ));
    }
    let committed = cfg_iter!(witnesses_expected_in_commitment)
        .map(|p| p.into_bigint())
        .collect::<Vec<_>>();

    // Check that proof.d is correctly constructed.
    let mut d = E::G1::msm_bigint(
        &vk.gamma_abc_g1[1 + public_inputs_count..1 + public_inputs_count + committed.len()],
        &committed,
    );
    d.add_assign(&vk.eta_gamma_inv_g1.mul_bigint(v.into_bigint()));

    if proof.d != d.into_affine() {
        return Err(Error::InvalidWitnessCommitment);
    }

    Ok(())
}

/// Given a LegoGroth16 proof, returns a fresh proof of the same statement. This is not described in the
/// Legosnark paper but inspired from `rerandomize_proof` in `ark_groth16`. Secondly this does not keep
/// `proof.D` as a commitment to the witnesses so not that useful. I don't know if this is theoretically
/// correct. Following comments are quoted from that
///
/// For a proof π of a
/// statement S, the output of the non-deterministic procedure `rerandomize_proof(π)` is
/// statistically indistinguishable from a fresh honest proof of S. For more info, see theorem 3 of
/// [\[BKSV20\]](https://eprint.iacr.org/2020/811)
pub fn rerandomize_proof<E, R>(proof: &Proof<E>, vk: &VerifyingKey<E>, rng: &mut R) -> Proof<E>
where
    E: Pairing,
    R: Rng,
{
    // These are our rerandomization factors. They must be nonzero and uniformly sampled.
    let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
    while r1.is_zero() || r2.is_zero() {
        r1 = E::ScalarField::rand(rng);
        r2 = E::ScalarField::rand(rng);
    }

    //   A' = (1/r₁)A
    //   B' = r₁B + r₁r₂(δG₂) + r₁r₂(γG₂)
    //   C' = C + r₂A
    //   D' = D + r₂A

    // We can unwrap() this because r₁ is guaranteed to be nonzero
    let new_a = proof.a.mul(r1.inverse().unwrap());
    let new_b = proof.b.mul(r1) + (vk.delta_g2 + vk.gamma_g2).mul(r1 * &r2);
    let a_r2 = proof.a.mul(r2).into_affine();
    let new_c = proof.c + a_r2;
    let new_d = proof.d + a_r2;

    Proof {
        a: new_a.into_affine(),
        b: new_b.into_affine(),
        c: new_c.into_affine(),
        d: new_d.into_affine(),
    }
}

/// A similar technique to re-randomize proof as in `rerandomize_proof` but it still keeps `proof.D` a
/// commitment to witnesses. See comments of `rerandomize_proof` for more.
pub fn rerandomize_proof_1<E, R>(
    proof: &Proof<E>,
    old_v: E::ScalarField,
    new_v: E::ScalarField,
    vk: &VerifyingKey<E>,
    eta_delta_inv_g1: &E::G1Affine,
    rng: &mut R,
) -> Proof<E>
where
    E: Pairing,
    R: Rng,
{
    // These are our rerandomization factors. They must be nonzero and uniformly sampled.
    let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
    while r1.is_zero() || r2.is_zero() {
        r1 = E::ScalarField::rand(rng);
        r2 = E::ScalarField::rand(rng);
    }

    //   A' = (1/r₁)A
    //   B' = r₁B + r₁r₂(δG₂)
    //   C' = C + r₂A + (old_v - new_v)((η/δ)G₁)
    //   D' = D + (new_v - old_v)((η/γ)G₁)

    // We can unwrap() this because r₁ is guaranteed to be nonzero
    let new_a = proof.a.mul(r1.inverse().unwrap());
    let new_b = proof.b.mul(r1) + vk.delta_g2.mul(r1 * &r2);
    let a_r2 = proof.a.mul(r2).into_affine();
    let new_c = (proof.c + a_r2) + eta_delta_inv_g1.mul(old_v - new_v).into_affine();
    let new_d = proof.d + vk.eta_gamma_inv_g1.mul(new_v - old_v).into_affine();

    Proof {
        a: new_a.into_affine(),
        b: new_b.into_affine(),
        c: new_c.into_affine(),
        d: new_d.into_affine(),
    }
}

/// Given a circuit, generate its constraints and the corresponding QAP witness.
#[inline]
pub fn synthesize_circuit<E, C, QAP>(
    circuit: C,
) -> crate::Result<(ConstraintSystemRef<E::ScalarField>, Vec<E::ScalarField>)>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    QAP: R1CStoQAP,
{
    let cs = ConstraintSystem::new_ref();

    // Set the optimization goal
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        return Err(Error::SynthesisError(SynthesisError::Unsatisfiable));
    }
    end_timer!(synthesis_time);

    let lc_time = start_timer!(|| "Inlining LCs");
    cs.finalize();
    end_timer!(lc_time);

    let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
    let h =
        QAP::witness_map::<E::ScalarField, GeneralEvaluationDomain<E::ScalarField>>(cs.clone())?;
    end_timer!(witness_map_time);
    Ok((cs, h))
}

fn calculate_coeff<G: AffineRepr>(
    initial: G::Group,
    query: &[G],
    vk_param: G,
    assignment: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Group {
    let el = query[0];
    let acc = G::Group::msm_bigint(&query[1..], assignment);
    initial + el + acc + vk_param
}
