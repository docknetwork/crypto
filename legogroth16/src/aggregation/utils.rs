use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::PrimeField;
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut,
    ops::{AddAssign, Mul, MulAssign},
    string::ToString,
    vec::Vec,
};
use dock_crypto_utils::{
    ff::{powers, sum_of_powers},
    randomized_pairing_check::RandomizedPairingChecker,
};

use crate::aggregation::{
    commitment::PairCommitment,
    key::{Key, PreparedVKey},
};

use crate::aggregation::{
    error::AggregationError,
    kzg::{prove_commitment_v, prove_commitment_w, verify_kzg_v, verify_kzg_w, KZGOpening},
    srs::VerifierSRSProjective,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// compress is similar to commit::{V,W}KEY::compress: it modifies the `vec`
/// vector by setting the value at index $i:0 -> split$  $vec[i] = vec[i] +
/// vec[i+split]^scaler$. The `vec` vector is half of its size after this call.
pub(crate) fn compress<C: AffineRepr>(vec: &mut Vec<C>, split: usize, scalar: &C::ScalarField) {
    let s_repr = scalar.into_bigint();
    let (left, right) = vec.split_at_mut(split);
    cfg_iter_mut!(left)
        .zip(cfg_iter!(right))
        .for_each(|(a_l, a_r)| {
            let x = a_r.mul_bigint(s_repr);
            *a_l = (x + *a_l).into_affine();
        });
    let len = left.len();
    vec.resize(len, C::zero());
}

pub(crate) fn inner_product_and_single_commitments<E: Pairing>(
    c_left: &[E::G1Affine],
    c_right: &[E::G1Affine],
    r_left_bi: &[<E::ScalarField as PrimeField>::BigInt],
    r_right_bi: &[<E::ScalarField as PrimeField>::BigInt],
    vk_left_prep: PreparedVKey<E>,
    vk_right_prep: PreparedVKey<E>,
) -> (
    E::G1Affine,
    E::G1Affine,
    PairCommitment<E>,
    PairCommitment<E>,
) {
    // z_l = c[n':] ^ r[:n']
    let zc_l = E::G1::msm_bigint(c_right, r_left_bi).into_affine();
    // Z_r = c[:n'] ^ r[n':]
    let zc_r = E::G1::msm_bigint(c_left, r_right_bi).into_affine();

    // u_l = c[n':] * v[:n']
    let tuc_l = PairCommitment::<E>::single(vk_left_prep, c_right).unwrap();
    // u_r = c[:n'] * v[n':]
    let tuc_r = PairCommitment::<E>::single(vk_right_prep, c_left).unwrap();

    (zc_l, zc_r, tuc_l, tuc_r)
}

pub(crate) fn inner_product_and_double_commitments<E: Pairing>(
    a_left: &[E::G1Affine],
    a_right: &[E::G1Affine],
    b_left: Vec<E::G2Prepared>,
    b_right: Vec<E::G2Prepared>,
    wk_left: &Key<E::G1Affine>,
    wk_right: &Key<E::G1Affine>,
    vk_left_prep: PreparedVKey<E>,
    vk_right_prep: PreparedVKey<E>,
) -> (
    PairingOutput<E>,
    PairingOutput<E>,
    PairCommitment<E>,
    PairCommitment<E>,
) {
    let tab_l =
        PairCommitment::<E>::double(vk_left_prep, wk_right, &a_right, b_left.clone()).unwrap();

    let tab_r =
        PairCommitment::<E>::double(vk_right_prep, wk_left, &a_left, b_right.clone()).unwrap();

    // \prod e(A_right,B_left)
    let zab_l = E::multi_pairing(a_right, b_left);
    let zab_r = E::multi_pairing(a_left, b_right);
    (zab_l, zab_r, tab_l, tab_r)
}

pub(crate) fn aggregate_public_inputs<G: AffineRepr>(
    public_inputs: &[Vec<G::ScalarField>],
    r_powers: &[G::ScalarField],
    r_sum: G::ScalarField,
    gamma_abc_g1: &[G],
) -> G {
    // compute the middle part of the final pairing equation, the one with the public inputs

    // We want to compute MUL(i:0 -> l) S_i ^ (SUM(j:0 -> n) ai,j * r^j)
    // this table keeps tracks of incremental computation of each i-th
    // exponent to later multiply with S_i
    // The index of the table is i, which is an index of the public
    // input element
    // We incrementally build the r vector and the table
    // NOTE: in this version it's not r^2j but simply r^j

    let l = public_inputs[0].len();

    // now we do the multi exponentiation
    let mut summed = cfg_into_iter!(0..l)
        .map(|i| {
            // i denotes the column of the public input, and j denotes which public input
            let mut c = public_inputs[0][i];
            for j in 1..public_inputs.len() {
                let mut ai = public_inputs[j][i];
                ai.mul_assign(&r_powers[j]);
                c.add_assign(&ai);
            }
            c.into_bigint()
        })
        .collect::<Vec<_>>();

    summed.insert(0, r_sum.into_bigint());

    G::Group::msm_bigint(&gamma_abc_g1, &summed).into_affine()
}

pub(crate) fn prove_commitments<E: Pairing>(
    h_alpha_powers_table: &[E::G2Affine],
    h_beta_powers_table: &[E::G2Affine],
    g_alpha_powers_table: &[E::G1Affine],
    g_beta_powers_table: &[E::G1Affine],
    challenges: &[E::ScalarField],
    challenges_inv: &[E::ScalarField],
    shift: &E::ScalarField,
    kzg_challenge: &E::ScalarField,
) -> Result<(KZGOpening<E::G2Affine>, KZGOpening<E::G1Affine>), AggregationError> {
    let vkey_opening = prove_commitment_v(
        h_alpha_powers_table,
        h_beta_powers_table,
        challenges_inv,
        kzg_challenge,
    )?;
    let wkey_opening = prove_commitment_w(
        g_alpha_powers_table,
        g_beta_powers_table,
        challenges,
        shift,
        kzg_challenge,
    )?;
    Ok((vkey_opening, wkey_opening))
}

pub(crate) fn verify_kzg<E: Pairing>(
    v_srs: &VerifierSRSProjective<E>,
    final_vkey: &(E::G2Affine, E::G2Affine),
    vkey_opening: &KZGOpening<E::G2Affine>,
    final_wkey: &(E::G1Affine, E::G1Affine),
    wkey_opening: &KZGOpening<E::G1Affine>,
    challenges: &[E::ScalarField],
    challenges_inv: &[E::ScalarField],
    shift: &E::ScalarField,
    kzg_challenge: &E::ScalarField,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) {
    // Verify commitment keys wellformed
    // check the opening proof for v
    verify_kzg_v(
        v_srs,
        final_vkey,
        vkey_opening,
        &challenges_inv,
        kzg_challenge,
        pairing_checker,
    );

    // check the opening proof for w - note that w has been rescaled by $r^{-1}$
    verify_kzg_w(
        v_srs,
        final_wkey,
        wkey_opening,
        &challenges,
        shift,
        kzg_challenge,
        pairing_checker,
    );
}

pub(crate) fn final_verification_check<E: Pairing>(
    mut source1: Vec<E::G1Affine>,
    mut source2: Vec<E::G2Affine>,
    z_c: E::G1Affine,
    z_ab: &PairingOutput<E>,
    r: &E::ScalarField,
    public_inputs: &[Vec<E::ScalarField>],
    alpha_g1: &E::G1Affine,
    beta_g2: E::G2Affine,
    gamma_g2: E::G2Affine,
    delta_g2: E::G2Affine,
    gamma_abc_g1: &[E::G1Affine],
    checker: &mut RandomizedPairingChecker<E>,
) -> Result<(), AggregationError> {
    let public_inputs_len = public_inputs
        .len()
        .try_into()
        .map_err(|_| AggregationError::PublicInputsTooLarge(public_inputs.len()))?;
    let r_powers = powers(r, public_inputs_len);
    let r_sum = sum_of_powers::<E::ScalarField>(r, public_inputs_len);

    // Check aggregate pairing product equation

    let alpha_g1_r_sum = alpha_g1.mul(r_sum);
    source1.push(alpha_g1_r_sum.into_affine());
    source2.push(beta_g2);

    source1.push(aggregate_public_inputs(
        public_inputs,
        &r_powers,
        r_sum,
        gamma_abc_g1,
    ));
    source2.push(gamma_g2);

    source1.push(z_c);
    source2.push(delta_g2);

    checker.add_multiple_sources_and_target(&source1, source2, &z_ab);

    match checker.verify() {
        true => Ok(()),
        false => Err(AggregationError::InvalidProof(
            "Proof Verification Failed due to pairing checks".to_string(),
        )),
    }
}
