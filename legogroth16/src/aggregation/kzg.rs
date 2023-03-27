use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_iter, format,
    ops::{MulAssign, Neg},
    string::ToString,
    vec,
    vec::Vec,
};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::aggregation::{error::AggregationError, srs::VerifierSRSProjective};

/// KZGOpening represents the KZG opening of a commitment key (which is a tuple
/// given commitment keys are a tuple).
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGOpening<G: AffineRepr>(pub G, pub G);

impl<G: AffineRepr> KZGOpening<G> {
    pub fn new_from_proj(a: G::Group, b: G::Group) -> Self {
        KZGOpening(a.into_affine(), b.into_affine())
    }
}

/// verify_kzg_opening_g2 takes a KZG opening, the final commitment key, SRS and
/// any shift (in TIPP we shift the v commitment by r^-1) and returns a pairing
/// tuple to check if the opening is correct or not.
pub(crate) fn verify_kzg_v<E: Pairing>(
    v_srs: &VerifierSRSProjective<E>,
    final_vkey: &(E::G2Affine, E::G2Affine),
    vkey_opening: &KZGOpening<E::G2Affine>,
    challenges: &[E::ScalarField],
    kzg_challenge: &E::ScalarField,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) {
    // f_v(z)
    let vpoly_eval_z = polynomial_evaluation_product_form_from_transcript(
        challenges,
        kzg_challenge,
        &E::ScalarField::one(),
    );
    // -g such that when we test a pairing equation we only need to check if
    // it's equal 1 at the end:
    // e(a,b) = e(c,d) <=> e(a,b)e(-c,d) = 1
    let ng = v_srs.g.neg().into_affine();
    // e(A,B) = e(C,D) <=> e(A,B)e(-C,D) == 1 <=> e(A,B)e(C,D)^-1 == 1

    // e(g, C_f * h^{-y}) == e(v1 * g^{-x}, \pi) = 1
    kzg_check_v::<E>(
        v_srs,
        ng,
        *kzg_challenge,
        vpoly_eval_z,
        final_vkey.0.into_group(),
        v_srs.g_alpha,
        vkey_opening.0,
        pairing_checker,
    );

    // e(g, C_f * h^{-y}) == e(v2 * g^{-x}, \pi) = 1
    kzg_check_v::<E>(
        v_srs,
        ng,
        *kzg_challenge,
        vpoly_eval_z,
        final_vkey.1.into_group(),
        v_srs.g_beta,
        vkey_opening.1,
        pairing_checker,
    );
}

/// Similar to verify_kzg_opening_g2 but for g1.
pub(crate) fn verify_kzg_w<E: Pairing>(
    v_srs: &VerifierSRSProjective<E>,
    final_wkey: &(E::G1Affine, E::G1Affine),
    wkey_opening: &KZGOpening<E::G1Affine>,
    challenges: &[E::ScalarField],
    r_shift: &E::ScalarField,
    kzg_challenge: &E::ScalarField,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) {
    // compute in parallel f(z) and z^n and then combines into f_w(z) = z^n * f(z)
    let fz = polynomial_evaluation_product_form_from_transcript(challenges, kzg_challenge, r_shift);
    let zn = kzg_challenge.pow(&[v_srs.n as u64]);
    let mut fwz = fz;
    fwz.mul_assign(&zn);

    let nh = v_srs.h.neg().into_affine();

    // e(C_f * g^{-y}, h) = e(\pi, w1 * h^{-x})
    kzg_check_w::<E>(
        v_srs,
        nh,
        *kzg_challenge,
        fwz,
        final_wkey.0.into_group(),
        v_srs.h_alpha,
        wkey_opening.0,
        pairing_checker,
    );

    // e(C_f * g^{-y}, h) = e(\pi, w2 * h^{-x})
    kzg_check_w::<E>(
        v_srs,
        nh,
        *kzg_challenge,
        fwz,
        final_wkey.1.into_group(),
        v_srs.h_beta,
        wkey_opening.1,
        pairing_checker,
    );
}

fn kzg_check_v<E: Pairing>(
    v_srs: &VerifierSRSProjective<E>,
    ng: E::G1Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G2,
    vk: E::G1,
    pi: E::G2Affine,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) {
    // KZG Check: e(g, C_f * h^{-y}) = e(vk * g^{-x}, \pi)
    // Transformed, such that
    // e(-g, C_f * h^{-y}) * e(vk * g^{-x}, \pi) = 1

    // C_f - (y * h)
    let b = (cf - v_srs.h.mul_bigint(y.into_bigint())).into();

    // vk - (g * x)
    let c = (vk - (v_srs.g.mul_bigint(x.into_bigint()))).into();
    pairing_checker.add_multiple_sources_and_target(
        &[ng, c],
        &[b, pi],
        &PairingOutput::<E>::zero(),
    );
}

fn kzg_check_w<E: Pairing>(
    v_srs: &VerifierSRSProjective<E>,
    nh: E::G2Affine,
    x: E::ScalarField,
    y: E::ScalarField,
    cf: E::G1,
    wk: E::G2,
    pi: E::G1Affine,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) {
    // KZG Check: e(C_f * g^{-y}, h) = e(\pi, wk * h^{-x})
    // Transformed, such that
    // e(C_f * g^{-y}, -h) * e(\pi, wk * h^{-x}) = 1

    // C_f - (y * g)
    let a = (cf - (v_srs.g.mul_bigint(y.into_bigint()))).into();

    // wk - (x * h)
    let d = (wk - (v_srs.h.mul_bigint(x.into_bigint()))).into();
    pairing_checker.add_multiple_sources_and_target(
        &[a, pi],
        &[nh, d],
        &PairingOutput::<E>::zero(),
    );
}

/// Returns the KZG opening proof for the given commitment key. Specifically, it
/// returns $g^{f(alpha) - f(z) / (alpha - z)}$ for $a$ and $b$.
fn create_kzg_opening<G: AffineRepr>(
    srs_powers_alpha_table: &[G], // h^alpha^i
    srs_powers_beta_table: &[G],  // h^beta^i
    poly: DensePolynomial<G::ScalarField>,
    eval_poly: G::ScalarField,
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, AggregationError> {
    let mut neg_kzg_challenge = *kzg_challenge;
    neg_kzg_challenge = neg_kzg_challenge.neg();

    if poly.coeffs().len() != srs_powers_alpha_table.len() {
        return Err(AggregationError::InvalidSRS(
            format!(
                "SRS len {} != coefficients len {}",
                srs_powers_alpha_table.len(),
                poly.coeffs().len(),
            )
            .to_string(),
        ));
    }

    // f_v(X) - f_v(z) / (X - z)
    let quotient_polynomial = &(&poly - &DensePolynomial::from_coefficients_vec(vec![eval_poly]))
        / &(DensePolynomial::from_coefficients_vec(vec![neg_kzg_challenge, G::ScalarField::one()]));

    let mut quotient_polynomial_coeffs = quotient_polynomial.coeffs;
    quotient_polynomial_coeffs.resize(srs_powers_alpha_table.len(), <G::ScalarField>::zero());
    let quotient_repr = cfg_iter!(quotient_polynomial_coeffs)
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();

    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_alpha_table.len()
    );
    assert_eq!(
        quotient_polynomial_coeffs.len(),
        srs_powers_beta_table.len()
    );

    // we do one proof over h^a and one proof over h^b (or g^a and g^b depending
    // on the curve we are on). that's the extra cost of the commitment scheme
    // used which is compatible with Groth16 CRS instead of the original paper
    // of Bunz'19
    let (a, b) = (
        G::Group::msm_bigint(&srs_powers_alpha_table, &quotient_repr),
        G::Group::msm_bigint(&srs_powers_beta_table, &quotient_repr),
    );
    Ok(KZGOpening::new_from_proj(a, b))
}

/// It returns the evaluation of the polynomial $\prod (1 + x_{l-j}(rX)^{2j}$ at
/// the point z, where transcript contains the reversed order of all challenges (the x).
/// THe challenges must be in reversed order for the correct evaluation of the
/// polynomial in O(logn)
pub(crate) fn polynomial_evaluation_product_form_from_transcript<F: Field>(
    transcript: &[F],
    z: &F,
    r_shift: &F,
) -> F {
    // this is the term (rz) that will get squared at each step to produce the
    // $(rz)^{2j}$ of the formula
    let mut power_zr = *z;
    power_zr.mul_assign(r_shift);

    let one = F::one();

    let mut res = one + transcript[0] * &power_zr;
    for x in &transcript[1..] {
        power_zr = power_zr.square();
        res.mul_assign(one + *x * &power_zr);
    }

    res
}

// Compute the coefficients of the polynomial $\prod_{j=0}^{l-1} (1 + x_{l-j}(rX)^{2j})$
// It does this in logarithmic time directly; here is an example with 2
// challenges:
//
//     We wish to compute $(1+x_1ra)(1+x_0(ra)^2) = 1 +  x_1ra + x_0(ra)^2 + x_0x_1(ra)^3$
//     Algorithm: $c_{-1} = [1]$; $c_j = c_{i-1} \| (x_{l-j} * c_{i-1})$; $r = r*r$
//     $c_0 = c_{-1} \| (x_1 * r * c_{-1}) = [1] \| [rx_1] = [1, rx_1]$, $r = r^2$
//     $c_1 = c_0 \| (x_0 * r^2c_0) = [1, rx_1] \| [x_0r^2, x_0x_1r^3] = [1, x_1r, x_0r^2, x_0x_1r^3]$
//     which is equivalent to $f(a) = 1 + x_1ra + x_0(ra)^2 + x_0x_1r^2a^3$
//
// This method expects the coefficients in reverse order so transcript[i] =
// x_{l-j}.
// f(Y) = Y^n * \prod (1 + x_{l-j-1} (r_shiftY^{2^j}))
fn polynomial_coefficients_from_transcript<F: Field>(transcript: &[F], r_shift: &F) -> Vec<F> {
    let mut coefficients = vec![F::one()];
    let mut power_2_r = *r_shift;

    for (i, x) in transcript.iter().enumerate() {
        let n = coefficients.len();
        if i > 0 {
            power_2_r = power_2_r.square();
        }
        for j in 0..n {
            let coeff = coefficients[j] * &(*x * &power_2_r);
            coefficients.push(coeff);
        }
    }

    coefficients
}

pub fn prove_commitment_v<G: AffineRepr>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, AggregationError> {
    // f_v
    let vkey_poly = DensePolynomial::from_coefficients_vec(
        polynomial_coefficients_from_transcript(transcript, &G::ScalarField::one()),
    );

    // f_v(z)
    let vkey_poly_z = polynomial_evaluation_product_form_from_transcript(
        &transcript,
        kzg_challenge,
        &G::ScalarField::one(),
    );
    create_kzg_opening(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        vkey_poly,
        vkey_poly_z,
        kzg_challenge,
    )
}

pub fn prove_commitment_w<G: AffineRepr>(
    srs_powers_alpha_table: &[G],
    srs_powers_beta_table: &[G],
    transcript: &[G::ScalarField],
    r_shift: &G::ScalarField,
    kzg_challenge: &G::ScalarField,
) -> Result<KZGOpening<G>, AggregationError> {
    let n = srs_powers_alpha_table.len();
    // this computes f(X) = \prod (1 + x (rX)^{2^j})
    let mut fcoeffs = polynomial_coefficients_from_transcript(transcript, r_shift);
    // this computes f_w(X) = X^n * f(X) - it simply shifts all coefficients to by n
    let mut fwcoeffs = vec![G::ScalarField::zero(); fcoeffs.len()];
    fwcoeffs.append(&mut fcoeffs);
    let fw = DensePolynomial::from_coefficients_vec(fwcoeffs);

    // this computes f(z)
    let fz =
        polynomial_evaluation_product_form_from_transcript(&transcript, kzg_challenge, &r_shift);
    // this computes the "shift" z^n
    let zn = kzg_challenge.pow(&[n as u64]);

    // this computes f_w(z) by multiplying by zn
    let mut fwz = fz;
    fwz.mul_assign(&zn);

    create_kzg_opening(
        srs_powers_alpha_table,
        srs_powers_beta_table,
        fw,
        fwz,
        kzg_challenge,
    )
}
