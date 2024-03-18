#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! Utilities for batch updates to the accumulators and witnesses.

use crate::setup::SecretKey;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, One, PrimeField, Zero};
use ark_poly::{
    polynomial::{univariate::DensePolynomial, DenseUVPolynomial},
    Polynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut,
    fmt::Debug,
    iter::{IntoIterator, Iterator},
    ops::Neg,
    vec,
    vec::Vec,
};
use digest::DynDigest;
use dock_crypto_utils::{
    cfg_iter_sum,
    msm::multiply_field_elems_with_same_group_elem,
    poly::{inner_product_poly, multiply_many_polys, multiply_poly},
    serde_utils::*,
};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use dock_crypto_utils::ff::{inner_product, powers};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use short_group_sig::bb_sig::prf;

/// Create a polynomial with given points in `updates` as:
/// `(updates[0]-x) * (updates[1]-x) * (updates[2] - x)...(updates[last] - x)`
fn poly_from_given_updates<F: PrimeField>(updates: &[F]) -> DensePolynomial<F> {
    if updates.is_empty() {
        return DensePolynomial::zero();
    }

    let minus_one = -F::one();

    // [(updates[0]-x), (updates[1]-x), (updates[2] - x), ..., (updates[last] - x)]
    let terms = cfg_into_iter!(updates)
        .map(|i| DensePolynomial::from_coefficients_slice(&[*i, minus_one]))
        .collect::<Vec<_>>();

    // Product (updates[0]-x) * (updates[1]-x) * (updates[2] - x)...(updates[last] - x)
    multiply_many_polys(terms)
    // Note: Using multiply operator from ark-poly is orders of magnitude slower than naive multiplication
    // x_i.into_iter().reduce(|a, b| &a * &b).unwrap()
}

// Polynomials as described in section 3 of the paper

/// Polynomial `d_A` and `d_D`. Same polynomial is used for both additions and removals.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Poly_d<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_A`. Used for batch additions
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Poly_v_A<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_D`. Used for batch removals
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Poly_v_D<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_{A, D}`. Used when doing batch additions and removals in the same call
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Poly_v_AD<F: PrimeField>(pub DensePolynomial<F>);

// TODO: Convert arguments to following functions to iterators

impl<F> Poly_d<F>
where
    F: PrimeField,
{
    /// Given a list of elements as `updates`, generates a polynomial `(updates[0]-x) * (updates[1]-x) * (updates[2] - x)...(updates[last] - x)`.
    pub fn generate(updates: &[F]) -> Self {
        if updates.is_empty() {
            // Returning constant polynomial with value one as the evaluation of this polynomial is multiplied by the old witness
            Self(DensePolynomial::from_coefficients_slice(&[F::one()]))
        } else {
            Self(poly_from_given_updates(updates))
        }
    }

    /// Evaluate this polynomial at `x`
    pub fn eval(&self, x: &F) -> F {
        self.0.evaluate(x)
    }

    /// Evaluation of polynomial without creating the polynomial as the variable is already known.
    /// Returns `(updates[0]-x)*(updates[1]-x)*(updates[2]-x)*...(updates[n]-x)`
    pub fn eval_direct(updates: &[F], x: &F) -> F {
        updates.iter().fold(F::one(), |a, y| (*y - *x) * a)
        // TODO: Figure out the why the following line is about 5 times slower than the sequential one above
        // cfg_iter!(updates).map(|y| *y - *x).product()
    }
}

impl<F> Poly_v_A<F>
where
    F: PrimeField,
{
    /// Generate polynomial `v_A(x)` given the list of elements `y_A` as `updates` and the secret
    /// key `alpha`.
    pub fn generate(additions: &[F], alpha: &F) -> Self {
        let n = additions.len();
        if n == 0 {
            return Self(DensePolynomial::zero());
        }
        if n == 1 {
            return Self(DensePolynomial::from_coefficients_vec(vec![F::one()]));
        }

        // Need to compute the sum:
        // (y_1-x)*(y_2-x)*(y_3-x)*..*(y_{n-1}-x) + (y_0+alpha)*(y_2-x)*(y_3-x)*..*(y_{n-1}-x) + (y_0+alpha)*(y_1+alpha)*(y_3-x)*..*(y_{n-1}-x) + (y_0+alpha)*(y_1+alpha)*..*(y_{n-2}+alpha)
        // Compute products by memoization: (y_0+alpha), (y_0+alpha)*(y_1+alpha),...y_0+alpha)*(y_1+alpha)*..*(y_{n-2}+alpha)
        // Compute products by memoization: (y_{n-1}-x), (y_{n-1}-x)*(y_{n-2}-x), ...(y_{n-1}-x)*(y_{n-2}-x)*...*(y_1-x)
        let mut factors = vec![F::one(); n];
        let mut polys = vec![DensePolynomial::from_coefficients_vec(vec![F::one()]); n];
        for s in 1..n {
            factors[s] = factors[s - 1] * (additions[s - 1] + alpha);
            polys[n - 1 - s] = multiply_poly(
                &polys[n - s],
                &DensePolynomial::from_coefficients_vec(vec![additions[n - s], -F::one()]),
            );
        }

        let sum = inner_product_poly(&polys, factors);
        Self(sum)
    }

    /// Generate polynomial `v_A(x)` given the list of elements `y_A` as `updates` and the secret
    /// key `alpha`. Slower than `Self::generate` but uses less memory at the cost of recomputing
    /// products of field elements and polynomials
    pub fn generate_without_memoize(additions: &[F], alpha: &F) -> Self {
        let n = additions.len();
        if n == 0 {
            return Self(DensePolynomial::zero());
        }
        let sum = (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, additions, alpha);
                let poly = if s < n - 1 {
                    let roots: Vec<F> = cfg_iter!(additions).skip(s + 1).map(|a| *a).collect();
                    poly_from_given_updates(&roots)
                } else {
                    DensePolynomial::from_coefficients_vec(vec![F::one()])
                };
                &poly * factor
            })
            .fold(DensePolynomial::zero(), |a, b| a + b);
        Self(sum)
    }

    /// Evaluate this polynomial at `x`
    pub fn eval(&self, x: &F) -> F {
        self.0.evaluate(x)
    }

    /// Evaluation of polynomial without creating the polynomial as the variables are already known.
    pub fn eval_direct(additions: &[F], alpha: &F, x: &F) -> F {
        let n = additions.len();
        if n == 0 {
            return F::zero();
        }
        if n == 1 {
            return F::one();
        }

        // Compute products (y_0+alpha), (y_0+alpha)*(y_1+alpha), .. etc by memoization
        // Compute products (y_{n-1}-x), (y_{n-1}-x)*(y_{n-2}-x), .. etc by memoization
        let mut factors = vec![F::one(); n];
        let mut polys = vec![F::one(); n];
        for s in 1..n {
            factors[s] = factors[s - 1] * (additions[s - 1] + alpha);
            polys[n - 1 - s] = polys[n - s] * (additions[n - s] - *x);
        }
        factors
            .into_iter()
            .zip(polys.into_iter())
            .map(|(f, p)| p * f)
            .fold(F::zero(), |a, b| a + b)

        // TODO: Following is slower by factor of 2 from above but why?
        /*cfg_into_iter!(factors)
        .zip(cfg_into_iter!(polys))
        .map(|(f, p)| p * f)
        .reduce(F::zero(), |a, b| a + b)*/
    }

    /// Evaluation of polynomial at multiple values without creating the polynomial as the variables are already known.
    pub fn eval_direct_on_batch(additions: &[F], alpha: &F, x: &[F]) -> Vec<F> {
        let n = additions.len();
        let m = x.len();
        if n == 0 {
            return vec![F::zero(); m];
        }
        if n == 1 {
            return vec![F::one(); m];
        }
        // Compute products (y_0+alpha), (y_0+alpha)*(y_1+alpha), .. etc by memoization
        let mut factors = vec![F::one(); n];
        let mut polys = vec![vec![F::one(); n]; m];
        for s in 1..n {
            factors[s] = factors[s - 1] * (additions[s - 1] + alpha);
            cfg_iter_mut!(polys).enumerate().for_each(|(j, polys_j)| {
                polys_j[n - 1 - s] = polys_j[n - s] * (additions[n - s] - x[j])
            });
        }
        cfg_into_iter!(polys)
            .map(|poly| {
                /*factors
                .iter()
                .zip(poly.into_iter())
                .map(|(f, p)| p * f)
                .fold(F::zero(), |a, b| a + b)*/
                inner_product(&factors, &poly)
            })
            .collect()
    }

    /// Evaluation of polynomial without creating the polynomial as the variables are already known.
    /// Slower than `Self::eval_direct` but uses less memory at the cost of recomputing
    /// products of field elements
    pub fn eval_direct_without_memoize(additions: &[F], alpha: &F, x: &F) -> F {
        let n = additions.len();
        (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, additions, alpha);
                let poly = if s < n - 1 {
                    additions
                        .iter()
                        .skip(s + 1)
                        .map(|a| *a - *x)
                        .fold(F::one(), |a, b| a * b)
                } else {
                    F::one()
                };
                poly * factor
            })
            .fold(F::zero(), |a, b| a + b)
    }

    fn compute_factor(s: usize, additions: &[F], alpha: &F) -> F {
        if s > 0 {
            (0..s)
                .map(|i| additions[i] + *alpha)
                .reduce(|a, b| a * b)
                .unwrap()
        } else {
            F::one()
        }
    }
}

impl<F> Poly_v_D<F>
where
    F: PrimeField,
{
    /// Generate polynomial `v_D(x)` given the list of elements `y_D` as `updates` and the secret key `alpha`
    pub fn generate(removals: &[F], alpha: &F) -> Self {
        let n = removals.len();
        if n == 0 {
            return Self(DensePolynomial::zero());
        }

        // Need products of terms 1/(removals[i]+alpha) for all, so invert them all at once thus
        // `y_plus_alpha_inv` will be 1/(removals[0] + alpha), 1/(removals[1] + alpha), .. etc
        let mut y_plus_alpha_inv = removals.iter().map(|y| *y + *alpha).collect::<Vec<_>>();
        batch_inversion(&mut y_plus_alpha_inv);

        // Compute products by memoization: 1/(y_0+alpha), 1/(y_0+alpha)*1/(y_1+alpha), ...., 1/(y_0+alpha)*1/(y_1+alpha)*...*1/(y_{n-1}+alpha)
        // Compute products by memoization: (y_0-x), (y_0-x)*(y_1-x), ...., (y_0-x)*(y_1-x)*..*(y_{n-2}-x)
        let mut factors = vec![F::one(); n];
        let mut polys = vec![DensePolynomial::from_coefficients_vec(vec![F::one()]); n];
        factors[0] = y_plus_alpha_inv[0];
        for s in 1..n {
            factors[s] = factors[s - 1] * y_plus_alpha_inv[s];
            polys[s] = multiply_poly(
                &polys[s - 1],
                &DensePolynomial::from_coefficients_vec(vec![removals[s - 1], -F::one()]),
            );
        }

        let sum = inner_product_poly(&polys, factors);
        Self(sum)
    }

    /// Generate polynomial `v_D(x)` given the list of elements `y_D` as `updates` and the secret key
    /// `alpha`. Slower than `Self::generate` but uses less memory at the cost of recomputing
    /// products of field elements and polynomials
    pub fn generate_without_memoize(removals: &[F], alpha: &F) -> Self {
        let n = removals.len();
        if n == 0 {
            return Self(DensePolynomial::zero());
        }
        let sum = (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, removals, alpha);
                let poly = if s > 0 {
                    let roots: Vec<F> = cfg_iter!(removals).take(s).map(|a| *a).collect();
                    poly_from_given_updates(&roots)
                } else {
                    DensePolynomial::from_coefficients_vec(vec![F::one()])
                };
                &poly * factor
            })
            .fold(DensePolynomial::zero(), |a, b| a + b);
        Self(sum)
    }

    /// Evaluate this polynomial at `x`
    pub fn eval(&self, x: &F) -> F {
        self.0.evaluate(x)
    }

    /// Evaluation of polynomial without creating the polynomial as the variables are already known.
    pub fn eval_direct(removals: &[F], alpha: &F, x: &F) -> F {
        let n = removals.len();
        if n == 0 {
            return F::zero();
        }

        // Compute 1/(removals[i]+alpha) for all i
        let mut y_plus_alpha_inv = removals.iter().map(|y| *y + *alpha).collect::<Vec<_>>();
        batch_inversion(&mut y_plus_alpha_inv);

        // Compute products by memoization: 1/(y_0+alpha), 1/(y_0+alpha)*1/(y_1+alpha), ...., 1/(y_0+alpha)*1/(y_1+alpha)*...*1/(y_{n-1}+alpha)
        // Compute products by memoization: (y_0-x), (y_0-x)*(y_1-x), ...., (y_0-x)*(y_1-x)*..*(y_{n-2}-x)
        let mut factors = vec![F::one(); n];
        let mut polys = vec![F::one(); n];
        factors[0] = y_plus_alpha_inv[0];
        for s in 1..n {
            factors[s] = factors[s - 1] * y_plus_alpha_inv[s];
            polys[s] = polys[s - 1] * (removals[s - 1] - *x);
        }

        factors
            .into_iter()
            .zip(polys.into_iter())
            .map(|(f, p)| p * f)
            .fold(F::zero(), |a, b| a + b)

        // TODO: Following is slower by factor of ~1.5 from above but why?
        /*cfg_into_iter!(factors)
        .zip(cfg_into_iter!(polys))
        .map(|(f, p)| p * f)
        .reduce(|| F::zero(), |a, b| a + b)*/
    }

    pub fn eval_direct_on_batch(removals: &[F], alpha: &F, x: &[F]) -> Vec<F> {
        let n = removals.len();
        let m = x.len();
        if n == 0 {
            return vec![F::zero(); m];
        }
        // Compute 1/(removals[i]+alpha) for all i
        let mut y_plus_alpha_inv = removals.iter().map(|y| *y + *alpha).collect::<Vec<_>>();
        batch_inversion(&mut y_plus_alpha_inv);

        // Compute products by memoization: 1/(y_0+alpha), 1/(y_0+alpha)*1/(y_1+alpha), ...., 1/(y_0+alpha)*1/(y_1+alpha)*...*1/(y_{n-1}+alpha)
        let mut factors = vec![F::one(); n];
        let mut polys = vec![vec![F::one(); n]; m];
        factors[0] = y_plus_alpha_inv[0];
        for s in 1..n {
            factors[s] = factors[s - 1] * y_plus_alpha_inv[s];
            cfg_iter_mut!(polys)
                .enumerate()
                .for_each(|(j, polys_j)| polys_j[s] = polys_j[s - 1] * (removals[s - 1] - x[j]));
        }
        cfg_into_iter!(polys)
            .map(|poly| {
                factors
                    .iter()
                    .zip(poly.into_iter())
                    .map(|(f, p)| p * f)
                    .fold(F::zero(), |a, b| a + b)
                // inner_product(&factors, &poly)
            })
            .collect()
    }

    /// Evaluation of polynomial without creating the polynomial as the variables are already known.
    /// Slower than `Self::eval_direct` but uses less memory at the cost of recomputing
    /// products of field elements
    pub fn eval_direct_without_memoize(removals: &[F], alpha: &F, x: &F) -> F {
        let n = removals.len();
        (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, removals, alpha);
                let poly = if s > 0 {
                    removals
                        .iter()
                        .take(s)
                        .map(|a| *a - *x)
                        .fold(F::one(), |a, b| a * b)
                } else {
                    F::one()
                };
                poly * factor
            })
            .fold(F::zero(), |a, b| a + b)
    }

    pub fn get_coefficients(&self) -> &[F] {
        &self.0.coeffs
    }

    fn compute_factor(s: usize, removals: &[F], alpha: &F) -> F {
        (0..s + 1)
            .map(|i| removals[i] + *alpha)
            .fold(F::one(), |a, b| a * b)
            .inverse()
            .unwrap()
    }
}

impl<F> Poly_v_AD<F>
where
    F: PrimeField,
{
    /// Generate polynomial `v_{A,D}(x)`, given `y_A` as `additions`, `y_D` as `removals` and the secret key `alpha`
    pub fn generate(additions: &[F], removals: &[F], alpha: &F) -> Self {
        let mut p = Poly_v_A::generate(additions, alpha).0;
        if !removals.is_empty() {
            p = &p
                - &(&Poly_v_D::generate(removals, alpha).0 * Self::compute_factor(additions, alpha))
        }
        Self(p)
    }

    /// Evaluate this polynomial at `x`
    pub fn eval(&self, x: &F) -> F {
        self.0.evaluate(x)
    }

    /// Evaluation of polynomial without creating the polynomial as the variables are already known.
    pub fn eval_direct(additions: &[F], removals: &[F], alpha: &F, x: &F) -> F {
        let mut e = Poly_v_A::eval_direct(additions, alpha, x);
        if !removals.is_empty() {
            e -= Poly_v_D::eval_direct(removals, alpha, x) * Self::compute_factor(additions, alpha)
        }
        e
    }

    pub fn eval_direct_on_batch(additions: &[F], removals: &[F], alpha: &F, x: &[F]) -> Vec<F> {
        let f = Self::compute_factor(additions, alpha);
        let mut a = Poly_v_A::eval_direct_on_batch(additions, alpha, x);
        if !removals.is_empty() {
            let b = Poly_v_D::eval_direct_on_batch(removals, alpha, x);
            cfg_iter_mut!(a)
                .enumerate()
                .for_each(|(i, a_i)| *a_i = *a_i - (b[i] * f));
        }
        a
    }

    pub fn get_coefficients(&self) -> &[F] {
        &self.0.coeffs
    }

    fn compute_factor(additions: &[F], alpha: &F) -> F {
        additions
            .iter()
            .map(|a| *a + *alpha)
            .fold(F::one(), |a, b| a * b)
    }
}

/// Published by the accumulator manager to allow witness updates without secret info. This "represents" a polynomial which
/// will be evaluated at the element whose witness needs to be updated. Defined in section 4.1 of the paper
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Omega<G: AffineRepr>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<G>);

impl<G> Omega<G>
where
    G: AffineRepr,
{
    /// Create new `Omega` after `additions` are added and `removals` are removed from `old_accumulator`.
    /// Note that `old_accumulator` is the accumulated value before the updates were made.
    /// Returns `c_0 * V, c_1 * V, ..., c_n * V` where `V` is the accumulator before the update and `c_i` are the coefficients of
    /// the polynomial `v_AD`
    pub fn new(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Self {
        let poly = Poly_v_AD::generate(additions, removals, &sk.0);
        let coeffs = poly.get_coefficients();
        Self(G::Group::normalize_batch(
            &multiply_field_elems_with_same_group_elem(old_accumulator.into_group(), coeffs),
        ))
    }

    /// Create `Omega` for KB positive accumulator after `removals` are removed from `old_accumulator`.
    /// Returns `c_0 * -V, c_1 * -V, ..., c_n * -V` where `V` is the accumulator before the update and `c_i` are the coefficients of
    /// the polynomial `v_D`. As this accumulator does not change on additions, only polynomial `v_D` is generated.
    pub fn new_for_kb_positive_accumulator<D: Default + DynDigest + Clone>(
        removals: &[G::ScalarField],
        old_accumulator: &G,
        sk: &crate::kb_positive_accumulator::setup::SecretKey<G::ScalarField>,
    ) -> Self {
        let accum_members = cfg_into_iter!(removals)
            .map(|r| prf::<G::ScalarField, D>(r, &sk.sig))
            .collect::<Vec<_>>();
        let poly = Poly_v_D::generate(&accum_members, &sk.accum.0);
        let coeffs = poly.get_coefficients();
        Self(G::Group::normalize_batch(
            &multiply_field_elems_with_same_group_elem(old_accumulator.into_group().neg(), coeffs),
        ))
    }

    /// Create 2 `Omega`s for KB universal accumulator. As this accumulator comprises of 2 positive accumulators, this
    /// returns 2 `Omega`s, one for each of those accumulators
    pub fn new_for_kb_universal_accumulator(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        old_mem_accumulator: &G,
        old_non_mem_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> (Self, Self) {
        let m = additions.len();
        let n = removals.len();
        let alpha = &sk.0;

        // mem_add_poly and mem_rem_poly are used to create v_A and v_D for the membership accumulator

        // (additions[0] + alpha), (additions[0] + alpha)*(additions[1] + alpha), ..., (additions[0] + alpha)*(additions[1] + alpha)*...(additions[m-1] + alpha)
        let mut factors_add = vec![G::ScalarField::one(); m];
        // (additions[1] - x)*(additions[2] - x)*...(additions[m-1] - x), (additions[2] - x)*(additions[3] - x)*...(additions[m-1] - x), .., 1. For v_A polynomial for membership accumulator
        let mut mem_add_poly =
            vec![DensePolynomial::from_coefficients_vec(vec![G::ScalarField::one()]); m];
        // 1, (additions[0] - x), (additions[0] - x)*(additions[1] - x), ..., (additions[0] - x)*(additions[1] - x)*...(additions[m-2] - x). For v_D polynomial for non-membership accumulator
        let mut non_mem_rem_poly =
            vec![DensePolynomial::from_coefficients_vec(vec![G::ScalarField::one()]); m];

        // (removals[0] + alpha), (removals[0] + alpha)*(removals[1] + alpha), ..., (removals[0] + alpha)*(removals[1] + alpha)*...(removals[n-1] + alpha)
        let mut factors_rem = vec![G::ScalarField::one(); n];
        // 1, (removals[0] - x), (removals[0] - x)*(removals[1] - x), ..., (removals[0] - x)*(removals[1] - x)*...(removals[n-2] - x). For v_D polynomial for membership accumulator
        let mut mem_rem_poly =
            vec![DensePolynomial::from_coefficients_vec(vec![G::ScalarField::one()]); n];
        // (removals[1] - x)*(removals[2] - x)*...(removals[n-1] - x), (removals[2] - x)*(removals[3] - x)*...(removals[n-1] - x), .., 1. For v_A polynomial for non-membership accumulator
        let mut non_mem_add_poly =
            vec![DensePolynomial::from_coefficients_vec(vec![G::ScalarField::one()]); n];

        let minus_1 = -G::ScalarField::one();

        if !additions.is_empty() {
            factors_add[0] = additions[0] + alpha;
        }
        if !removals.is_empty() {
            factors_rem[0] = removals[0] + alpha;
        }

        for s in 1..m {
            factors_add[s] = factors_add[s - 1] * (additions[s] + alpha);
            mem_add_poly[m - s - 1] = multiply_poly(
                &mem_add_poly[m - s],
                &DensePolynomial::from_coefficients_vec(vec![additions[m - s], minus_1]),
            );
            non_mem_rem_poly[s] = multiply_poly(
                &non_mem_rem_poly[s - 1],
                &DensePolynomial::from_coefficients_vec(vec![additions[s - 1], minus_1]),
            );
        }
        for s in 1..n {
            factors_rem[s] = factors_rem[s - 1] * (removals[s] + alpha);
            non_mem_add_poly[n - s - 1] = multiply_poly(
                &non_mem_add_poly[n - s],
                &DensePolynomial::from_coefficients_vec(vec![removals[n - s], minus_1]),
            );
            mem_rem_poly[s] = multiply_poly(
                &mem_rem_poly[s - 1],
                &DensePolynomial::from_coefficients_vec(vec![removals[s - 1], minus_1]),
            );
        }

        // 1/(additions[0] + alpha), 1/(additions[0] + alpha)*(additions[1] + alpha), ..., 1/(additions[0] + alpha)*(additions[1] + alpha)*...(additions[m-1] + alpha)
        let mut factors_add_inv = factors_add.clone();
        batch_inversion(&mut factors_add_inv);
        // 1/(removals[0] + alpha), 1/(removals[0] + alpha)*(removals[1] + alpha), ..., 1/(removals[0] + alpha)*(removals[1] + alpha)*...(removals[n-1] + alpha)
        let mut factors_rem_inv = factors_rem.clone();
        batch_inversion(&mut factors_rem_inv);

        let one = G::ScalarField::one();
        let zero = DensePolynomial::zero;

        // 1*mem_add_poly[0] + factors_add[0]*mem_add_poly[1] + ... + factors_add[m-2]*mem_add_poly[m-1]
        let mem_poly_v_A = cfg_into_iter!(0..m)
            .map(|i| if i == 0 { &one } else { &factors_add[i - 1] })
            .zip(cfg_iter!(mem_add_poly))
            .map(|(f, p)| p * *f);
        let mem_poly_v_A = cfg_iter_sum!(mem_poly_v_A, zero);

        // 1*non_mem_add_poly[0] + factors_rem[0]*non_mem_add_poly[1] + ... + factors_rem[n-2]*non_mem_add_poly[n-1]
        let non_mem_poly_v_A = cfg_into_iter!(0..n)
            .map(|i| if i == 0 { &one } else { &factors_rem[i - 1] })
            .zip(cfg_iter!(non_mem_add_poly))
            .map(|(f, p)| p * *f);
        let non_mem_poly_v_A = cfg_iter_sum!(non_mem_poly_v_A, zero);

        let mem_poly_v_D = inner_product_poly(&mem_rem_poly, factors_rem_inv);

        let non_mem_poly_v_D = inner_product_poly(&non_mem_rem_poly, factors_add_inv);

        // mem_poly_v_AD = mem_poly_v_A - mem_poly_v_AD*(additions[0] + alpha)*(additions[1] + alpha)*...(additions[m-1] + alpha)
        let mut mem_poly_v_AD = mem_poly_v_A;
        if !removals.is_empty() {
            mem_poly_v_AD = &mem_poly_v_AD
                - &(&mem_poly_v_D
                    * if additions.is_empty() {
                        G::ScalarField::one()
                    } else {
                        factors_add[m - 1]
                    });
        }
        let omega_mem = Self(G::Group::normalize_batch(
            &multiply_field_elems_with_same_group_elem(
                old_mem_accumulator.into_group(),
                &mem_poly_v_AD.coeffs,
            ),
        ));

        // non_mem_poly_v_AD = non_mem_poly_v_AD - non_mem_poly_v_AD*(removals[0] + alpha)*(removals[1] + alpha)*...(removals[n-1] + alpha)
        let mut non_mem_poly_v_AD = non_mem_poly_v_A;
        if !additions.is_empty() {
            non_mem_poly_v_AD = &non_mem_poly_v_AD
                - &(&non_mem_poly_v_D
                    * if removals.is_empty() {
                        G::ScalarField::one()
                    } else {
                        factors_rem[n - 1]
                    });
        }
        let omega_non_mem = Self(G::Group::normalize_batch(
            &multiply_field_elems_with_same_group_elem(
                old_non_mem_accumulator.into_group(),
                &non_mem_poly_v_AD.coeffs,
            ),
        ));

        (omega_mem, omega_non_mem)
    }

    /// Inner product of powers of `y`, i.e. the element for which witness needs to be updated and `omega`.
    /// Equivalent to evaluating the polynomial at `y` and multiplying the result by `scalar`
    /// Used by the (non)member to update its witness without the knowledge of secret key.
    pub fn inner_product_with_scaled_powers_of_y(
        &self,
        y: &G::ScalarField,
        scalar: &G::ScalarField,
    ) -> G::Group {
        let powers_of_y = Self::scaled_powers_of_y(y, scalar, self.len());
        // <powers_of_y, omega>
        G::Group::msm_unchecked(&self.0, &powers_of_y)
    }

    pub fn inner_product_with_scaled_powers_of_y_temp(
        &self,
        y: &G::ScalarField,
        scalar: &G::ScalarField,
    ) -> G::Group {
        let pow = powers(y, self.len() as u32);
        let r = G::Group::msm_unchecked(&self.0, &pow);
        r * scalar
    }

    /// Return [`scalar`*1, `scalar`*`y`, `scalar`*`y^2`, `scalar`*`y^3`, ..., `scalar`*`y^{n-1}`]
    pub fn scaled_powers_of_y(
        y: &G::ScalarField,
        scalar: &G::ScalarField,
        n: usize,
    ) -> Vec<G::ScalarField> {
        let mut powers = Vec::with_capacity(n);
        if n > 0 {
            powers.push(*scalar);
        }
        for i in 1..n {
            powers.push(powers[i - 1] * y);
        }
        powers
    }

    /// Scale the omega vector by the given `scalar`
    pub fn scaled(&self, scalar: &G::ScalarField) -> Vec<G::Group> {
        let scalar_bigint = scalar.into_bigint();
        cfg_iter!(self.0)
            .map(|o| o.mul_bigint(scalar_bigint))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Coefficient (`c_i`) at the _ith_ position
    pub fn coefficient(&self, i: usize) -> &G {
        &self.0[i]
    }

    pub fn from(coeffs: Vec<G>) -> Self {
        Self(coeffs)
    }

    #[cfg(test)]
    /// Test function to check if Omega is generated correctly.
    pub(crate) fn check(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        element: &G::ScalarField,
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) {
        use ark_ff::Field;

        let v_AD = Poly_v_AD::eval_direct(additions, removals, &sk.0, element);
        let d_D_inv = Poly_d::eval_direct(removals, element).inverse().unwrap();

        let mut V_prime = old_accumulator.into_group();
        V_prime *= v_AD * d_D_inv;

        let omega = Self::new(additions, removals, old_accumulator, sk);
        // <powers_of_y, omega> * 1/d_D(x)
        let y_omega_ip = omega.inner_product_with_scaled_powers_of_y(element, &d_D_inv);

        assert_eq!(V_prime, y_omega_ip);
    }

    #[cfg(test)]
    /// Test function to check if generated correctly.
    pub(crate) fn check_for_kb_positive_accumulator<D: Default + DynDigest + Clone>(
        removals: &[G::ScalarField],
        element: &G::ScalarField,
        old_accumulator: &G,
        sk: &crate::kb_positive_accumulator::setup::SecretKey<G::ScalarField>,
    ) {
        use ark_ff::Field;

        let removed_members = cfg_into_iter!(removals)
            .map(|r| prf::<G::ScalarField, D>(r, &sk.sig))
            .collect::<Vec<_>>();
        let member = prf::<G::ScalarField, D>(element, &sk.sig);
        let v_D = Poly_v_D::eval_direct(&removed_members, &sk.accum.0, &member);
        let d_D_inv = Poly_d::eval_direct(&removed_members, &member)
            .inverse()
            .unwrap();

        let mut V_prime = old_accumulator.into_group();
        V_prime *= v_D * d_D_inv;

        let omega = Self::new_for_kb_positive_accumulator::<D>(removals, old_accumulator, sk);
        // <powers_of_y, omega> * 1/d_D(x)
        let y_omega_ip = omega.inner_product_with_scaled_powers_of_y(&member, &d_D_inv);

        assert_eq!(V_prime, y_omega_ip.neg());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn polys() {
        // Test evaluation of polynomials defined above
        let mut rng = StdRng::seed_from_u64(0u64);
        let updates = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();

        let batch_size = 10;
        let x = Fr::rand(&mut rng);
        let x_vec = (0..batch_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();

        let poly_d = Poly_d::generate(&updates);
        assert_eq!(Poly_d::eval_direct(&updates, &x), poly_d.eval(&x));

        // Polynomial with degree 1, i.e. a single update
        let single_update = vec![Fr::rand(&mut rng)];
        let poly_d_single = Poly_d::generate(&single_update);
        assert_eq!(
            Poly_d::eval_direct(&single_update, &x),
            single_update[0] - x
        );
        assert_eq!(poly_d_single.eval(&x), single_update[0] - x);

        assert_eq!(Poly_d::eval_direct(&[], &x), Fr::one());
        assert_eq!(Poly_d::generate(&[]).eval(&x), Fr::one());

        let alpha = Fr::rand(&mut rng);

        let poly_v_A = Poly_v_A::generate(&updates, &alpha);
        assert_eq!(
            Poly_v_A::eval_direct(&updates, &alpha, &x),
            poly_v_A.eval(&x)
        );
        assert_eq!(
            Poly_v_A::generate_without_memoize(&updates, &alpha),
            Poly_v_A::generate(&updates, &alpha)
        );
        assert_eq!(
            Poly_v_A::eval_direct_without_memoize(&updates, &alpha, &x),
            Poly_v_A::eval_direct(&updates, &alpha, &x)
        );
        assert_eq!(
            Poly_v_A::eval_direct_without_memoize(&[], &alpha, &x),
            Fr::zero()
        );
        assert_eq!(Poly_v_A::eval_direct(&[], &alpha, &x), Fr::zero());
        assert_eq!(
            Poly_v_A::generate_without_memoize(&[], &alpha).eval(&x),
            Fr::zero()
        );
        assert_eq!(Poly_v_A::generate(&[], &alpha).eval(&x), Fr::zero());
        assert_eq!(
            Poly_v_A::eval_direct_on_batch(&updates, &alpha, &x_vec),
            (0..batch_size)
                .map(|i| Poly_v_A::eval_direct(&updates, &alpha, &x_vec[i]))
                .collect::<Vec<_>>(),
        );

        let poly_v_D = Poly_v_D::generate(&updates, &alpha);
        assert_eq!(
            Poly_v_D::eval_direct(&updates, &alpha, &x),
            poly_v_D.eval(&x)
        );
        assert_eq!(
            Poly_v_D::generate_without_memoize(&updates, &alpha),
            Poly_v_D::generate(&updates, &alpha)
        );
        assert_eq!(
            Poly_v_D::eval_direct_without_memoize(&updates, &alpha, &x),
            Poly_v_D::eval_direct(&updates, &alpha, &x)
        );
        assert_eq!(
            Poly_v_D::eval_direct_without_memoize(&[], &alpha, &x),
            Fr::zero()
        );
        assert_eq!(Poly_v_D::eval_direct(&[], &alpha, &x), Fr::zero());
        assert_eq!(
            Poly_v_D::generate_without_memoize(&[], &alpha).eval(&x),
            Fr::zero()
        );
        assert_eq!(Poly_v_D::generate(&[], &alpha).eval(&x), Fr::zero());
        assert_eq!(
            Poly_v_D::eval_direct_on_batch(&updates, &alpha, &x_vec),
            (0..batch_size)
                .map(|i| Poly_v_D::eval_direct(&updates, &alpha, &x_vec[i]))
                .collect::<Vec<_>>(),
        );

        for &i in &[100, 70, 50, 40, 35, 20, 10, 7, 1, 0] {
            let updates_1 = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();

            let start = Instant::now();
            let poly_v_AD = Poly_v_AD::generate(&updates, &updates_1, &alpha);
            println!(
                "For {} additions and {} removals, Poly_v_AD::generates takes {:?}",
                updates.len(),
                updates_1.len(),
                start.elapsed()
            );

            let start = Instant::now();
            let expected = Poly_v_AD::eval_direct(&updates, &updates_1, &alpha, &x);
            println!(
                "For {} additions and {} removals, Poly_v_AD::eval_direct takes {:?}",
                updates.len(),
                updates_1.len(),
                start.elapsed()
            );
            assert_eq!(expected, poly_v_AD.eval(&x));

            let start = Instant::now();
            let r1 = Poly_v_AD::eval_direct_on_batch(&updates, &updates_1, &alpha, &x_vec);
            println!("For {} additions and {} removals and a batch of {}, Poly_v_AD::eval_direct_on_batch takes {:?}", updates.len(), updates_1.len(), x_vec.len(), start.elapsed());

            let start = Instant::now();
            let r2 = (0..batch_size)
                .map(|i| Poly_v_AD::eval_direct(&updates, &updates_1, &alpha, &x_vec[i]))
                .collect::<Vec<_>>();
            println!("For {} additions and {} removals and a batch of {}, Poly_v_AD::eval_direct takes {:?}", updates.len(), updates_1.len(), x_vec.len(), start.elapsed());

            assert_eq!(r1, r2);
        }

        macro_rules! test_poly_time {
            ($count:ident, $updates:ident, $alpha:ident, $x:ident, $poly: ident, $name: expr) => {
                let start = Instant::now();
                let poly_m = $poly::generate(&$updates, &$alpha);
                let poly_gen_mem_time = start.elapsed();

                let start = Instant::now();
                let poly = $poly::generate_without_memoize(&$updates, &$alpha);
                let poly_gen_time = start.elapsed();

                assert_eq!(poly, poly_m);

                let start = Instant::now();
                let poly_eval_m = $poly::eval_direct(&$updates, &$alpha, &$x);
                let poly_eval_mem_time = start.elapsed();

                let start = Instant::now();
                let poly_eval = $poly::eval_direct_without_memoize(&$updates, &$alpha, &$x);
                let poly_eval_time = start.elapsed();

                assert_eq!(poly_eval_m, poly_eval);

                println!("For {} updates, {}::generates takes {:?} with memoization and {:?} without memoization", $count, $name, poly_gen_mem_time, poly_gen_time);
                println!("For {} updates, {}::eval_direct takes {:?} with memoization and {:?} without memoization", $count, $name, poly_eval_mem_time, poly_eval_time);

                let start = Instant::now();
                let a = $poly::eval_direct_on_batch(&$updates, &$alpha, &x_vec);
                let eval_batch_time = start.elapsed();

                let start = Instant::now();
                let b = (0..batch_size).map(|i| $poly::eval_direct(&$updates, &$alpha, &x_vec[i])).collect::<Vec<_>>();
                let eval_single_time = start.elapsed();

                assert_eq!(a, b);

                println!("For {} updates and a batch of {}, {}::eval_direct_on_batch takes {:?}", $count, batch_size, $name, eval_batch_time);
                println!("For {} updates and a batch of {}, {}::eval_direct takes {:?}", $count, batch_size, $name, eval_single_time);
            }
        }

        for count in [100, 200, 400] {
            let updates = (0..count).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
            let x = Fr::rand(&mut rng);

            test_poly_time!(count, updates, alpha, x, Poly_v_A, "Poly_v_A");
            test_poly_time!(count, updates, alpha, x, Poly_v_D, "Poly_v_D");
        }
    }

    #[test]
    fn omega() {
        // Test evaluation of polynomials defined above
        let mut rng = StdRng::seed_from_u64(0u64);
        let secret_key = SecretKey(Fr::rand(&mut rng));
        let accum_value = G1Affine::rand(&mut rng);
        let scalar = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        for size in [10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000] {
            let additions = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
            let removals = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
            let omega = Omega::new(&additions, &removals, &accum_value, &secret_key);
            println!(
                "For {} additions and removals, omega size is {}",
                size,
                omega.len()
            );

            let start = Instant::now();
            let e1 = omega.inner_product_with_scaled_powers_of_y(&y, &scalar);
            println!("Time taken is {:?}", start.elapsed());

            let start = Instant::now();
            let e2 = omega.inner_product_with_scaled_powers_of_y_temp(&y, &scalar);
            println!("Time taken with temp is {:?}", start.elapsed());
            assert_eq!(e1, e2);
        }
    }
}
