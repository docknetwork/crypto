#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! Utilities for batch updates to the accumulators and witnesses.

use crate::setup::SecretKey;
use crate::utils::multiply_field_elems_refs_with_same_group_elem;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_poly::polynomial::{univariate::DensePolynomial, UVPolynomial};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    iter::{IntoIterator, Iterator},
    vec,
    vec::Vec,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Naive multiplication (n^2) of 2 polynomials defined over prime fields
fn multiply_poly<F: PrimeField>(
    left: &DensePolynomial<F>,
    right: &DensePolynomial<F>,
) -> DensePolynomial<F> {
    let mut product = (0..(left.degree() + right.degree() + 1))
        .map(|_| F::zero())
        .collect::<Vec<_>>();
    for i in 0..=left.degree() {
        for j in 0..=right.degree() {
            product[i + j] += left.coeffs[i] * right.coeffs[j];
        }
    }
    DensePolynomial::from_coefficients_vec(product)
}

/// Create a polynomial with given points in `updates` as:
/// (updates[0]-x) * (updates[1]-x) * (updates[2] - x)...(updates[last] - x)
fn poly_from_given_updates<F: PrimeField>(updates: &[F]) -> DensePolynomial<F> {
    if updates.is_empty() {
        return DensePolynomial::zero();
    }

    let minus_one = -F::one();
    // [(updates[0]-x), (updates[1]-x), (updates[2] - x), ..., (updates[last] - x)]
    #[cfg(not(feature = "parallel"))]
    let x_i = updates
        .iter()
        .map(|i| DensePolynomial::from_coefficients_slice(&[*i, minus_one]));

    #[cfg(feature = "parallel")]
    let x_i = updates
        .par_iter()
        .map(|i| DensePolynomial::from_coefficients_slice(&[*i, minus_one]));

    // Product (updates[0]-x) * (updates[1]-x) * (updates[2] - x)...(updates[last] - x)
    #[cfg(not(feature = "parallel"))]
    let r = x_i
        .into_iter()
        .reduce(|a, b| multiply_poly(&a, &b))
        .unwrap();

    #[cfg(feature = "parallel")]
    let r = x_i.into_par_iter().reduce(
        || DensePolynomial::from_coefficients_vec(vec![F::one()]),
        |a, b| multiply_poly(&a, &b),
    );

    r
    // Note: Using multiply operator from ark-poly is orders of magnitude slower than naive multiplication
    // x_i.into_iter().reduce(|a, b| &a * &b).unwrap()
}

pub(crate) fn batch_normalize_projective_into_affine<G: ProjectiveCurve>(
    mut v: Vec<G>,
) -> Vec<G::Affine> {
    G::batch_normalization(&mut v);
    v.into_iter().map(|v| v.into()).collect()
}

// Polynomials as described in section 3 of the paper

/// Polynomial `d_A` and `d_D`. Same polynomial is used for both additions and removals.
pub struct Poly_d<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_A`. Used for batch additions
pub struct Poly_v_A<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_D`. Used for batch removals
pub struct Poly_v_D<F: PrimeField>(pub DensePolynomial<F>);

/// Polynomial `v_{A, D}`. Used when doing batch additions and removals in the same call
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
    /// Returns (updates[0]-x)*(updates[1]-x)*(updates[2]-x)*...(updates[n]-x)*
    pub fn eval_direct(updates: &[F], x: &F) -> F {
        updates.iter().fold(F::one(), |a, y| (*y - *x) * a)
        // TODO: Figure out the why the following line is about 5 times slower than the sequential one above
        // iter!(updates).map(|y| *y - *x).product()
    }
}

impl<F> Poly_v_A<F>
where
    F: PrimeField,
{
    /// Generate polynomial `v_A(x)` given the list of elements `y_A` as `updates` and the secret key `alpha`
    pub fn generate(additions: &[F], alpha: &F) -> Self {
        let n = additions.len();
        if n == 0 {
            return Self(DensePolynomial::zero());
        }
        let sum = (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, additions, alpha);
                let poly = if s < n - 1 {
                    let roots: Vec<F> = iter!(additions).skip(s + 1).map(|a| *a).collect();
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
        let sum = (0..n)
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
            .fold(F::zero(), |a, b| a + b);
        sum
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
        let sum = (0..n)
            .map(|s| {
                let factor = Self::compute_factor(s, removals, alpha);
                let poly = if s > 0 {
                    let roots: Vec<F> = iter!(removals).take(s).map(|a| *a).collect();
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
        let sum = (0..n)
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
            .fold(F::zero(), |a, b| a + b);
        sum
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
        if additions.is_empty() && removals.is_empty() {
            return Self(DensePolynomial::zero());
        }
        let mut p = Poly_v_A::generate(additions, alpha).0;
        if removals.len() > 0 {
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
        if removals.len() > 0 {
            e = e
                - (Poly_v_D::eval_direct(removals, alpha, x)
                    * Self::compute_factor(additions, alpha))
        }
        e
    }

    pub fn get_omega_coefficients(&self) -> &[F] {
        &self.0.coeffs
    }

    fn compute_factor(additions: &[F], alpha: &F) -> F {
        additions
            .iter()
            .map(|a| *a + *alpha)
            .fold(F::one(), |a, b| a * b)
    }
}

/// Published by the accumulator manager to allow witness updates without secret info. Defined in section 4.1 of the paper
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Omega<G: AffineCurve>(pub Vec<G>);

impl<G> Omega<G>
where
    G: AffineCurve,
{
    pub fn new(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Self {
        let poly = Poly_v_AD::generate(additions, removals, &sk.0);
        let coeffs = poly.get_omega_coefficients();
        Omega(batch_normalize_projective_into_affine::<G::Projective>(
            multiply_field_elems_refs_with_same_group_elem(
                4,
                old_accumulator.into_projective(),
                coeffs.iter(),
            ),
        ))
    }

    /// Inner product of powers of `y`, i.e. the element for which witness needs to be updated and `omega`
    /// Used by the (non)member to update its witness without the knowledge of secret key.
    pub fn inner_product_with_powers_of_y(&self, element: &G::ScalarField) -> G::Projective {
        // powers_of_y = [1, element, element^2, element^3, ...]
        let mut powers_of_y = Vec::with_capacity(self.len());
        if self.len() > 0 {
            powers_of_y.push(G::ScalarField::one());
        }
        if self.len() > 1 {
            powers_of_y.push(element.clone());
        }
        for i in 2..self.len() {
            powers_of_y.push(powers_of_y[i - 1] * element);
        }
        let powers_of_y = into_iter!(powers_of_y)
            .map(|y| y.into_repr())
            .collect::<Vec<_>>();

        // <powers_of_y, omega>
        VariableBaseMSM::multi_scalar_mul(&self.0, &powers_of_y)
    }

    /// Scale the omega vector by the given `scalar`
    pub fn scaled(&self, scalar: &G::ScalarField) -> Vec<G::Projective> {
        let scalar_bigint = scalar.into_repr();
        iter!(self.0).map(|o| o.mul(scalar_bigint)).collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Coefficient (`c_i`) at the _ith_ position
    pub fn coefficient(&self, i: usize) -> &G {
        &self.0[i]
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

        let mut V_prime = old_accumulator.into_projective();
        V_prime *= v_AD * d_D_inv;

        let omega = Self::new(additions, removals, old_accumulator, sk);
        let mut y_omega_ip = omega.inner_product_with_powers_of_y(element);
        // <powers_of_y, omega> * 1/d_D(x)
        y_omega_ip *= d_D_inv;

        println!("y_omega_ip={}", y_omega_ip);
        println!("V_prime={}", V_prime);
        assert_eq!(V_prime, y_omega_ip);
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_ff::One;
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};

    use super::*;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn polys() {
        // Test evaluation of polynomials defined above
        let mut rng = StdRng::seed_from_u64(0u64);
        let updates = (0..100)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();

        let x = Fr::rand(&mut rng);

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

        assert_eq!(Poly_d::eval_direct(&vec![], &x), Fr::one());
        assert_eq!(Poly_d::generate(&vec![]).eval(&x), Fr::one());

        let alpha = Fr::rand(&mut rng);

        let poly_v_A = Poly_v_A::generate(&updates, &alpha);
        assert_eq!(
            Poly_v_A::eval_direct(&updates, &alpha, &x),
            poly_v_A.eval(&x)
        );
        assert_eq!(Poly_v_A::eval_direct(&vec![], &alpha, &x), Fr::zero());
        assert_eq!(Poly_v_A::generate(&vec![], &alpha).eval(&x), Fr::zero());

        let poly_v_D = Poly_v_D::generate(&updates, &alpha);
        assert_eq!(
            Poly_v_D::eval_direct(&updates, &alpha, &x),
            poly_v_D.eval(&x)
        );
        assert_eq!(Poly_v_D::eval_direct(&vec![], &alpha, &x), Fr::zero());
        assert_eq!(Poly_v_D::generate(&vec![], &alpha).eval(&x), Fr::zero());

        for i in vec![100, 70, 50, 40, 35, 20, 10, 7, 1, 0] {
            let updates_1 = (0..i)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<Fr>>();
            let poly_v_AD = Poly_v_AD::generate(&updates, &updates_1, &alpha);
            assert_eq!(
                Poly_v_AD::eval_direct(&updates, &updates_1, &alpha, &x),
                poly_v_AD.eval(&x)
            );
        }
    }
}
