use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Naive multiplication (n^2) of 2 polynomials defined over prime fields
/// Note: Using multiply operator from ark-poly is orders of magnitude slower than naive multiplication
pub fn multiply_poly<F: PrimeField>(
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

/// Multiply given polynomials together
pub fn multiply_many_polys<F: PrimeField>(polys: Vec<DensePolynomial<F>>) -> DensePolynomial<F> {
    #[cfg(not(feature = "parallel"))]
    let r = polys
        .into_iter()
        .reduce(|a, b| multiply_poly(&a, &b))
        .unwrap();

    #[cfg(feature = "parallel")]
    let r = polys.into_par_iter().reduce(
        || DensePolynomial::from_coefficients_vec(vec![F::one()]),
        |a, b| multiply_poly(&a, &b),
    );

    r
}

/// Given a vector of polynomials `polys` and scalars `coeffs`, return their inner product `polys[0] * coeffs[0] + polys[1] * coeffs[1] + ...`
pub fn inner_product_poly<F: PrimeField>(
    polys: Vec<DensePolynomial<F>>,
    coeffs: Vec<F>,
) -> DensePolynomial<F> {
    let product = cfg_into_iter!(coeffs)
        .zip(cfg_into_iter!(polys))
        .map(|(f, p)| &p * f);

    #[cfg(feature = "parallel")]
    let sum = product.reduce(DensePolynomial::zero, |a, b| a + b);

    #[cfg(not(feature = "parallel"))]
    let sum = product.fold(DensePolynomial::zero(), |a, b| a + b);

    sum
}
