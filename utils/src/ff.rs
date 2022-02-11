use ark_ff::PrimeField;
use ark_std::cfg_into_iter;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Inner product of 2 vectors `a` and `b`
pub fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    let size = a.len().min(b.len());

    #[cfg(feature = "parallel")]
    let sum = cfg_into_iter!(0..size)
        .map(|i| a[i] * b[i])
        .reduce(|| F::zero(), |accum, v| accum + v);

    #[cfg(not(feature = "parallel"))]
    let sum = (0..size)
        .map(|i| a[i] * b[i])
        .fold(F::zero(), |accum, v| accum + v);

    sum
}
