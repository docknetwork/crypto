use ark_ff::PrimeField;
use ark_std::rand::Rng;

#[cfg(feature = "parallel")]
use {ark_std::cfg_into_iter, rayon::prelude::*};

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

pub fn non_zero_random<F: PrimeField, R: Rng>(rng: &mut R) -> F {
    let mut r = F::rand(rng);
    while r.is_zero() {
        r = F::rand(rng);
    }
    r
}