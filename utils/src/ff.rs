use ark_ff::PrimeField;
use ark_std::{rand::Rng, vec, vec::Vec};

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

/// Powers of a finite field as `[1, s, s^2, .. s^{num-1}]`
pub fn powers<F: PrimeField>(s: &F, num: usize) -> Vec<F> {
    let mut powers = vec![F::one()];
    for i in 1..num {
        powers.push(powers[i - 1] * s);
    }
    powers
}

/// SUM of a geometric progression
/// SUM a^i = (1 - a^n) / (1 - a) = -(1-a^n)/-(1-a)
/// = (a^n - 1) / (a - 1)
pub fn sum_of_powers<F: PrimeField>(r: &F, num: usize) -> F {
    (r.pow([num as u64]) - &F::one()) * (*r - F::one()).inverse().unwrap()
}
