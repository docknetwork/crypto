use crate::msm::multiply_field_elems_with_same_group_elem;
use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::RngCore, UniformRand};

/// Generates an iterator of randoms producing `count` elements using the supplied `rng`.
pub fn n_rand<T: UniformRand, R: RngCore>(
    rng: &'_ mut R,
    count: usize,
) -> impl Iterator<Item = T> + '_ {
    (0..count).map(move |_| rand(rng))
}

/// Generates a random using given `rng`.
pub fn rand<T: UniformRand, R: RngCore>(rng: &mut R) -> T {
    UniformRand::rand(rng)
}

/// Produces points by multiplying supplied base by the provided scalars.
pub fn points<G: AffineRepr>(base: &G, scalars: &[G::ScalarField]) -> Vec<G> {
    let group = base.into_group();
    let products = multiply_field_elems_with_same_group_elem(group, scalars);

    G::Group::normalize_batch(&products)
}
