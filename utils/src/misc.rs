use crate::{
    aliases::DoubleEndedExactSizeIterator, msm::multiply_field_elems_with_same_group_elem,
};
use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::RngCore, UniformRand};
use core::cmp::Ord;

/// Returns `true` if `first` is less than `second`.
pub fn is_lt<I: Ord>(first: &I, second: &I) -> bool {
    first.cmp(second).is_lt()
}

/// Produces a function which will check for each pair current to be previous plus 1 starting from the supplied value.
pub fn check_seq_from(mut from: usize) -> impl FnMut(&usize, &usize) -> bool {
    move |&prev, &cur| {
        let valid = from == prev && prev + 1 == cur;
        from = cur;

        valid
    }
}

/// Generates an iterator of randoms producing `count` elements using the supplied `rng`.
pub fn n_rand<T: UniformRand, R: RngCore>(
    rng: &'_ mut R,
    count: usize,
) -> impl DoubleEndedExactSizeIterator<Item = T> + '_ {
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
