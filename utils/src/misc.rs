use crate::{
    aliases::DoubleEndedExactSizeIterator,
    msm::multiply_field_elems_with_same_group_elem,
    try_iter::{InvalidPair, InvalidPairOrSingle},
};
use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::RngCore, UniformRand};

/// Ensures that each sequence pair satisfy provided predicate.
pub fn seq_pairs_satisfy<I, F>(mut validate: F) -> impl FnMut(&I) -> Option<InvalidPair<I>>
where
    I: Clone,
    F: FnMut(&I, &I) -> bool,
{
    let mut last = None;

    move |item: &I| -> Option<InvalidPair<I>> {
        if let Some((prev, _)) = last
            .replace(item.clone())
            .zip(last.as_ref())
            .filter(|(prev, cur)| !validate(prev, cur))
        {
            Some(InvalidPair(prev, item.clone()))
        } else {
            None
        }
    }
}

/// Produces a function which will check for each item to be equal previous plus `n` starting from the supplied value.
pub fn seq_inc_by_n_from(
    n: usize,
    mut from: usize,
) -> impl FnMut(&usize) -> Option<InvalidPairOrSingle<usize>> + Clone {
    let mut init = false;

    move |&item: &usize| {
        if init {
            let next = from.checked_add(n);
            let res =
                (next != Some(item)).then_some(InvalidPairOrSingle::Pair(InvalidPair(from, item)));
            from = item;

            res
        } else {
            init = true;

            (from != item).then_some(InvalidPairOrSingle::Single(item))
        }
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
