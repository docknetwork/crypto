use core::ops::Range;

use crate::{
    aliases::{DoubleEndedExactSizeIterator, SendIfParallel},
    concat_slices,
    hashing_utils::projective_group_elem_from_try_and_incr,
    impl_indexed_iter,
    msm::multiply_field_elems_with_same_group_elem,
    try_iter::{InvalidPair, InvalidPairOrSingle},
};
use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{cfg_into_iter, rand::RngCore, UniformRand};

use digest::Digest;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
pub fn seq_inc_by_n_from<N>(
    n: N,
    mut from: N,
) -> impl FnMut(&N) -> Option<InvalidPairOrSingle<N>> + Clone
where
    N: num::CheckedAdd + Eq + Copy,
{
    let mut init = false;

    move |&item: &N| {
        if init {
            let next = from.checked_add(&n);
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
pub fn n_rand<'a, T: UniformRand, R: RngCore, N: From<u8> + 'a>(
    rng: &'a mut R,
    count: N,
) -> impl DoubleEndedExactSizeIterator<Item = T> + 'a
where
    Range<N>: DoubleEndedExactSizeIterator,
{
    (0.into()..count).map(move |_| rand(rng))
}

/// Produces an iterator emitting `n` items `u32::to_le_bytes` of the counter starting from zero.
pub fn le_bytes_iter(n: u32) -> impl_indexed_iter!(<Item = [u8; 4]>) {
    cfg_into_iter!(0..n).map(u32::to_le_bytes)
}

/// Produces an iterator of little endian bytes of each element contained in the range `counter_range`
pub fn le_bytes_iter_from_given_range(
    counter_range: Range<u32>,
) -> impl_indexed_iter!(<Item = [u8; 4]>) {
    cfg_into_iter!(counter_range).map(u32::to_le_bytes)
}

/// Produces an iterator of projective group elements created by hashing a label and a counter in the range `counter_range`
pub fn n_projective_group_elements<'iter, G, D>(
    counter_range: Range<u32>,
    bytes: &'iter [u8],
) -> impl_indexed_iter!(<Item = G::Group> + 'iter)
where
    G: AffineRepr + SendIfParallel,
    D: Digest,
{
    le_bytes_iter_from_given_range(counter_range).map(move |ctr_bytes| -> G::Group {
        projective_group_elem_from_try_and_incr::<G, D>(&concat_slices!(bytes.as_ref(), ctr_bytes))
    })
}

/// Produces an iterator affine group elements created by hashing a label and a counter in the range `counter_range`
pub fn n_affine_group_elements<'iter, G, D>(
    n: Range<u32>,
    bytes: &'iter [u8],
) -> impl_indexed_iter!(<Item = G> + 'iter)
where
    G: AffineRepr + SendIfParallel,
    D: Digest,
{
    n_projective_group_elements::<G, D>(n, bytes).map(CurveGroup::into_affine)
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
