use itertools::{EitherOrBoth, Itertools};

use super::try_iter::{try_pair_with_slice, try_validate_pairs, IndexIsOutOfBounds, InvalidPair};

/// Plucks items from the supplied iterator corresponding to missed indices.
/// This function implies that both iterators are sorted.
pub fn pluck_missed<Indices, I>(indices: Indices, iter: I) -> impl Iterator<Item = I::Item>
where
    Indices: IntoIterator<Item = usize>,
    I: IntoIterator,
{
    iter.into_iter()
        .enumerate()
        .merge_join_by(indices, |(i, _), j| i.cmp(j))
        .filter_map(|either| match either {
            EitherOrBoth::Left((_, item)) => Some(item),
            _ => None,
        })
}

/// Maps supplied iterator and attempts to pair each item with an item from the slice which has provided index.
/// Returns `Err` containing an invalid index in case slice length is exceeded.
pub fn pair_with_slice<'iter, 'pairs, I, Item, P>(
    iter: I,
    pairs: &'pairs [P],
) -> impl Iterator<Item = Result<(&'pairs P, Item), IndexIsOutOfBounds>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: 'iter,
{
    try_pair_with_slice(iter.into_iter().map(Ok), pairs)
}

/// Maps supplied iterator and attempts to pair each successfully validated item with a corresponding item from the slice.
/// Validation errors will be propagated without looking at them.
/// In case of error, `Err(IndexIsOutOfBounds)` will be emitted.
pub fn pair_valid_pairs_with_slice<'iter, 'pairs, I, Item, Pair, E, F>(
    iter: I,
    f: F,
    pairs: &'pairs [Pair],
) -> impl Iterator<Item = Result<(&'pairs Pair, Item), E>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: Clone + 'iter,
    E: From<IndexIsOutOfBounds> + From<InvalidPair<I::Item>> + 'iter,
    F: FnMut(&I::Item, &I::Item) -> bool + 'iter,
{
    try_pair_with_slice(try_validate_pairs(iter.into_iter().map(Ok), f), pairs)
}

/// Ensures that the given iterator satisfies provided function for each previous - current pair.
/// The supplied option will be modified to invalid pair in case of failure, and iteration will be aborted.
pub fn take_while_pairs_satisfy<'iter, 'invalid, I, F>(
    iter: I,
    f: F,
    invalid_pair: &'invalid mut Option<(I::Item, I::Item)>,
) -> impl Iterator<Item = I::Item> + 'iter
where
    'invalid: 'iter,
    I: IntoIterator + 'iter,
    I::Item: Clone,
    F: FnMut(&I::Item, &I::Item) -> bool + 'iter,
{
    try_validate_pairs(iter.into_iter().map(Ok), f).scan((), |(), res| {
        res.map_err(InvalidPair::into)
            .map_err(|invalid| invalid_pair.replace(invalid))
            .ok()
    })
}

/// Ensures that given iterator emits only unique sorted items i.e. for each item `previous < current`.
/// The supplied option will be modified to invalid pair in case of failure, and iteration will be aborted.
pub fn take_while_pairs_unique_sorted<'iter, 'invalid, I>(
    iter: I,
    invalid_pair: &'invalid mut Option<(I::Item, I::Item)>,
) -> impl Iterator<Item = I::Item> + 'iter
where
    'invalid: 'iter,
    I: IntoIterator + 'iter,
    I::Item: Ord + Clone,
{
    take_while_pairs_satisfy(iter, |prev, cur| prev < cur, invalid_pair)
}

/// Skips up to `n` elements from the iterator using supplied random generator.
pub fn skip_up_to_n<'rng, I>(
    rng: &'rng mut impl ark_std::rand::RngCore,
    iter: I,
    mut allowed_to_skip: usize,
) -> impl Iterator<Item = I::Item> + 'rng
where
    I: IntoIterator + 'rng,
{
    iter.into_iter().filter(move |_| {
        use ark_std::rand::Rng;

        let res = allowed_to_skip == 0 || rng.gen_bool(0.5);
        if !res {
            allowed_to_skip -= 1;
        }

        res
    })
}
