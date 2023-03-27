use itertools::{EitherOrBoth, Itertools};

use super::try_iter::{
    try_pair_with_slice, try_validate_pairs, IndexIsOutOfBounds, InvalidPair, PairValidator,
};

/// Plucks items from the supplied iterator corresponding to missed indices.
/// This function implies that both iterators are sorted.
pub fn pluck_missed<Indices, Iter>(indices: Indices, iter: Iter) -> impl Iterator<Item = Iter::Item>
where
    Indices: IntoIterator<Item = usize>,
    Iter: IntoIterator,
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
    pair_with: &'pairs [P],
) -> impl Iterator<Item = Result<(&'pairs P, Item), IndexIsOutOfBounds>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: 'iter,
{
    try_pair_with_slice(iter.into_iter().map(Ok), pair_with)
}

/// Maps supplied iterator and attempts to pair each successfully validated item with a corresponding item from the slice.
/// Validation errors will be propagated without looking at them.
/// In case of error, `Err(IndexIsOutOfBounds)` will be emitted.
pub fn pair_valid_pairs_with_slice<'iter, 'pairs, I, Item, Pair, E, P>(
    iter: I,
    validator: P,
    pair_with: &'pairs [Pair],
) -> impl Iterator<Item = Result<(&'pairs Pair, Item), E>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: 'iter,
    P: PairValidator<(usize, Item)> + 'iter,
    E: From<IndexIsOutOfBounds> + From<InvalidPair<P::MappedItem>> + 'iter,
{
    try_pair_with_slice(
        try_validate_pairs(iter.into_iter().map(Ok), validator),
        pair_with,
    )
}

/// Ensures that the given iterator satisfies provided function for each previous - current pair.
/// The supplied option will be modified to invalid pair in case of failure, and iteration will be aborted.
pub fn take_while_pairs_satisfy<'iter, 'invalid, I, P>(
    iter: I,
    validator: P,
    invalid_pair: &'invalid mut Option<(P::MappedItem, P::MappedItem)>,
) -> impl Iterator<Item = I::Item> + 'iter
where
    'invalid: 'iter,
    I: IntoIterator + 'iter,
    P: PairValidator<I::Item> + 'iter,
{
    try_validate_pairs(iter.into_iter().map(Ok), validator)
        .map(|res| {
            res.map_err(InvalidPair::into)
                .map_err(|invalid| invalid_pair.replace(invalid))
                .ok()
        })
        .take_while(Option::is_some)
        .flatten()
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
