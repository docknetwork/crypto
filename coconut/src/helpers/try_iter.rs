use core::convert::identity;

use itertools::Itertools;

/// Provided index is out of bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexIsOutOfBounds {
    pub index: usize,
    pub length: usize,
}

/// Maps supplied iterator and attempts to pair each `Ok(_)` item with an item from the slice which has provided index.
/// Returns `Err` containing an invalid index in case slice length is exceeded.
pub fn try_pair_with_slice<'iter, 'pairs, I, OK, E, P>(
    iter: I,
    pairs: &'pairs [P],
) -> impl Iterator<Item = Result<(&'pairs P, OK), E>> + 'iter
where
    'pairs: 'iter,
    OK: 'iter,
    I: IntoIterator<Item = Result<(usize, OK), E>> + 'iter,
    E: From<IndexIsOutOfBounds>,
{
    iter.into_iter()
        .map_ok(|(index, item)| {
            pairs.get(index).map(|pair| (pair, item)).ok_or_else(|| {
                IndexIsOutOfBounds {
                    index,
                    length: pairs.len(),
                }
                .into()
            })
        })
        .map(|res| res.and_then(identity))
}

/// This pair was invalid according to the supplied predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPair<I>(pub I, pub I);

impl<I> InvalidPair<I> {
    /// Transforms the given pair to another pair.
    pub fn map<F: FnMut(I) -> R, R>(self, mut f: F) -> InvalidPair<R> {
        InvalidPair(f(self.0), f(self.1))
    }
}

impl<I> From<InvalidPair<I>> for (I, I) {
    fn from(InvalidPair(first, second): InvalidPair<I>) -> Self {
        (first, second)
    }
}

/// Ensures that the given iterator satisfies provided function for each successful (`Ok(_)`) previous - current pair.
/// In case of an error, `Err(InvalidPair)` will be emitted.
pub fn try_validate_pairs<I, OK, E, F>(iter: I, mut f: F) -> impl Iterator<Item = Result<OK, E>>
where
    OK: Clone,
    I: IntoIterator<Item = Result<OK, E>>,
    F: FnMut(&OK, &OK) -> bool,
    E: From<InvalidPair<OK>>,
{
    iter.into_iter().scan(None, move |prev, cur| match cur {
        err @ Err(_) => Some(err),
        Ok(cur) => {
            let item = if let Some(failure) = prev.take().filter(|prev| !f(prev, &cur)) {
                Err(InvalidPair(failure, cur.clone()).into())
            } else {
                Ok(cur.clone())
            };
            prev.replace(cur);

            Some(item)
        }
    })
}
