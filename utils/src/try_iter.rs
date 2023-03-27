use serde::{Deserialize, Serialize};

/// Provided index is out of bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexIsOutOfBounds {
    pub index: usize,
    pub length: usize,
}

/// Maps supplied iterator and attempts to pair each `Ok(_)` item with an item from the slice which has provided index.
/// Returns `Err` containing an invalid index in case slice length is exceeded.
pub fn try_pair_with_slice<'iter, 'pairs, I, OK, E, P>(
    iter: I,
    pair_with: &'pairs [P],
) -> impl Iterator<Item = Result<(&'pairs P, OK), E>> + 'iter
where
    'pairs: 'iter,
    OK: 'iter,
    I: IntoIterator<Item = Result<(usize, OK), E>> + 'iter,
    E: From<IndexIsOutOfBounds>,
{
    iter.into_iter().map(|indexed_item| {
        let (index, item) = indexed_item?;

        let pair = pair_with.get(index).ok_or_else(|| IndexIsOutOfBounds {
            index,
            length: pair_with.len(),
        })?;

        Ok((pair, item))
    })
}

/// This pair was invalid according to the supplied predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Trait allowing to validate supplied pair.
/// Prior to validation, each item must be mapped using `PairValidator::map`.
pub trait PairValidator<I> {
    /// Item to be used in validation.
    type ValidationItem;

    /// Maps an item to prepare it for validation.
    fn map(&self, item: &I) -> Self::ValidationItem;

    /// Validates given pair.
    fn validate(&mut self, previous: &Self::ValidationItem, current: &Self::ValidationItem)
        -> bool;
}

impl<I, M, MapF, ValidateF> PairValidator<I> for (MapF, ValidateF)
where
    MapF: Fn(&I) -> M,
    ValidateF: FnMut(&M, &M) -> bool,
{
    type ValidationItem = M;

    fn map(&self, item: &I) -> M {
        self.0(item)
    }

    fn validate(&mut self, previous: &M, current: &M) -> bool {
        self.1(previous, current)
    }
}

impl<I: Clone, ValidateF> PairValidator<I> for ValidateF
where
    ValidateF: FnMut(&I, &I) -> bool,
{
    type ValidationItem = I;

    fn map(&self, item: &I) -> I {
        item.clone()
    }

    fn validate(&mut self, previous: &I, current: &I) -> bool {
        (self)(previous, current)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current left items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckLeft<F>(pub F);

impl<First: Clone, Second, ValidateF> PairValidator<(First, Second)> for CheckLeft<ValidateF>
where
    ValidateF: FnMut(&First, &First) -> bool,
{
    type ValidationItem = First;

    fn map(&self, item: &(First, Second)) -> First {
        item.0.clone()
    }

    fn validate(&mut self, previous: &First, current: &First) -> bool {
        self.0(previous, current)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current right items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckRight<F>(pub F);

impl<First, Second: Clone, ValidateF> PairValidator<(First, Second)> for CheckRight<ValidateF>
where
    ValidateF: FnMut(&Second, &Second) -> bool,
{
    type ValidationItem = Second;

    fn map(&self, item: &(First, Second)) -> Second {
        item.1.clone()
    }

    fn validate(&mut self, previous: &Second, current: &Second) -> bool {
        self.0(previous, current)
    }
}

/// Ensures that the given iterator satisfies provided function for each successful (`Ok(_)`) previous - current pair.
/// In case of an error, `Err(InvalidPair)` will be emitted.
pub fn try_validate_pairs<I, OK, E, P>(
    iter: I,
    mut validator: P,
) -> impl Iterator<Item = Result<OK, E>>
where
    I: IntoIterator<Item = Result<OK, E>>,
    P: PairValidator<OK>,
    E: From<InvalidPair<P::ValidationItem>>,
{
    let mut last = None;

    iter.into_iter().map(move |item| {
        let cur = item?;

        let invalid = last
            .replace(validator.map(&cur))
            .zip(last.as_ref())
            .map(|(prev, cur)| (prev, cur))
            .filter(|(prev, cur)| !validator.validate(prev, cur));

        if let Some((prev, _)) = invalid {
            Err(InvalidPair(prev, validator.map(&cur)).into())
        } else {
            Ok(cur)
        }
    })
}
