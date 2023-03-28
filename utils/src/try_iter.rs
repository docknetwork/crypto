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

        let pair = pair_with.get(index).ok_or(IndexIsOutOfBounds {
            index,
            length: pair_with.len(),
        })?;

        Ok((pair, item))
    })
}

/// This pair or item was invalid according to the supplied predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidPairOrItem<I>(pub PairOrSingle<I>);

/// Describes either pair (two items) or a single item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairOrSingle<I> {
    Single(I),
    Pair(I, I),
}

impl<I> PairOrSingle<I> {
    /// Applies the given function to either the last item of a pair or a single item.
    pub fn over_cur<F, R>(self, mut f: F) -> R
    where
        F: FnMut(I) -> R,
    {
        match self {
            Self::Pair(_, cur) => f(cur),
            Self::Single(cur) => f(cur),
        }
    }

    /// Applies `sf` to a single item and `pf` to a pair.
    pub fn over<SF, PF, R>(self, mut sf: SF, mut pf: PF) -> R
    where
        SF: FnMut(I) -> R,
        PF: FnMut(I, I) -> R,
    {
        match self {
            Self::Pair(prev, cur) => pf(prev, cur),
            Self::Single(cur) => sf(cur),
        }
    }

    /// Applies the supplied function to a pair, returns `None` in case of a single item.
    pub fn over_pair<F, R>(self, mut f: F) -> Option<R>
    where
        F: FnMut(I, I) -> R,
    {
        match self {
            Self::Pair(prev, cur) => Some(f(prev, cur)),
            Self::Single(_) => None,
        }
    }

    /// Applies the supplied function to a single item, returns `None` in case of a pair.
    pub fn over_single<F, R>(self, mut f: F) -> Option<R>
    where
        F: FnMut(I) -> R,
    {
        match self {
            Self::Pair(_, _) => None,
            Self::Single(cur) => Some(f(cur)),
        }
    }

    /// Unwraps pair, panics in case of single item.
    pub fn unwrap_pair(self) -> (I, I) {
        match self {
            Self::Pair(prev, cur) => (prev, cur),
            Self::Single(_) => panic!("called `PairOrSingle::unwrap_pair()` on a `None` value"),
        }
    }
}

impl<I> From<(Option<I>, I)> for PairOrSingle<I> {
    fn from((prev, cur): (Option<I>, I)) -> Self {
        match prev {
            Some(prev) => Self::Pair(prev, cur),
            None => Self::Single(cur),
        }
    }
}

impl<I> From<(I, I)> for PairOrSingle<I> {
    fn from((prev, cur): (I, I)) -> Self {
        Self::Pair(prev, cur)
    }
}

impl<I> From<I> for PairOrSingle<I> {
    fn from(single: I) -> Self {
        Self::Single(single)
    }
}

impl<I> From<InvalidPairOrItem<I>> for PairOrSingle<I> {
    fn from(InvalidPairOrItem(pair_or_single): InvalidPairOrItem<I>) -> Self {
        pair_or_single
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
    fn validate(&mut self, pair: PairOrSingle<&Self::ValidationItem>) -> bool;
}

impl<I, M, MapF, ValidateF> PairValidator<I> for (MapF, ValidateF)
where
    MapF: Fn(&I) -> M,
    ValidateF: FnMut(PairOrSingle<&M>) -> bool,
{
    type ValidationItem = M;

    fn map(&self, item: &I) -> M {
        self.0(item)
    }

    fn validate(&mut self, pair: PairOrSingle<&Self::ValidationItem>) -> bool {
        self.1(pair)
    }
}

impl<I: Clone, ValidateF> PairValidator<I> for ValidateF
where
    ValidateF: FnMut(PairOrSingle<&I>) -> bool,
{
    type ValidationItem = I;

    fn map(&self, item: &I) -> I {
        item.clone()
    }

    fn validate(&mut self, pair: PairOrSingle<&Self::ValidationItem>) -> bool {
        (self)(pair)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current left items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckLeft<F>(pub F);

impl<First: Clone, Second, ValidateF> PairValidator<(First, Second)> for CheckLeft<ValidateF>
where
    ValidateF: FnMut(PairOrSingle<&First>) -> bool,
{
    type ValidationItem = First;

    fn map(&self, item: &(First, Second)) -> First {
        item.0.clone()
    }

    fn validate(&mut self, pair: PairOrSingle<&Self::ValidationItem>) -> bool {
        self.0(pair)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current right items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckRight<F>(pub F);

impl<First, Second: Clone, ValidateF> PairValidator<(First, Second)> for CheckRight<ValidateF>
where
    ValidateF: FnMut(PairOrSingle<&Second>) -> bool,
{
    type ValidationItem = Second;

    fn map(&self, item: &(First, Second)) -> Second {
        item.1.clone()
    }

    fn validate(&mut self, pair: PairOrSingle<&Self::ValidationItem>) -> bool {
        self.0(pair)
    }
}

/// Ensures that the given iterator satisfies provided function for each successful (`Ok(_)`) previous - current pair.
/// In case of an error, `Err(InvalidPairOrItem)` will be emitted.
pub fn try_validate<I, OK, E, P>(iter: I, mut validator: P) -> impl Iterator<Item = Result<OK, E>>
where
    I: IntoIterator<Item = Result<OK, E>>,
    P: PairValidator<OK>,
    E: From<InvalidPairOrItem<P::ValidationItem>>,
{
    let mut last = None;

    iter.into_iter().map(move |item| {
        let cur = item?;
        let prev = last.replace(validator.map(&cur));

        let pair = ((prev.as_ref(), last.as_ref().unwrap())).into();

        if !validator.validate(pair) {
            Err(InvalidPairOrItem((prev, validator.map(&cur)).into()).into())
        } else {
            Ok(cur)
        }
    })
}
