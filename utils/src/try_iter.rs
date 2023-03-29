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

/// Trait allowing to accumulatively validate supplied sequence of items.
pub trait SeqValidator<I> {
    /// Validation failure.
    type Failure;

    /// Validates an item.
    fn validate(&mut self, item: &I) -> Option<Self::Failure>;
}

impl<I: Clone, F, ValidateF> SeqValidator<I> for ValidateF
where
    ValidateF: FnMut(&I) -> Option<F>,
{
    type Failure = F;

    fn validate(&mut self, item: &I) -> Option<Self::Failure> {
        (self)(item)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current left items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckLeft<F>(pub F);

impl<First: Clone, Second, F, ValidateF> SeqValidator<(First, Second)> for CheckLeft<ValidateF>
where
    ValidateF: FnMut(&First) -> Option<F>,
{
    type Failure = F;

    fn validate(&mut self, (first, _): &(First, Second)) -> Option<Self::Failure> {
        self.0(first)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current right items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckRight<F>(pub F);

impl<First, Second: Clone, F, ValidateF> SeqValidator<(First, Second)> for CheckRight<ValidateF>
where
    ValidateF: FnMut(&Second) -> Option<F>,
{
    type Failure = F;

    fn validate(&mut self, (_, second): &(First, Second)) -> Option<Self::Failure> {
        self.0(second)
    }
}

macro_rules! impl_validator {
    (@ $self: ident $item: ident) => { None };
    (@ $self: ident $item: ident $main: ident = $main_idx: tt $($ty: ident = $idx: tt)*) => {
        if let failure @ Some(_) = $self.$main_idx.validate($item) {
            failure.map(Into::into)
        } else {
            impl_validator!(@ $self $item $($ty = $idx)*)
        }
    };
    ($main: ident = $main_idx: tt $($ty: ident = $idx: tt)+) => {
        impl<I, $main, $($ty),+> SeqValidator<I> for ($main, $($ty),+)
            where
                $main: SeqValidator<I>,
                $($ty: SeqValidator<I>, <$ty>::Failure: Into<<$main>::Failure>),+
        {
            type Failure = <$main>::Failure;

            fn validate(&mut self, item: &I) -> Option<Self::Failure> {
                impl_validator!(@ self item $main = $main_idx $($ty = $idx)+)
            }
        }
    }
}

impl_validator!(A = 0 B = 1);
impl_validator!(A = 0 B = 1 C = 2);
impl_validator!(A = 0 B = 1 C = 2 D = 3);
impl_validator!(A = 0 B = 1 C = 2 D = 3 E = 4);
impl_validator!(A = 0 B = 1 C = 2 D = 3 E = 4 F = 5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidPairOrSingle<I> {
    Pair(InvalidPair<I>),
    Single(I),
}

impl<I> InvalidPairOrSingle<I> {
    /// Applies `sf` to a single item and `pf` to a pair.
    pub fn over<SF, PF, R>(self, mut sf: SF, mut pf: PF) -> R
    where
        SF: FnMut(I) -> R,
        PF: FnMut(InvalidPair<I>) -> R,
    {
        match self {
            Self::Pair(pair) => pf(pair),
            Self::Single(cur) => sf(cur),
        }
    }
}

/// This pair or item was invalid according to the supplied predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidPair<I>(pub I, pub I);

impl<I> From<InvalidPair<I>> for (I, I) {
    fn from(InvalidPair(prev, cur): InvalidPair<I>) -> Self {
        (prev, cur)
    }
}

impl<I> From<(I, I)> for InvalidPair<I> {
    fn from((prev, cur): (I, I)) -> Self {
        InvalidPair(prev, cur)
    }
}

/// Ensures that the given iterator satisfies provided validator for each successful item.
/// In case of an error, `Err(E)` will be emitted.
pub fn try_validate<I, OK, E, P>(iter: I, mut validator: P) -> impl Iterator<Item = Result<OK, E>>
where
    I: IntoIterator<Item = Result<OK, E>>,
    P: SeqValidator<OK>,
    E: From<P::Failure>,
{
    iter.into_iter().map(move |res| {
        let item = res?;

        if let Some(failure) = validator.validate(&item) {
            Err(failure.into())
        } else {
            Ok(item)
        }
    })
}
