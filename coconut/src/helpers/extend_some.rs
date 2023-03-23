#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Extends only `Some(_)` produced by an iterator and drops all `None`s.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExtendSome<C>(pub C);

impl<C: Default> Default for ExtendSome<C> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<C: IntoIterator> IntoIterator for ExtendSome<C> {
    type Item = C::Item;
    type IntoIter = C::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, C: Extend<T>> Extend<Option<T>> for ExtendSome<C> {
    fn extend<I: IntoIterator<Item = Option<T>>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().flatten());
    }
}

impl<T, C: Default + FromIterator<T>> FromIterator<Option<T>> for ExtendSome<C> {
    fn from_iter<I: IntoIterator<Item = Option<T>>>(iter: I) -> Self {
        Self(C::from_iter(iter.into_iter().flatten()))
    }
}

#[cfg(feature = "parallel")]
impl<T: Send, C: Default + FromParallelIterator<T> + Send> FromParallelIterator<Option<T>>
    for ExtendSome<C>
{
    fn from_par_iter<I>(par_iter: I) -> Self
    where
        I: IntoParallelIterator<Item = Option<T>>,
    {
        Self(C::from_par_iter(par_iter.into_par_iter().flatten()))
    }
}

#[cfg(feature = "parallel")]
impl<T: Send, C: Default + ParallelExtend<T> + Send> ParallelExtend<Option<T>> for ExtendSome<C> {
    fn par_extend<I>(&mut self, par_iter: I)
    where
        I: IntoParallelIterator<Item = Option<T>>,
    {
        self.0.par_extend(par_iter.into_par_iter().flatten());
    }
}
