use alloc::vec::Vec;

use crate::pairs;

use crate::pairs::Pairs;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::PrimeField;

use core::iter::Zip;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Combines two vectors together if they have equal length.
/// Allows to iterate over the given pairs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnedPairs<Left, Right> {
    left: Vec<Left>,
    right: Vec<Right>,
}

impl<Left, Right> Default for OwnedPairs<Left, Right> {
    fn default() -> Self {
        Self {
            left: Vec::new(),
            right: Vec::new(),
        }
    }
}

#[allow(dead_code)]
impl<Left, Right> OwnedPairs<Left, Right> {
    /// Instantiates new `OwnedPairs` built from supplied `left` and `right` `Vec`s.
    pub fn new(left: Vec<Left>, right: Vec<Right>) -> Option<Self> {
        (left.len() == right.len()).then_some(Self { right, left })
    }

    /// Splits into two vectors with equal length.
    pub fn split(self) -> (Vec<Left>, Vec<Right>) {
        (self.left, self.right)
    }

    /// Borrows `OwnedPairs` as `Pairs.`
    pub fn as_ref(&self) -> Pairs<Left, Right> {
        pairs!(&self.left, &self.right)
    }

    /// Returns underlying length.
    pub fn len(&self) -> usize {
        self.left.len()
    }

    /// Returns `true` if length equals to zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over zipped pairs.
    pub fn iter(&self) -> Zip<alloc::slice::Iter<'_, Left>, alloc::slice::Iter<'_, Right>> {
        self.left.iter().zip(self.right.iter())
    }

    /// Returns a parallel iterator over zipped pairs.
    #[cfg(feature = "parallel")]
    pub fn par_iter(
        &self,
    ) -> rayon::iter::Zip<rayon::slice::Iter<'_, Left>, rayon::slice::Iter<'_, Right>>
    where
        Left: Sync,
        Right: Sync,
    {
        use rayon::prelude::*;

        self.left.par_iter().zip(self.right.par_iter())
    }
}

impl<Left, Right> TryFrom<(Vec<Left>, Vec<Right>)> for OwnedPairs<Left, Right> {
    type Error = (usize, usize);

    fn try_from((left, right): (Vec<Left>, Vec<Right>)) -> Result<Self, Self::Error> {
        let left_len = left.len();
        let right_len = right.len();

        Self::new(left, right).ok_or((left_len, right_len))
    }
}

/// Extension for `OwnedPairs` for cases when left is an `AffineRepr` implementer, and right is a `ScalarField` implementer.
impl<G: AffineRepr> OwnedPairs<G, G::ScalarField> {
    /// `G::Group::msm_unchecked(left, right)`
    pub fn msm(&self) -> G::Group {
        G::Group::msm_unchecked(&self.left, &self.right)
    }
}

/// Extension for `OwnedPairs` for cases when left is an `AffineRepr` implementer, and right is a `ScalarField::BigInt` implementer.
impl<G: AffineRepr> OwnedPairs<G, <G::ScalarField as PrimeField>::BigInt> {
    /// `G::Group::msm_bigint(left, right)`
    pub fn msm_bigint(&self) -> G::Group {
        G::Group::msm_bigint(&self.left, &self.right)
    }
}

impl<Left, Right> FromIterator<(Left, Right)> for OwnedPairs<Left, Right> {
    fn from_iter<T: IntoIterator<Item = (Left, Right)>>(iter: T) -> Self {
        let (left, right) = iter.into_iter().unzip();

        Self::new(left, right).unwrap()
    }
}

impl<Left: Clone, Right: Clone, const SIZE: usize> From<([Left; SIZE], [Right; SIZE])>
    for OwnedPairs<Left, Right>
{
    fn from((left, right): ([Left; SIZE], [Right; SIZE])) -> Self {
        Self::new(left.to_vec(), right.to_vec()).unwrap()
    }
}

impl<Left, Right> Extend<(Left, Right)> for OwnedPairs<Left, Right> {
    fn extend<T: IntoIterator<Item = (Left, Right)>>(&mut self, iter: T) {
        let (mut left, mut right) = iter.into_iter().unzip();

        self.left.append(&mut left);
        self.right.append(&mut right);
    }
}

#[cfg(feature = "parallel")]
impl<Left: Send, Right: Send> ParallelExtend<(Left, Right)> for OwnedPairs<Left, Right> {
    fn par_extend<I>(&mut self, par_iter: I)
    where
        I: IntoParallelIterator<Item = (Left, Right)>,
    {
        let (mut left, mut right) = par_iter.into_par_iter().unzip();

        self.left.append(&mut left);
        self.right.append(&mut right);
    }
}

#[cfg(feature = "parallel")]
impl<Left: Send, Right: Send> FromParallelIterator<(Left, Right)> for OwnedPairs<Left, Right> {
    fn from_par_iter<I>(par_iter: I) -> Self
    where
        I: IntoParallelIterator<Item = (Left, Right)>,
    {
        let (left, right) = par_iter.into_par_iter().unzip();

        Self::new(left, right).unwrap()
    }
}

impl<Left, Right> IntoIterator for OwnedPairs<Left, Right> {
    type IntoIter = Zip<alloc::vec::IntoIter<Left>, alloc::vec::IntoIter<Right>>;
    type Item = (Left, Right);

    fn into_iter(self) -> Self::IntoIter {
        self.left.into_iter().zip(self.right)
    }
}

#[cfg(feature = "parallel")]
impl<Left, Right> rayon::prelude::IntoParallelIterator for OwnedPairs<Left, Right>
where
    Left: Send,
    Right: Send,
{
    type Iter = rayon::iter::Zip<rayon::vec::IntoIter<Left>, rayon::vec::IntoIter<Right>>;
    type Item = (Left, Right);

    fn into_par_iter(self) -> Self::Iter {
        use rayon::prelude::*;

        ark_std::cfg_into_iter!(self.left).zip(self.right)
    }
}
