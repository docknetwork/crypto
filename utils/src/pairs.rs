use ark_ec::AffineRepr;

use ark_ec::VariableBaseMSM;
use ark_ff::PrimeField;
use core::{iter::Zip, slice::Iter};

/// Combines two slices together if they have equal length.
/// Allows to iterate over the given pairs.
#[derive(Debug, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Pairs<'left, 'right, Left, Right> {
    left: &'left [Left],
    right: &'right [Right],
}

impl<'left, 'right, Left, Right> Clone for Pairs<'left, 'right, Left, Right> {
    fn clone(&self) -> Self {
        let &Self { left, right } = self;

        Self { left, right }
    }
}

impl<'left, 'right, Left, Right> Pairs<'left, 'right, Left, Right> {
    /// Combines two slices together if they have equal length.
    pub fn new(left: &'left [Left], right: &'right [Right]) -> Option<Self> {
        Self::build_if_equal(left, right)
    }

    /// Combines two slices if left has length equal or greater to right.
    /// Truncates the left slice if needed so that they will have equal length.
    pub fn new_truncate_left(left: &'left [Left], right: &'right [Right]) -> Option<Self> {
        (left.len() >= right.len()).then(|| Self::new_truncate_to_min(left, right))
    }

    /// Combines two slices if right has length equal or greater to left.
    /// Truncates the right slice if needed so that they will have equal length.
    pub fn new_truncate_right(left: &'left [Left], right: &'right [Right]) -> Option<Self> {
        (right.len() >= left.len()).then(|| Self::new_truncate_to_min(left, right))
    }

    /// Truncates either left or right slice to ensure they have the same length (minimum).
    pub fn new_truncate_to_min(left: &'left [Left], right: &'right [Right]) -> Self {
        let min = left.len().min(right.len());

        Self {
            left: &left[..min],
            right: &right[..min],
        }
    }

    /// Applies offset to the left slice, and then combines two slices together if they have equal length.
    pub fn new_with_left_offset(
        left: &'left [Left],
        left_offset: usize,
        right: &'right [Right],
    ) -> Option<Self> {
        let left_with_offset = left.get(left_offset..)?;

        Self::build_if_equal(left_with_offset, right)
    }

    /// Applies offset to the right slice, and then combines two slices together if they have equal length.
    pub fn new_with_right_offset(
        left: &'left [Left],
        right: &'right [Right],
        right_offset: usize,
    ) -> Option<Self> {
        let right_with_offset = right.get(right_offset..)?;

        Self::build_if_equal(left, right_with_offset)
    }

    /// Applies offsets to the both slices, and then combines them together if they have equal length.
    pub fn new_with_left_and_right_offset(
        left: &'left [Left],
        left_offset: usize,
        right: &'right [Right],
        right_offset: usize,
    ) -> Option<Self> {
        let left_with_offset = left.get(left_offset..)?;
        let right_with_offset = right.get(right_offset..)?;

        Self::build_if_equal(left_with_offset, right_with_offset)
    }

    /// Returns underlying left elements.
    pub fn left(self) -> &'left [Left] {
        self.left
    }

    /// Returns underlying right elements.
    pub fn right(self) -> &'right [Right] {
        self.right
    }

    /// Splits into two slices with equal length.
    pub fn split(self) -> (&'left [Left], &'right [Right]) {
        (self.left, self.right)
    }

    /// Returns underlying length.
    pub fn len(&self) -> usize {
        self.left.len()
    }

    /// Returns `true` if no pairs exists.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over zipped pairs.
    pub fn iter(&self) -> <Self as IntoIterator>::IntoIter {
        self.left.iter().zip(self.right)
    }

    /// Returns a parallel iterator over zipped pairs.
    #[cfg(feature = "parallel")]
    pub fn par_iter(&self) -> <Self as rayon::prelude::IntoParallelIterator>::Iter
    where
        Left: Sync,
        Right: Sync,
    {
        use rayon::prelude::*;

        self.left.par_iter().zip(self.right.par_iter())
    }

    fn build_if_equal(left: &'left [Left], right: &'right [Right]) -> Option<Self> {
        (left.len() == right.len()).then_some(Self { right, left })
    }
}

impl<'left, 'right, Left, Right> TryFrom<(&'left [Left], &'right [Right])>
    for Pairs<'left, 'right, Left, Right>
{
    type Error = (usize, usize);

    fn try_from((left, right): (&'left [Left], &'right [Right])) -> Result<Self, Self::Error> {
        Self::new(left, right).ok_or((left.len(), right.len()))
    }
}

/// Extension for `Pairs` for cases when left is an `AffineRepr` implementer, and right is a `ScalarField` implementer.
impl<'left, 'right, G: AffineRepr> Pairs<'left, 'right, G, G::ScalarField> {
    /// `G::Group::msm_unchecked(left, right)`
    pub fn msm(self) -> G::Group {
        G::Group::msm_unchecked(self.left, self.right)
    }
}

/// Extension for `OwnedPairs` for cases when left is an `AffineRepr` implementer, and right is a `ScalarField::BigInt` implementer.
impl<G: AffineRepr> Pairs<'_, '_, G, <G::ScalarField as PrimeField>::BigInt> {
    /// `G::Group::msm_bigint(left, right)`
    pub fn msm_bigint(&self) -> G::Group {
        G::Group::msm_bigint(self.left, self.right)
    }
}

impl<'left, 'right, Left, Right> IntoIterator for Pairs<'left, 'right, Left, Right> {
    type IntoIter = Zip<Iter<'left, Left>, Iter<'right, Right>>;
    type Item = (&'left Left, &'right Right);

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(feature = "parallel")]
impl<'left, 'right, Left, Right> rayon::prelude::IntoParallelIterator
    for Pairs<'left, 'right, Left, Right>
where
    Left: Sync,
    Right: Sync,
{
    type Iter =
        rayon::iter::Zip<rayon::slice::Iter<'left, Left>, rayon::slice::Iter<'right, Right>>;
    type Item = (&'left Left, &'right Right);

    fn into_par_iter(self) -> Self::Iter {
        self.par_iter()
    }
}
