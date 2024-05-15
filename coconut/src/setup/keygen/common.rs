use core::{iter::once, ops::RangeInclusive};

use alloc::vec::Vec;

use ark_ff::PrimeField;
use ark_serialize::*;
use itertools::Itertools;
use secret_sharing_and_dkg::common::Share;

use crate::setup::SecretKey;

/// Numbers relation `threshold` / `total` where `threshold` <= `total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Threshold(
    /// `threshold`
    pub(super) u16,
    /// `total`
    pub(super) u16,
);

impl IntoIterator for Threshold {
    type Item = u16;
    type IntoIter = RangeInclusive<u16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0..=self.1
    }
}

impl Threshold {
    /// Constructs new `Threshold` if supplied `threshold` is less or equal to `total`.
    pub fn new(threshold: u16, total: u16) -> Option<Self> {
        (threshold <= total).then_some(Self(threshold, total))
    }
}

/// Contains some entities in the same structure as `SecretKey`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct SecretKeyModel<X> {
    pub(crate) x: X,
    pub(crate) y: Vec<X>,
}

impl<F: PrimeField> From<&'_ SecretKey<F>> for SecretKeyModel<F> {
    fn from(sk: &'_ SecretKey<F>) -> Self {
        SecretKeyModel {
            x: sk.x,
            y: sk.y.clone(),
        }
    }
}

impl<C, X> Extend<SecretKeyModel<X>> for SecretKeyModel<C>
where
    C: Extend<X> + Default,
{
    fn extend<I: IntoIterator<Item = SecretKeyModel<X>>>(&mut self, iter: I) {
        for item in iter {
            self.x.extend(once(item.x));
            self.y
                .iter_mut()
                .zip_eq(item.y)
                .for_each(|(this, item)| this.extend(once(item)));
        }
    }
}

impl<C, X> FromIterator<SecretKeyModel<X>> for SecretKeyModel<C>
where
    C: Extend<X> + Default,
    Vec<C>: Extend<Vec<X>>,
{
    fn from_iter<I: IntoIterator<Item = SecretKeyModel<X>>>(iter: I) -> Self {
        let mut peekable = iter.into_iter().peekable();
        let mut this = Self {
            x: Default::default(),
            y: peekable
                .peek()
                .map(|item| (0..item.y.len()).map(|_| Default::default()).collect())
                .unwrap_or_default(),
        };
        this.extend(peekable);

        this
    }
}

impl<F: PrimeField> From<SecretKeyModel<Share<F>>> for SecretKey<F> {
    fn from(mut key: SecretKeyModel<Share<F>>) -> Self {
        key.map_ref_mut(|share| core::mem::take(&mut share.share))
            .into()
    }
}

impl<F: PrimeField> From<SecretKeyModel<F>> for SecretKey<F> {
    fn from(SecretKeyModel { mut x, y }: SecretKeyModel<F>) -> Self {
        let sk = SecretKey { x, y };
        x.zeroize();

        sk
    }
}

#[allow(dead_code)]
impl<X> SecretKeyModel<X> {
    /// Attempts to apply given `f` to the mutable reference of each contained entity producing a new `SecretKeyModel`.
    pub(crate) fn try_map_ref_mut<F, R, E>(&mut self, mut map: F) -> Result<SecretKeyModel<R>, E>
    where
        F: FnMut(&mut X) -> Result<R, E>,
    {
        let Self { x, y } = self;

        Ok(SecretKeyModel {
            x: map(x)?,
            y: y.iter_mut().map(map).try_collect()?,
        })
    }

    /// Applies given `f` to the mutable reference of each contained entity producing a new `SecretKeyModel`.
    pub(crate) fn map_ref_mut<F, R>(&mut self, mut f: F) -> SecretKeyModel<R>
    where
        F: FnMut(&mut X) -> R,
    {
        let Self { x, y } = self;

        SecretKeyModel {
            x: f(x),
            y: y.iter_mut().map(f).collect(),
        }
    }

    /// Applies given `f` to each contained entity producing a new `SecretKeyModel`.
    pub(crate) fn map<F, R>(self, mut f: F) -> SecretKeyModel<R>
    where
        F: FnMut(X) -> R,
    {
        let Self { x, y } = self;

        SecretKeyModel {
            x: f(x),
            y: y.into_iter().map(f).collect(),
        }
    }
}
