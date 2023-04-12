use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::*;

/// `CanonicalDeserialize + CanonicalSerialize`
pub trait CanonicalSerDe: CanonicalDeserialize + CanonicalSerialize {}
impl<T: CanonicalDeserialize + CanonicalSerialize> CanonicalSerDe for T {}

/// `ExactSizeIterator + DoubleEndedIterator`
pub trait DoubleEndedExactSizeIterator: ExactSizeIterator + DoubleEndedIterator {}
impl<I, T: ExactSizeIterator<Item = I> + DoubleEndedIterator<Item = I>> DoubleEndedExactSizeIterator
    for T
{
}

/// Marks a type that implements `DynDigest + Default + Clone`.
pub trait FullDigest: DynDigest + Default + Clone {}
impl<T: DynDigest + Default + Clone> FullDigest for T {}

/// `Send` if the `parallel` feature enabled
#[cfg(feature = "parallel")]
pub trait SendIfParallel: Send {}
#[cfg(feature = "parallel")]
impl<T: Send> SendIfParallel for T {}

/// `Send` if the `parallel` feature enabled
#[cfg(not(feature = "parallel"))]
pub trait SendIfParallel {}
#[cfg(not(feature = "parallel"))]
impl<T> SendIfParallel for T {}

/// `Sync` if the `parallel` feature enabled
#[cfg(feature = "parallel")]
pub trait SyncIfParallel: Sync {}
#[cfg(feature = "parallel")]
impl<T: Sync> SyncIfParallel for T {}

/// `Sync` if the `parallel` feature enabled
#[cfg(not(feature = "parallel"))]
pub trait SyncIfParallel {}
#[cfg(not(feature = "parallel"))]
impl<T> SyncIfParallel for T {}

#[cfg(feature = "parallel")]
pub use rayon::iter;

#[cfg(not(feature = "parallel"))]
pub use core::iter;
