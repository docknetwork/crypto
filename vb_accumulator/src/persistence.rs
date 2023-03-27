//! Interfaces for persistent storage of accumulators

use ark_std::iter::Iterator;

/// Database interface implemented for the universal accumulator and holds the accumulator members created during setup.
/// These members are never added or removed from the accumulator. Only the accumulator manager needs to keep this.
/// A production implementation of this could be persistent key-value store like LevelDb or Rocksdb.
pub trait InitialElementsStore<T> {
    /// Add element
    fn add(&mut self, element: T);

    /// Check if element is present
    fn has(&self, element: &T) -> bool;
}

/// Database interface implemented for the accumulators to store elements present in the accumulator. As elements
/// are added or removed from the accumulator, this database is updated.
pub trait State<T> {
    /// Add element
    fn add(&mut self, element: T);

    /// Remove element
    fn remove(&mut self, element: &T);

    /// Check if element is present
    fn has(&self, element: &T) -> bool;

    /// Number of elements currently present
    fn size(&self) -> u64;
}

/// Database interface implemented for universal accumulator for calculating non-membership witness. This
/// interface expects the database to be able to return all elements present.
pub trait UniversalAccumulatorState<'a, T: 'a>: State<T> {
    type ElementIterator: Iterator<Item = &'a T>;

    /// Return an iterator over all elements present.
    fn elements(&'a self) -> Self::ElementIterator;
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::{collections::HashSet, hash::Hash};

    // In-memory stores for testing.

    #[derive(Clone, Debug)]
    pub struct InMemoryInitialElements<T: Clone> {
        pub db: HashSet<T>,
    }

    impl<T: Clone> InMemoryInitialElements<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Hash + Eq> InitialElementsStore<T> for InMemoryInitialElements<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InMemoryState<T: Clone> {
        pub db: HashSet<T>,
    }

    impl<T: Clone> InMemoryState<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Hash + Eq + Sized> State<T> for InMemoryState<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn remove(&mut self, element: &T) {
            self.db.remove(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }

        fn size(&self) -> u64 {
            self.db.len() as u64
        }
    }

    impl<'a, T: Clone + Hash + Eq + Sized + 'a> UniversalAccumulatorState<'a, T> for InMemoryState<T> {
        type ElementIterator = std::collections::hash_set::Iter<'a, T>;

        fn elements(&'a self) -> Self::ElementIterator {
            self.db.iter()
        }
    }
}
