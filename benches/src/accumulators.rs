use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::rand::rngs::StdRng;
use std::collections::HashSet;
use std::hash::Hash;
use vb_accumulator::persistence::UniversalAccumulatorState;
use vb_accumulator::{
    persistence::{InitialElementsStore, State},
    positive::PositiveAccumulator,
    setup::{Keypair, SetupParams},
    universal::UniversalAccumulator,
};

type Fr = <Bls12_381 as PairingEngine>::Fr;

// NOTE: THIS IS TEST CODE COPIED FROM ACCUMULATOR CRATE FOR BENCHMARKING

pub fn setup_positive_accum(
    rng: &mut StdRng,
) -> (
    SetupParams<Bls12_381>,
    Keypair<Bls12_381>,
    PositiveAccumulator<Bls12_381>,
    InMemoryState<Fr>,
) {
    let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
    let keypair = Keypair::<Bls12_381>::generate_using_rng(rng, &params);

    let accumulator = PositiveAccumulator::initialize(&params);
    let state = InMemoryState::new();
    (params, keypair, accumulator, state)
}

pub fn setup_universal_accum(
    rng: &mut StdRng,
    max: u64,
) -> (
    SetupParams<Bls12_381>,
    Keypair<Bls12_381>,
    UniversalAccumulator<Bls12_381>,
    InMemoryInitialElements<Fr>,
    InMemoryState<Fr>,
) {
    let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
    let keypair = Keypair::<Bls12_381>::generate_using_rng(rng, &params);

    let mut initial_elements = InMemoryInitialElements::new();
    let accumulator = UniversalAccumulator::initialize_with_all_random(
        rng,
        &params,
        max,
        &keypair.secret_key,
        &mut initial_elements,
    );
    let state = InMemoryState::new();
    (params, keypair, accumulator, initial_elements, state)
}

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
