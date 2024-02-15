use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{rand::rngs::StdRng, UniformRand};
use blake2::Blake2b512;
use std::{collections::HashSet, hash::Hash};
use vb_accumulator::{
    kb_positive_accumulator::{
        setup::{PublicKey, SecretKey},
        KBPositiveAccumulator,
    },
    kb_universal_accumulator::KBUniversalAccumulator,
    persistence::{InitialElementsStore, State, UniversalAccumulatorState},
    positive::PositiveAccumulator,
    setup::{Keypair, SetupParams},
    universal::UniversalAccumulator,
};

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

pub fn setup_kb_positive_accum(
    rng: &mut StdRng,
) -> (
    vb_accumulator::kb_positive_accumulator::setup::SetupParams<Bls12_381>,
    SecretKey<Fr>,
    PublicKey<Bls12_381>,
    KBPositiveAccumulator<Bls12_381>,
    InMemoryState<Fr>,
) {
    let params = vb_accumulator::kb_positive_accumulator::setup::SetupParams::<Bls12_381>::new::<
        Blake2b512,
    >(b"test");
    let sk = SecretKey::new(rng);
    let pk = PublicKey::new(&sk, &params);
    let accumulator = KBPositiveAccumulator::initialize(rng, &params.accum);
    let state = InMemoryState::new();
    (params, sk, pk, accumulator, state)
}

pub fn setup_kb_universal_accum(
    rng: &mut StdRng,
    size: usize,
) -> (
    SetupParams<Bls12_381>,
    Keypair<Bls12_381>,
    KBUniversalAccumulator<Bls12_381>,
    Vec<Fr>,
    InMemoryState<Fr>,
    InMemoryState<Fr>,
) {
    let domain = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
    let (p, kp, a, ms, nms) = setup_kb_universal_accum_given_domain(rng, domain.clone());
    (p, kp, a, domain, ms, nms)
}

pub fn setup_kb_universal_accum_given_domain(
    rng: &mut StdRng,
    domain: Vec<Fr>,
) -> (
    SetupParams<Bls12_381>,
    Keypair<Bls12_381>,
    KBUniversalAccumulator<Bls12_381>,
    InMemoryState<Fr>,
    InMemoryState<Fr>,
) {
    let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
    let keypair = Keypair::<Bls12_381>::generate_using_rng(rng, &params);
    let mem_state = InMemoryState::new();
    let mut non_mem_state = InMemoryState::new();
    let accumulator = KBUniversalAccumulator::initialize(
        &params,
        &keypair.secret_key,
        domain,
        &mut non_mem_state,
    )
    .unwrap();
    (params, keypair, accumulator, mem_state, non_mem_state)
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
