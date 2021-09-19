#![allow(non_snake_case)]

//! Universal accumulator that support single as well as batched additions, removals and generating
//! membership and non-membership witness for single or a multiple elements at once. Described in section 2
//! of the paper
//! # Examples
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//! use vb_accumulator::positive::Accumulator;
//! use vb_accumulator::universal::UniversalAccumulator;
//! use vb_accumulator::persistence::{State, InitialElementsStore};
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//! // Maximum number of members accumulator should have
//! let max_size = 100;
//!
//!  // `initial_elements` should be a persistent db implementing the trait `InitialElementsStore`
//! let accumulator = UniversalAccumulator::initialize(&mut rng,
//!             &params,
//!             max_size,
//!             &keypair.secret_key,
//!             &mut initial_elements);
//!
//! // Addition, removal, creating and verifying membership witness updates has same API as `PositiveAccumulator`
//!
//! // Create non-membership witness
//! // non_member should be absent in the accumulator
//! let nm_wit = accumulator
//!                 .get_non_membership_witness(&non_member, &keypair.secret_key, &state, &params)
//!                 .unwrap();
//! // Verify non-membership witness
//! accumulator.verify_non_membership(
//!                 &elem,
//!                 &nm_wit,
//!                 &keypair.public_key,
//!                 &params
//!             );
//!
//! // Similar to positive accumulator, additions, removals or both can be done in a batch using `add_batch`,
//! // `remove_batch`, etc.
//!
//! // Similar to positive accumulator, non-membership witnesses can be calculated in a batch as
//! let mem_witnesses = accumulator
//!             .get_membership_witness_for_batch(&non_members, &keypair.secret_key, &state)
//!             .unwrap();
//! ```

use crate::error::VBAccumulatorError;
use crate::persistence::{InitialElementsStore, State, UniversalAccumulatorState};
use crate::positive::Accumulator;
use crate::setup::{PublicKey, SecretKey, SetupParams};
use crate::utils::multiply_field_elems_with_same_group_elem;
use crate::witness::NonMembershipWitness;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::fields::Field;
use ark_ff::{batch_inversion, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    iter::Iterator,
    rand::RngCore,
    vec,
    vec::Vec,
    One, UniformRand, Zero,
};

use dock_crypto_utils::serde_utils::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Accumulator supporting both membership and non-membership proofs. Is capped at a size defined
/// at setup to avoid non-membership witness forgery attack described in section 6 of the paper
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct UniversalAccumulator<E: PairingEngine> {
    /// This is the accumulated value. It is considered a digest of state of the accumulator.
    #[serde_as(as = "AffineGroupBytes")]
    pub V: E::G1Affine,
    /// This is f_V(alpha) and is the discrete log of `V` wrt. P from setup parameters. Accumulator
    /// manager persists it for efficient computation of non-membership witnesses
    #[serde_as(as = "ScalarFieldBytes")]
    pub f_V: E::Fr,
    /// The maximum elements the accumulator can store
    pub max_size: u64,
}

impl<E> Accumulator<E> for UniversalAccumulator<E>
where
    E: PairingEngine,
{
    fn value(&self) -> &E::G1Affine {
        &self.V
    }
}

impl<E> UniversalAccumulator<E>
where
    E: PairingEngine,
{
    pub fn initialize<R: RngCore>(
        rng: &mut R,
        setup_params: &SetupParams<E>,
        max_size: u64,
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &mut dyn InitialElementsStore<E::Fr>,
    ) -> Self {
        let mut f_V = E::Fr::one();
        for _ in 0..max_size + 1 {
            // Each of the random values should be preserved by the manager and should not be removed (check before removing)
            // from the accumulator
            // TODO: Make it same as the paper
            let elem = E::Fr::rand(rng);
            f_V = f_V * (elem + sk.0);
            initial_elements_store.add(elem);
        }

        let V = setup_params.P.mul(f_V.into_repr());

        Self {
            V: V.into_affine(),
            f_V,
            max_size,
        }
    }

    /// Maximum elements the accumulator should hold
    fn max_size(&self) -> u64 {
        self.max_size
    }

    // TODO: What is an attacker figures out a way to keep on querying the accumulator manager for acceptable elements.
    // Like submitting add or remove requests and keeping track of when errors were returned or requesting witness for elements.
    // In practice this would be a cost to an attacker but still something to be aware of.
    /// Check if element is part of the initial elements. Such elements should not be added or removed from the accumulator
    pub fn is_element_acceptable(
        &self,
        element: &E::Fr,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
    ) -> bool {
        !initial_elements_store.has(element)
    }

    /// Update the accumulated values with the given ones
    pub fn get_updated(&self, V: E::G1Affine, f_V: E::Fr) -> Self {
        Self {
            V,
            f_V,
            max_size: self.max_size,
        }
    }

    /// Add an element to the accumulator and state. Described in section 2 of the paper
    pub fn add(
        &self,
        element: E::Fr,
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() == state.size() {
            return Err(VBAccumulatorError::AccumulatorFull);
        }
        if !self.is_element_acceptable(&element, initial_elements_store) {
            return Err(VBAccumulatorError::ProhibitedElement);
        }

        // TODO: Check if its more efficient to always have a window table of setup parameter `P` and
        // multiply `P` by `f_V` rather than multiplying `y_plus_alpha` by `V`. Use `windowed_mul` from FixedBase
        let (y_plus_alpha, V) = self._add(element, sk, state)?;
        let f_V = y_plus_alpha * self.f_V;
        Ok(self.get_updated(V, f_V))
    }

    /// Add a batch of members in the accumulator
    pub fn add_batch(
        &self,
        elements: Vec<E::Fr>,
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() < (state.size() + elements.len() as u64) {
            return Err(VBAccumulatorError::BatchExceedsAccumulatorCapacity);
        }
        for element in elements.iter() {
            if !self.is_element_acceptable(&element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }
        let (d_alpha, V) = self._add_batch(elements, sk, state)?;
        let f_V = d_alpha * self.f_V;
        Ok(self.get_updated(V, f_V))
    }

    /// Remove an element from the accumulator and state. Described in section 2 of the paper
    pub fn remove(
        &self,
        element: &E::Fr,
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        if !self.is_element_acceptable(&element, initial_elements_store) {
            return Err(VBAccumulatorError::ProhibitedElement);
        }

        // TODO: Check if its more efficient to always have a window table of setup parameter `P` and
        // multiply `P` by `f_V` rather than multiplying `y_plus_alpha_inv` by `V`. Use `windowed_mul` from FixedBase
        let (y_plus_alpha_inv, V) = self._remove(element, sk, state)?;
        let f_V = y_plus_alpha_inv * self.f_V;
        Ok(self.get_updated(V, f_V))
    }

    /// Removing a batch of members from the accumulator
    pub fn remove_batch(
        &self,
        elements: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in elements.iter() {
            if !self.is_element_acceptable(&element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }
        let (d_alpha_inv, V) = self._remove_batch(elements, sk, state)?;
        let f_V = d_alpha_inv * self.f_V;
        Ok(self.get_updated(V, f_V))
    }

    /// Adding and removing batches of elements from the accumulator
    pub fn batch_updates(
        &self,
        additions: Vec<E::Fr>,
        removals: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        initial_elements_store: &dyn InitialElementsStore<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() < (state.size() + additions.len() as u64 - removals.len() as u64) {
            return Err(VBAccumulatorError::BatchExceedsAccumulatorCapacity);
        }
        for element in additions.iter().chain(removals) {
            if !self.is_element_acceptable(&element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }

        let (d_alpha, V) = self._batch_updates(additions, removals, sk, state)?;
        let f_V = d_alpha * self.f_V;
        Ok(self.get_updated(V, f_V))
    }

    /// Get non-membership witness for an element absent in accumulator. Described in section 2 of the paper
    pub fn get_non_membership_witness<'a>(
        &self,
        element: &E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &'a dyn UniversalAccumulatorState<
            'a,
            E::Fr,
            ElementIterator = impl Iterator<Item = &'a E::Fr>,
        >,
        params: &SetupParams<E>,
    ) -> Result<NonMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        if state.has(element) {
            return Err(VBAccumulatorError::ElementPresent);
        }

        // f_V(alpha) is part of the current accumulator
        // d = f_V(-y).
        // This is expensive as a product involving all accumulated elements is needed. This can use parallelization.
        // But rayon will not work with wasm, look at https://github.com/GoogleChromeLabs/wasm-bindgen-rayon.
        let mut d = E::Fr::one();
        for i in state.elements() {
            d *= *i - element;
        }
        if d.is_zero() {
            panic!("d shouldn't have been 0 as the check in state should have ensured that element is not present in the accumulator.")
        }

        let y_plus_alpha_inv = (*element + sk.0).inverse().unwrap();
        let mut C = params.P.into_projective();
        C *= (self.f_V - d) * y_plus_alpha_inv;
        Ok(NonMembershipWitness {
            d,
            C: C.into_affine(),
        })
    }

    /// Get non-membership witnesses for multiple elements absent in accumulator. Returns witnesses in the
    /// order of passed elements. It is more efficient than computing multiple witnesses independently as
    /// it uses windowed multiplication and batch invert. Will throw error even if one element is not present
    pub fn get_non_membership_witness_for_batch<'a>(
        &self,
        elements: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &'a dyn UniversalAccumulatorState<
            'a,
            E::Fr,
            ElementIterator = impl Iterator<Item = &'a E::Fr>,
        >,
        params: &SetupParams<E>,
    ) -> Result<Vec<NonMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        for element in elements {
            if state.has(element) {
                return Err(VBAccumulatorError::ElementPresent);
            }
        }

        // For all non-members `elements` and existing `members` in state, need products
        // `(elements_0 - member_0)*(elements_0 - member_1)*..(elements_0 - member_{n-1})*`
        // `(elements_1 - member_0)*(elements_1 - member_1)*..(elements_1 - member_{n-1})*`
        // ...
        // `(elements_{m-1} - member_0)*(elements_{m-1} - member_1)*..(elements_{m-1} - member_{n-1})*`

        // `d_for_witnesses` stores `d` corresponding to each of `elements`
        let mut d_for_witnesses = vec![E::Fr::one(); elements.len()];
        // Since iterating state is expensive, compute iterate over it once
        for member in state.elements() {
            for (i, t) in into_iter!(elements)
                .map(|e| *member - *e)
                .collect::<Vec<_>>()
                .into_iter()
                .enumerate()
            {
                d_for_witnesses[i] *= t;
            }
        }

        let f_V_alpha_minus_d: Vec<E::Fr> = iter!(d_for_witnesses).map(|d| self.f_V - *d).collect();

        let mut y_plus_alpha_inv: Vec<E::Fr> = iter!(elements).map(|y| *y + sk.0).collect();
        batch_inversion(&mut y_plus_alpha_inv);

        let P_multiple = f_V_alpha_minus_d
            .iter()
            .zip(y_plus_alpha_inv.iter())
            .map(|(numr, denom)| *numr * *denom);

        // The same group element (self.V) has to multiplied by each element in P_multiple so creating a window table
        let wits = multiply_field_elems_with_same_group_elem(
            4,
            params.P.into_projective(),
            P_multiple.into_iter(),
        );
        let wits_affine = E::G1Projective::batch_normalization_into_affine(&wits);
        Ok(into_iter!(wits_affine)
            .zip(into_iter!(d_for_witnesses))
            .map(|(C, d)| NonMembershipWitness { C, d })
            .collect())
    }

    /// Check if element is absent in accumulator. Described in section 2 of the paper
    pub fn verify_non_membership(
        &self,
        element: &E::Fr,
        witness: &NonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E::G2Affine>,
        params: &SetupParams<E>,
    ) -> bool {
        if witness.d.is_zero() {
            return false;
        }
        // witness.d != 0 and e(witness.C, element*P_tilde + Q_tilde) * e(P, P_tilde)^witness.d == e(self.V, P_tilde)
        // => e(witness.C, element*P_tilde + Q_tilde) * e(P, P_tilde)^witness.d * e(self.V, P_tilde)^-1 == 1
        // => e(witness.C, element*P_tilde + Q_tilde) * e(witness.d*P, P_tilde) * e(-self.V, P_tilde) == 1

        // element * P_tilde
        let mut P_tilde_times_y = params.P_tilde.into_projective();
        P_tilde_times_y *= *element;

        // witness.d * P
        let mut P_times_d = params.P.into_projective();
        P_times_d *= witness.d;

        // e(witness.C, element*P_tilde + Q_tilde) * e(witness.d*P - self.V, P_tilde) == 1
        E::product_of_pairings(&[
            (
                E::G1Prepared::from(witness.C),
                E::G2Prepared::from((P_tilde_times_y + pk.0.into_projective()).into_affine()),
            ),
            (
                E::G1Prepared::from((P_times_d - self.value().into_projective()).into_affine()),
                E::G2Prepared::from(params.P_tilde),
            ),
        ])
        .is_one()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::persistence::test::*;
    use crate::setup::Keypair;
    use crate::test_serialization;

    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::time::{Duration, Instant};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    /// Setup a universal accumulator, its keys, params and state for testing.
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
        let accumulator = UniversalAccumulator::initialize(
            rng,
            &params,
            max,
            &keypair.secret_key,
            &mut initial_elements,
        );
        let state = InMemoryState::new();
        (params, keypair, accumulator, initial_elements, state)
    }

    #[test]
    fn membership_non_membership() {
        // Test to check (non)membership in accumulator
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, initial_elements, mut state) =
            setup_universal_accum(&mut rng, max);

        test_serialization!(UniversalAccumulator<Bls12_381>, accumulator);

        let mut total_mem_check_time = Duration::default();
        let mut total_non_mem_check_time = Duration::default();
        let count = max;
        let mut elems = vec![];
        for _ in 0..count {
            let prohibited_element = initial_elements.db.iter().cloned().next().unwrap();
            assert!(!state.has(&prohibited_element));
            assert!(accumulator
                .add(
                    prohibited_element,
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state
                )
                .is_err());
            assert!(!state.has(&prohibited_element));

            let elem = Fr::rand(&mut rng);
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err());

            let mut start = Instant::now();
            let nm_wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            assert!(accumulator.verify_non_membership(
                &elem,
                &nm_wit,
                &keypair.public_key,
                &params
            ));
            total_non_mem_check_time += start.elapsed();

            test_serialization!(
                NonMembershipWitness<<Bls12_381 as PairingEngine>::G1Affine>,
                nm_wit
            );

            assert!(accumulator
                .remove(&elem, &keypair.secret_key, &initial_elements, &mut state)
                .is_err());

            assert!(!state.has(&elem));
            accumulator = accumulator
                .add(
                    elem.clone(),
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state,
                )
                .unwrap();
            assert!(state.has(&elem));

            assert!(accumulator
                .add(elem, &keypair.secret_key, &initial_elements, &mut state)
                .is_err());

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let mut expected_V = m_wit.0.into_projective();
            expected_V *= elem + keypair.secret_key.0;
            assert_eq!(expected_V, accumulator.V);

            start = Instant::now();
            assert!(accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params));
            total_mem_check_time += start.elapsed();
            elems.push(elem);
        }

        let elem = Fr::rand(&mut rng);
        assert!(accumulator
            .add(elem, &keypair.secret_key, &initial_elements, &mut state)
            .is_err());

        for elem in elems {
            assert!(state.has(&elem));
            accumulator = accumulator
                .remove(&elem, &keypair.secret_key, &initial_elements, &mut state)
                .unwrap();
            assert!(!state.has(&elem));
            let nm_wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            assert!(accumulator.verify_non_membership(
                &elem,
                &nm_wit,
                &keypair.public_key,
                &params
            ));
        }

        println!(
            "Total time to verify {} individual memberships {:?}",
            count, total_mem_check_time
        );
        println!(
            "Total time to verify {} individual non-memberships {:?}",
            count, total_non_mem_check_time
        );
    }

    #[test]
    fn batch_update_and_membership() {
        // Tests batch updates and batch membership witness generation
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator_1, initial_elements, mut state_1) =
            setup_universal_accum(&mut rng, max);

        // Create more accumulators to compare. Same elements will be added and removed from them as accumulator_1
        let mut accumulator_2: UniversalAccumulator<Bls12_381> = accumulator_1.clone();
        let mut state_2 = InMemoryState::<Fr>::new();

        let mut accumulator_3: UniversalAccumulator<Bls12_381> = accumulator_1.clone();
        let mut state_3 = InMemoryState::<Fr>::new();

        let additions: Vec<Fr> = (0..10).into_iter().map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions[i].clone())
            .collect();

        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i].clone();
            accumulator_1 = accumulator_1
                .add(
                    elem.clone(),
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state_1,
                )
                .unwrap();
        }

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());
        // Add as a batch
        accumulator_2 = accumulator_2
            .add_batch(
                additions.clone(),
                &keypair.secret_key,
                &initial_elements,
                &mut state_2,
            )
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove(
                    &removals[i],
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state_1,
                )
                .unwrap();
        }

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());
        // Remove as a batch
        accumulator_2 = accumulator_2
            .remove_batch(
                &removals,
                &keypair.secret_key,
                &initial_elements,
                &mut state_2,
            )
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions.clone();
        for e in removals.iter() {
            accumulator_3 = accumulator_3
                .add(
                    e.clone(),
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state_3,
                )
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove as a batch
        accumulator_3 = accumulator_3
            .batch_updates(
                new_additions.clone(),
                &removals,
                &keypair.secret_key,
                &initial_elements,
                &mut state_3,
            )
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_3.value());
        assert_eq!(*accumulator_2.value(), *accumulator_3.value());
        assert_eq!(state_1.db, state_3.db);
        assert_eq!(state_2.db, state_3.db);

        let mem_witnesses = accumulator_3
            .get_membership_witness_for_batch(&new_additions, &keypair.secret_key, &state_3)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(accumulator_3.verify_membership(
                &new_additions[i],
                &mem_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        let start = Instant::now();
        let npn_mem_witnesses = accumulator_3
            .get_non_membership_witness_for_batch(&removals, &keypair.secret_key, &state_3, &params)
            .unwrap();
        println!("Non-membership witnesses in accumulator of size {} using secret key for batch of size {} takes: {:?}", state_3.db.len(), removals.len(), start.elapsed());
        for i in 0..removals.len() {
            assert!(accumulator_3.verify_non_membership(
                &removals[i],
                &npn_mem_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
    }
}
