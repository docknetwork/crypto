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
//! // Get accumulated value (as group element in G1)
//! let accumulated = accumulator.value();
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
//! // Or create a new new accumulator for verification and verify
//! let verification_accumulator = UniversalAccumulator::from_accumulated(accumulator.value().clone());
//! verification_accumulator.verify_non_membership(&elem, &nm_wit, &keypair.public_key, &params);
//!
//! // Similar to positive accumulator, additions, removals or both can be done in a batch using `add_batch`,
//! // `remove_batch`, etc.
//!
//! // Similar to membership witnesses for batch in positive accumulator, non-membership witnesses can be calculated in a batch as
//! let mem_witnesses = accumulator
//!             .get_non_membership_witnesses_for_batch(&non_members, &keypair.secret_key, &state)
//!             .unwrap();
//!
//! // Above methods to update accumulator and generate witness require access to `State`. In cases when its
//! // not possible to provide access to `State`, use methods starting with `compute_` to compute the required
//! // value.
//!
//!
//! ```

use crate::{
    error::VBAccumulatorError,
    persistence::{InitialElementsStore, State, UniversalAccumulatorState},
    positive::Accumulator,
    setup::{PublicKey, SecretKey, SetupParams},
    witness::NonMembershipWitness,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{batch_inversion, fields::Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, fmt::Debug, iter::Iterator, rand::RngCore, vec,
    vec::Vec, One, UniformRand, Zero,
};
use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

use dock_crypto_utils::serde_utils::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zeroize::Zeroize;

/// Accumulator supporting both membership and non-membership proofs. Is capped at a size defined
/// at setup to avoid non-membership witness forgery attack described in section 6 of the paper.
/// For more docs, check [`Accumulator`]
///
/// [`Accumulator`]: crate::positive::Accumulator
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct UniversalAccumulator<E: Pairing> {
    /// This is the accumulated value. It is considered a digest of state of the accumulator.
    #[serde_as(as = "ArkObjectBytes")]
    pub V: E::G1Affine,
    /// This is f_V(alpha) and is the discrete log of `V` wrt. P from setup parameters. Accumulator
    /// manager persists it for efficient computation of non-membership witnesses
    #[serde_as(as = "ArkObjectBytes")]
    pub f_V: E::ScalarField,
    /// The maximum elements the accumulator can store
    pub max_size: u64,
}

impl<E: Pairing> AsRef<E::G1Affine> for UniversalAccumulator<E> {
    fn as_ref(&self) -> &E::G1Affine {
        self.value()
    }
}

impl<E: Pairing> Accumulator<E> for UniversalAccumulator<E> {
    fn value(&self) -> &E::G1Affine {
        &self.V
    }

    /// Create an `UniversalAccumulator` using the accumulated value. This is used for (non)membership verification
    /// purposes only
    fn from_accumulated(accumulated: E::G1Affine) -> Self {
        Self {
            f_V: E::ScalarField::zero(),
            V: accumulated,
            max_size: 0,
        }
    }
}

impl<E: Pairing> UniversalAccumulator<E> {
    /// Create a new universal accumulator. Given the max size, it generates `max_size-n+1` initial elements
    /// as mentioned in the paper. `n` elements are passed as argument `xs`. These are generated
    /// once for each curve as they depend on the order of the scalar field and then reused.
    /// Constants for some of the curves are defined in `universal_init_constants.rs` and are computed
    /// using sage code in `universal_init.sage`. Those should be passed as argument `xs`. The rest of
    /// the `max_size + 1` are generated randomly.
    pub fn initialize<R: RngCore>(
        rng: &mut R,
        params_gen: impl AsRef<E::G1Affine>,
        max_size: u64,
        sk: &SecretKey<E::ScalarField>,
        xs: Vec<E::ScalarField>,
        initial_elements_store: &mut dyn InitialElementsStore<E::ScalarField>,
    ) -> Self {
        let f_V = Self::compute_initial(rng, max_size, sk, xs, initial_elements_store);

        let V = params_gen
            .as_ref()
            .mul_bigint(f_V.into_bigint())
            .into_affine();

        Self { V, f_V, max_size }
    }

    /// Create a new universal accumulator. Given the max size, it generates `max_size+1` initial elements
    /// *randomly* and adds them to the accumulator; these initial elements can never be removed or
    /// added back to the accumulator. Generating all elements *randomly* deviates from the paper and
    /// is present for legacy purposes. This will likely be removed.
    pub fn initialize_with_all_random<R: RngCore>(
        rng: &mut R,
        params_gen: impl AsRef<E::G1Affine>,
        max_size: u64,
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &mut dyn InitialElementsStore<E::ScalarField>,
    ) -> Self {
        let f_V = Self::compute_random_initial(rng, max_size, sk, initial_elements_store);
        let V = params_gen
            .as_ref()
            .mul_bigint(f_V.into_bigint())
            .into_affine();

        Self { V, f_V, max_size }
    }

    /// Create a new universal accumulator but assumes that the initial elements have been already
    /// generated and `f_V = (y_1 + alpha) * (y_2 + alpha) *...*(y_n + alpha)` has been calculated
    /// where `y_i` are the initial elements and `alpha` is the secret key
    pub fn initialize_given_f_V(
        f_V: E::ScalarField,
        params_gen: impl AsRef<E::G1Affine>,
        max_size: u64,
    ) -> Self {
        let V = params_gen
            .as_ref()
            .mul_bigint(f_V.into_bigint())
            .into_affine();
        Self { V, f_V, max_size }
    }

    /// Compute `f_V = (y_1 + alpha) * (y_2 + alpha) *...*(y_n + alpha)` where `y_i` are the initial elements
    /// and `alpha` is the secret key. If `initial_elements` is large enough to be not passed in a single
    /// invocation of this function, several evaluations of this function can be multiplied to get the
    /// final `f_V`
    pub fn compute_initial_f_V(
        initial_elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> E::ScalarField {
        let mut f_V = E::ScalarField::one();
        for elem in initial_elements {
            // Each of the random values should be preserved by the manager and should not be removed (check before removing)
            // from the accumulator
            // TODO: Make it same as the paper
            f_V *= *elem + sk.0;
        }
        f_V
    }

    /// Maximum elements the accumulator should hold
    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    // TODO: What is an attacker figures out a way to keep on querying the accumulator manager for acceptable elements.
    // Like submitting add or remove requests and keeping track of when errors were returned or requesting witness for elements.
    // In practice this would be a cost to an attacker but still something to be aware of.
    /// Check if element is part of the initial elements. Such elements should not be added or removed from the accumulator
    pub fn is_element_acceptable(
        &self,
        element: &E::ScalarField,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
    ) -> bool {
        !initial_elements_store.has(element)
    }

    /// Update the accumulated values with the given ones
    pub fn get_updated(&self, f_V: E::ScalarField, V: E::G1Affine) -> Self {
        Self {
            V,
            f_V,
            max_size: self.max_size,
        }
    }

    /// Compute new accumulated value after addition.
    pub fn compute_new_post_add(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let (y_plus_alpha, V) = self._compute_new_post_add(element, sk);
        let f_V = y_plus_alpha * self.f_V;
        (f_V, V)
    }

    /// Add an element to the accumulator and state. Reads and writes to state. Described in section 2 of the paper
    pub fn add(
        &self,
        element: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() == state.size() {
            return Err(VBAccumulatorError::AccumulatorFull);
        }
        if !self.is_element_acceptable(&element, initial_elements_store) {
            return Err(VBAccumulatorError::ProhibitedElement);
        }

        // TODO: Check if it's more efficient to always have a window table of setup parameter `P` and
        // multiply `P` by `f_V` rather than multiplying `y_plus_alpha` by `V`. Use `windowed_mul` from FixedBase
        let (y_plus_alpha, V) = self._add(element, sk, state)?;
        let f_V = y_plus_alpha * self.f_V;
        Ok(self.get_updated(f_V, V))
    }

    /// Compute new accumulated value after batch addition.
    pub fn compute_new_post_add_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let (mut d_alpha, V) = self._compute_new_post_add_batch(elements, sk);
        let f_V = d_alpha * self.f_V;
        d_alpha.zeroize();
        (f_V, V)
    }

    /// Add a batch of members in the accumulator. Reads and writes to state. Described in section 3 of the paper
    pub fn add_batch(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() < (state.size() + elements.len() as u64) {
            return Err(VBAccumulatorError::BatchExceedsAccumulatorCapacity);
        }
        for element in elements.iter() {
            if !self.is_element_acceptable(element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }
        let (mut d_alpha, V) = self._add_batch(elements, sk, state)?;
        let f_V = d_alpha * self.f_V;
        d_alpha.zeroize();
        Ok(self.get_updated(f_V, V))
    }

    /// Compute new accumulated value after removal
    pub fn compute_new_post_remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let (mut y_plus_alpha_inv, V) = self._compute_new_post_remove(element, sk);
        let f_V = y_plus_alpha_inv * self.f_V;
        y_plus_alpha_inv.zeroize();
        (f_V, V)
    }

    /// Remove an element from the accumulator and state. Reads and writes to state. Described in section 2 of the paper
    pub fn remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        if !self.is_element_acceptable(element, initial_elements_store) {
            return Err(VBAccumulatorError::ProhibitedElement);
        }

        // TODO: Check if its more efficient to always have a window table of setup parameter `P` and
        // multiply `P` by `f_V` rather than multiplying `y_plus_alpha_inv` by `V`. Use `windowed_mul` from FixedBase
        let (mut y_plus_alpha_inv, V) = self._remove(element, sk, state)?;
        let f_V = y_plus_alpha_inv * self.f_V;
        y_plus_alpha_inv.zeroize();
        Ok(self.get_updated(f_V, V))
    }

    /// Compute new accumulated value after batch removal
    pub fn compute_new_post_remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let (mut d_alpha_inv, V) = self._compute_new_post_remove_batch(elements, sk);
        let f_V = d_alpha_inv * self.f_V;
        d_alpha_inv.zeroize();
        (f_V, V)
    }

    /// Removing a batch of members from the accumulator. Reads and writes to state. Described in section 3 of the paper
    pub fn remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in elements.iter() {
            if !self.is_element_acceptable(element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }
        let (mut d_alpha_inv, V) = self._remove_batch(elements, sk, state)?;
        let f_V = d_alpha_inv * self.f_V;
        d_alpha_inv.zeroize();
        Ok(self.get_updated(f_V, V))
    }

    /// Compute new accumulated value after batch additions and removals
    pub fn compute_new_post_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let (mut d_alpha, V) = self._compute_new_post_batch_updates(additions, removals, sk);
        let f_V = d_alpha * self.f_V;
        d_alpha.zeroize();
        (f_V, V)
    }

    /// Adding and removing batches of elements from the accumulator. Reads and writes to state. Described in section 3 of the paper
    pub fn batch_updates(
        &self,
        additions: Vec<E::ScalarField>,
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &dyn InitialElementsStore<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        if self.max_size() < (state.size() + additions.len() as u64 - removals.len() as u64) {
            return Err(VBAccumulatorError::BatchExceedsAccumulatorCapacity);
        }
        for element in additions.iter().chain(removals) {
            if !self.is_element_acceptable(element, initial_elements_store) {
                return Err(VBAccumulatorError::ProhibitedElement);
            }
        }

        let (mut d_alpha, V) = self._batch_updates(additions, removals, sk, state)?;
        let f_V = d_alpha * self.f_V;
        d_alpha.zeroize();
        Ok(self.get_updated(f_V, V))
    }

    /// Compute `d` where `d = f_V(-non_member) = (member_0 - non_member)*(member_1 - non_member)*...(member_n - non_member)`
    /// where each `member_i` is a member of the accumulator (except the elements added during initialization).
    /// In case the accumulator is of a large number of members such that it's not possible to pass all of
    /// them in 1 invocation of this function, they can be partitioned and each partition can be passed
    /// to 1 invocation of this function and later outputs from all invocations are multiplied
    pub fn compute_d_given_members(
        non_member: &E::ScalarField,
        members: &[E::ScalarField],
    ) -> E::ScalarField {
        let mut d = E::ScalarField::one();
        for member in members {
            d *= *member - non_member;
        }
        d
    }

    /// Compute non membership witness given `d` where
    /// `d = f_V(-non_member) = (member_0 - non_member)*(member_1 - non_member)*...(member_n - non_member)`
    /// where each `member_i` is a member of the accumulator (except the elements added during initialization)
    /// Described in section 2 of the paper
    pub fn compute_non_membership_witness_given_d(
        &self,
        d: E::ScalarField,
        non_member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params_gen: impl AsRef<E::G1Affine>,
    ) -> Result<NonMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        if d.is_zero() {
            return Err(VBAccumulatorError::CannotBeZero);
        }
        let mut y_plus_alpha_inv = (*non_member + sk.0).inverse().unwrap();
        let mut C = params_gen.as_ref().into_group();
        C *= (self.f_V - d) * y_plus_alpha_inv;
        y_plus_alpha_inv.zeroize();
        Ok(NonMembershipWitness {
            d,
            C: C.into_affine(),
        })
    }

    /// Get non-membership witness for an element absent from accumulator. Described in section 2 of the paper
    pub fn get_non_membership_witness<'a>(
        &self,
        non_member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &'a dyn UniversalAccumulatorState<
            'a,
            E::ScalarField,
            ElementIterator = impl Iterator<Item = &'a E::ScalarField>,
        >,
        params_gen: impl AsRef<E::G1Affine>,
    ) -> Result<NonMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        if state.has(non_member) {
            return Err(VBAccumulatorError::ElementPresent);
        }

        // f_V(alpha) is part of the current accumulator
        // d = f_V(-y).
        // This is expensive as a product involving all accumulated elements is needed. This can use parallelization.
        // But rayon will not work with wasm, look at https://github.com/GoogleChromeLabs/wasm-bindgen-rayon.
        let mut d = E::ScalarField::one();
        for member in state.elements() {
            d *= *member - non_member;
        }

        self.compute_non_membership_witness_given_d(d, non_member, sk, params_gen)
    }

    /// Compute a vector `d` for a batch where each `non_member_i` in batch has `d` as `d_i` and
    /// `d_i = f_V(-non_member_i) = (member_0 - non_member_i)*(member_1 - non_member_i)*...(member_n - non_member_i)`
    /// where each `member_i` is a member of the accumulator (except the elements added during initialization).
    /// In case the accumulator is of a large number of members such that it's not possible to pass all of
    /// them in 1 invocation of this function, they can be partitioned and each partition can be passed
    /// to 1 invocation of this function and later outputs from all invocations are multiplied
    pub fn compute_d_for_batch_given_members(
        non_members: &[E::ScalarField],
        members: &[E::ScalarField],
    ) -> Vec<E::ScalarField> {
        let mut ds = vec![E::ScalarField::one(); non_members.len()];
        for member in members {
            for (i, t) in cfg_into_iter!(non_members)
                .map(|e| *member - *e)
                .collect::<Vec<_>>()
                .into_iter()
                .enumerate()
            {
                ds[i] *= t;
            }
        }
        ds
    }

    /// Compute non-membership witnesses for a batch {`y_i`} given their `d`s, where `d = f_V(-y_i)`
    /// for each member `y_i`
    pub fn compute_non_membership_witnesses_for_batch_given_d(
        &self,
        d: Vec<E::ScalarField>,
        non_members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        params_gen: impl AsRef<E::G1Affine>,
    ) -> Result<Vec<NonMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        if cfg_iter!(d).any(|&x| x.is_zero()) {
            return Err(VBAccumulatorError::CannotBeZero);
        }
        let f_V_alpha_minus_d: Vec<E::ScalarField> = cfg_iter!(d).map(|d| self.f_V - *d).collect();

        let mut y_plus_alpha_inv: Vec<E::ScalarField> =
            cfg_iter!(non_members).map(|y| *y + sk.0).collect();
        batch_inversion(&mut y_plus_alpha_inv);

        let P_multiple = f_V_alpha_minus_d
            .iter()
            .zip(y_plus_alpha_inv.iter())
            .map(|(numr, denom)| *numr * *denom)
            .collect::<Vec<_>>();

        // The same group element (self.V) has to be multiplied by each element in P_multiple, so we create a window table
        let mut wits = multiply_field_elems_with_same_group_elem(
            params_gen.as_ref().into_group(),
            P_multiple.as_slice(),
        );
        let wits_affine = E::G1::normalize_batch(&wits);
        cfg_iter_mut!(y_plus_alpha_inv).for_each(|y| y.zeroize());
        wits.iter_mut().for_each(|w| w.zeroize());
        cfg_iter_mut!(wits).for_each(|y| y.zeroize());

        Ok(cfg_into_iter!(wits_affine)
            .zip(cfg_into_iter!(d))
            .map(|(C, d)| NonMembershipWitness { C, d })
            .collect())
    }

    /// Get non-membership witnesses for multiple elements absent in accumulator. Returns witnesses in the
    /// order of passed elements. It is more efficient than computing multiple witnesses independently as
    /// it uses windowed multiplication and batch invert. Will throw error even if one element is not present
    pub fn get_non_membership_witnesses_for_batch<'a>(
        &self,
        non_members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &'a dyn UniversalAccumulatorState<
            'a,
            E::ScalarField,
            ElementIterator = impl Iterator<Item = &'a E::ScalarField>,
        >,
        params_gen: impl AsRef<E::G1Affine>,
    ) -> Result<Vec<NonMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        for element in non_members {
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
        let mut d_for_witnesses = vec![E::ScalarField::one(); non_members.len()];
        // Since iterating state is expensive, compute iteration over it once
        for member in state.elements() {
            for (i, t) in cfg_into_iter!(non_members)
                .map(|e| *member - *e)
                .collect::<Vec<_>>()
                .into_iter()
                .enumerate()
            {
                d_for_witnesses[i] *= t;
            }
        }

        self.compute_non_membership_witnesses_for_batch_given_d(
            d_for_witnesses,
            non_members,
            sk,
            params_gen,
        )
    }

    /// Check if element is absent in accumulator. Described in section 2 of the paper
    /// This takes `self` as an argument, but the secret `f_V` isn't used; thus it can be passed as 0.
    pub fn verify_non_membership_given_accumulated(
        V: &E::G1Affine,
        non_member: &E::ScalarField,
        witness: &NonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        if witness.d.is_zero() {
            return false;
        }
        // witness.d != 0 and e(witness.C, element*P_tilde + Q_tilde) * e(P, P_tilde)^witness.d == e(V, P_tilde)
        // => e(witness.C, element*P_tilde + Q_tilde) * e(P, P_tilde)^witness.d * e(V, P_tilde)^-1 == 1
        // => e(witness.C, element*P_tilde + Q_tilde) * e(witness.d*P, P_tilde) * e(-V, P_tilde) == 1

        // element * P_tilde
        let mut P_tilde_times_y_plus_Q_tilde = params.P_tilde.into_group();
        P_tilde_times_y_plus_Q_tilde *= *non_member;
        // element*P_tilde + Q_tilde
        P_tilde_times_y_plus_Q_tilde += pk.0;

        // witness.d * P
        let mut P_times_d_minus_V = params.P.into_group();
        P_times_d_minus_V *= witness.d;
        // witness.d * P - V
        P_times_d_minus_V -= *V;

        // e(witness.C, element*P_tilde + Q_tilde) * e(witness.d*P - V, P_tilde) == 1
        E::multi_pairing(
            [witness.C, P_times_d_minus_V.into_affine()],
            [P_tilde_times_y_plus_Q_tilde.into_affine(), params.P_tilde],
        )
        .is_zero()
    }

    /// Check if element is absent in accumulator. Described in section 2 of the paper
    /// This takes `self` as an argument, but the secret `f_V` isn't used; thus it can be passed as 0.
    pub fn verify_non_membership(
        &self,
        non_member: &E::ScalarField,
        witness: &NonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        Self::verify_non_membership_given_accumulated(self.value(), non_member, witness, pk, params)
    }

    pub fn from_value(f_V: E::ScalarField, V: E::G1Affine, max_size: u64) -> Self {
        Self { f_V, V, max_size }
    }

    fn compute_initial<R: RngCore>(
        rng: &mut R,
        max_size: u64,
        sk: &SecretKey<E::ScalarField>,
        xs: Vec<E::ScalarField>,
        initial_elements_store: &mut dyn InitialElementsStore<E::ScalarField>,
    ) -> E::ScalarField {
        let mut f_V = E::ScalarField::one();
        for x in xs {
            f_V *= x + sk.0;
            initial_elements_store.add(x);
        }

        // We need more secret elements than known elements (in case all witness holders collude). As there can
        // be at most `max_size` witnesses, there must be at least `max_size + 1` initial elements secret.
        // It's assumed that elements in `xs` are public constants and thus `max_size + 1` more random elements are generated.
        // Thus there are `max_size + xs.len() + 1` initial elements in total. However, if `xs` could be assumed
        // secret, then only `max_size - xs.len() + 1` random elements need to be generated.
        // Accepting an argument indicating whether `xs` is public could be another way to solve it
        // but as `xs.len <<< max_size` in practice, didn't feel right to make the function accept
        // one more argument and make caller decide one more thing.
        for _ in 0..(max_size + 1) {
            let elem = E::ScalarField::rand(rng);
            f_V *= elem + sk.0;
            initial_elements_store.add(elem);
        }
        f_V
    }

    fn compute_random_initial<R: RngCore>(
        rng: &mut R,
        max_size: u64,
        sk: &SecretKey<E::ScalarField>,
        initial_elements_store: &mut dyn InitialElementsStore<E::ScalarField>,
    ) -> E::ScalarField {
        let mut f_V = E::ScalarField::one();
        for _ in 0..max_size + 1 {
            // Each of the random values should be preserved by the manager and should not be removed (check before removing)
            // from the accumulator
            let elem = E::ScalarField::rand(rng);
            f_V *= elem + sk.0;
            initial_elements_store.add(elem);
        }
        f_V
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{persistence::test::*, setup::Keypair, test_serialization};

    use ark_bls12_381::Bls12_381;
    use ark_ff::MontFp;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::time::{Duration, Instant};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

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

    #[test]
    fn initialization() {
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, accumulator, initial_elements, _) =
            setup_universal_accum(&mut rng, max);

        let accumulator_1: UniversalAccumulator<Bls12_381> =
            UniversalAccumulator::initialize_given_f_V(accumulator.f_V, &params, max);
        assert_eq!(accumulator, accumulator_1);

        let initial = initial_elements.db.into_iter().collect::<Vec<Fr>>();
        let mut chunks = initial.chunks(30);
        let f_V_1 = UniversalAccumulator::<Bls12_381>::compute_initial_f_V(
            chunks.next().unwrap(),
            &keypair.secret_key,
        );
        let f_V_2 = UniversalAccumulator::<Bls12_381>::compute_initial_f_V(
            chunks.next().unwrap(),
            &keypair.secret_key,
        );
        let f_V_3 = UniversalAccumulator::<Bls12_381>::compute_initial_f_V(
            chunks.next().unwrap(),
            &keypair.secret_key,
        );
        let f_V_4 = UniversalAccumulator::<Bls12_381>::compute_initial_f_V(
            chunks.next().unwrap(),
            &keypair.secret_key,
        );
        assert_eq!(accumulator.f_V, f_V_1 * f_V_2 * f_V_3 * f_V_4);

        let initial: Vec<Fr> = initial_elements_for_bls12_381!(Fr);
        assert_eq!(initial.len(), 12);
        let mut initial_elements_1 = InMemoryInitialElements::new();
        let accumulator_1: UniversalAccumulator<Bls12_381> = UniversalAccumulator::initialize(
            &mut rng,
            &params,
            max,
            &keypair.secret_key,
            initial.clone(),
            &mut initial_elements_1,
        );
        assert_eq!(
            initial_elements_1.db.len(),
            max as usize + initial.len() + 1
        );
        for i in initial {
            assert!(initial_elements_1.db.contains(&i));
            assert!(!accumulator_1.is_element_acceptable(&i, &initial_elements_1));
        }
    }

    #[test]
    fn membership_non_membership() {
        // Test to check membership and non-membership in accumulator
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

            let verification_accum = UniversalAccumulator::from_accumulated(*accumulator.value());
            let mut start = Instant::now();
            let nm_wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            assert!(verification_accum.verify_non_membership(
                &elem,
                &nm_wit,
                &keypair.public_key,
                &params
            ));
            total_non_mem_check_time += start.elapsed();

            test_serialization!(
                NonMembershipWitness<<Bls12_381 as Pairing>::G1Affine>,
                nm_wit
            );

            // Randomizing the witness and accumulator
            let random = Fr::rand(&mut rng);
            let randomized_accum = accumulator.randomized_value(&random);
            let randomized_wit = nm_wit.randomize(&random);
            let verification_accum = UniversalAccumulator::from_accumulated(randomized_accum);
            assert!(verification_accum.verify_non_membership(
                &elem,
                &randomized_wit,
                &keypair.public_key,
                &params
            ));

            assert!(accumulator
                .remove(&elem, &keypair.secret_key, &initial_elements, &mut state)
                .is_err());

            assert!(!state.has(&elem));
            let computed_new = accumulator.compute_new_post_add(&elem, &keypair.secret_key);
            accumulator = accumulator
                .add(elem, &keypair.secret_key, &initial_elements, &mut state)
                .unwrap();
            assert_eq!(computed_new, (accumulator.f_V, accumulator.V));
            assert!(state.has(&elem));

            assert!(accumulator
                .add(elem, &keypair.secret_key, &initial_elements, &mut state)
                .is_err());

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let mut expected_V = m_wit.0.into_group();
            expected_V *= elem + keypair.secret_key.0;
            assert_eq!(expected_V, accumulator.V);

            assert_eq!(
                accumulator.compute_membership_witness(&elem, &keypair.secret_key),
                m_wit
            );

            let verification_accum = UniversalAccumulator::from_accumulated(*accumulator.value());
            start = Instant::now();
            assert!(verification_accum.verify_membership(
                &elem,
                &m_wit,
                &keypair.public_key,
                &params
            ));
            total_mem_check_time += start.elapsed();
            elems.push(elem);
        }

        let elem = Fr::rand(&mut rng);
        assert!(accumulator
            .add(elem, &keypair.secret_key, &initial_elements, &mut state)
            .is_err());

        for elem in elems {
            assert!(state.has(&elem));
            let computed_new = accumulator.compute_new_post_remove(&elem, &keypair.secret_key);
            accumulator = accumulator
                .remove(&elem, &keypair.secret_key, &initial_elements, &mut state)
                .unwrap();
            assert!(!state.has(&elem));
            assert_eq!(computed_new, (accumulator.f_V, accumulator.V));

            let nm_wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            let verification_accum = UniversalAccumulator::from_accumulated(*accumulator.value());
            assert!(verification_accum.verify_non_membership(
                &elem,
                &nm_wit,
                &keypair.public_key,
                &params
            ));

            let members = state.db.iter().copied().collect::<Vec<_>>();
            let d = UniversalAccumulator::<Bls12_381>::compute_d_given_members(&elem, &members);
            assert_eq!(
                accumulator
                    .compute_non_membership_witness_given_d(d, &elem, &keypair.secret_key, &params)
                    .unwrap(),
                nm_wit
            );
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

        let additions: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9].into_iter().map(|i| additions[i]).collect();

        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i];
            accumulator_1 = accumulator_1
                .add(elem, &keypair.secret_key, &initial_elements, &mut state_1)
                .unwrap();
        }

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());

        // Add as a batch
        let computed_new =
            accumulator_2.compute_new_post_add_batch(&additions, &keypair.secret_key);
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
        assert_eq!(computed_new, (accumulator_2.f_V, accumulator_2.V));

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
        let computed_new =
            accumulator_2.compute_new_post_remove_batch(&removals, &keypair.secret_key);
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
        assert_eq!(computed_new, (accumulator_2.f_V, accumulator_2.V));

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions;
        for e in removals.iter() {
            accumulator_3 = accumulator_3
                .add(*e, &keypair.secret_key, &initial_elements, &mut state_3)
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove as a batch
        let computed_new = accumulator_3.compute_new_post_batch_updates(
            &new_additions,
            &removals,
            &keypair.secret_key,
        );
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
        assert_eq!(computed_new, (accumulator_3.f_V, accumulator_3.V));

        let mem_witnesses = accumulator_3
            .get_membership_witnesses_for_batch(&new_additions, &keypair.secret_key, &state_3)
            .unwrap();
        let verification_accum = UniversalAccumulator::from_accumulated(*accumulator_3.value());
        for i in 0..new_additions.len() {
            assert!(verification_accum.verify_membership(
                &new_additions[i],
                &mem_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        assert_eq!(
            accumulator_3
                .compute_membership_witnesses_for_batch(&new_additions, &keypair.secret_key),
            mem_witnesses
        );

        let start = Instant::now();
        let npn_mem_witnesses = accumulator_3
            .get_non_membership_witnesses_for_batch(
                &removals,
                &keypair.secret_key,
                &state_3,
                &params,
            )
            .unwrap();
        println!("Non-membership witnesses in accumulator of size {} using secret key for batch of size {} takes: {:?}", state_3.db.len(), removals.len(), start.elapsed());
        for i in 0..removals.len() {
            assert!(verification_accum.verify_non_membership(
                &removals[i],
                &npn_mem_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        let members = state_3.db.iter().copied().collect::<Vec<_>>();
        let d = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &removals, &members,
        );
        assert_eq!(
            accumulator_3
                .compute_non_membership_witnesses_for_batch_given_d(
                    d,
                    &removals,
                    &keypair.secret_key,
                    &params
                )
                .unwrap(),
            npn_mem_witnesses
        );
    }

    #[test]
    fn computing_d() {
        // Test computing `d` where `d = (member_0 - element)*(member_1 - element)*...(member_n - element)`
        // where each `member_i` is an accumulator member.

        let mut rng = StdRng::seed_from_u64(0u64);

        // Check that `d` computed for a single element (non-member) when all members are available is
        // same as when `d` is computed over chunks of members and then multiplied
        let members: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let non_member = Fr::rand(&mut rng);

        let d = UniversalAccumulator::<Bls12_381>::compute_d_given_members(&non_member, &members);

        let mut chunks = members.chunks(3);
        let d1 = UniversalAccumulator::<Bls12_381>::compute_d_given_members(
            &non_member,
            chunks.next().unwrap(),
        );
        let d2 = UniversalAccumulator::<Bls12_381>::compute_d_given_members(
            &non_member,
            chunks.next().unwrap(),
        );
        let d3 = UniversalAccumulator::<Bls12_381>::compute_d_given_members(
            &non_member,
            chunks.next().unwrap(),
        );
        let d4 = UniversalAccumulator::<Bls12_381>::compute_d_given_members(
            &non_member,
            chunks.next().unwrap(),
        );
        assert_eq!(d, d1 * d2 * d3 * d4);

        // Check that `d` computed for a batch of elements (non-members) when all members are available is
        // same as when `d` is computed over chunks of members and then multiplied
        let non_members = vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let d = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &non_members,
            &members,
        );

        let mut chunks = members.chunks(3);
        let d1 = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &non_members,
            chunks.next().unwrap(),
        );
        let d2 = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &non_members,
            chunks.next().unwrap(),
        );
        let d3 = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &non_members,
            chunks.next().unwrap(),
        );
        let d4 = UniversalAccumulator::<Bls12_381>::compute_d_for_batch_given_members(
            &non_members,
            chunks.next().unwrap(),
        );
        assert_eq!(d.len(), d1.len());
        assert_eq!(d.len(), d2.len());
        assert_eq!(d.len(), d3.len());
        assert_eq!(d.len(), d4.len());
        for i in 0..d.len() {
            assert_eq!(d[i], d1[i] * d2[i] * d3[i] * d4[i]);
        }
    }
}
