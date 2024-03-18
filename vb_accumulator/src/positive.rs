#![allow(non_snake_case)]

//! Positive accumulator that support single as well as batched additions, removals and generating
//! membership witness for single or multiple elements at once. Described in section 2 of the paper.
//! Creating accumulator, adding/removing from it, creating and verifying membership witness:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//! use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
//! use vb_accumulator::persistence::State;
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//! let public_key = &keypair.public_key;
//!
//! let accumulator = PositiveAccumulator::initialize(&params);
//!
//! // `state` should be a persistent db implementing the trait `State`
//! // `elem` is being added to the accumulator
//! let new_accumulator = accumulator
//!                 .add(elem, &keypair.secret_key, &mut state)
//!                 .unwrap();
//!
//! // Get accumulated value (as group element in G1)
//! let accumulated = accumulator.value();
//!
//! // Create membership witness for the element `elem` just added
//! let m_wit = new_accumulator
//!                 .get_membership_witness(&elem, &keypair.secret_key, &state)
//!                 .unwrap();
//!
//! // Verifiers should check that the parameters and public key are valid before verifying
//! // any witness. This just needs to be done once when the verifier fetches/receives them.
//!
//! assert!(params.is_valid());
//! assert!(public_key.is_valid());
//!
//! // Verify membership witness
//! new_accumulator.verify_membership(&elem, &m_wit, public_key, &params);
//!
//! // Or create a new new accumulator for verification and verify
//! let verification_accumulator = PositiveAccumulator::from_accumulated(new_accumulator.value().clone());
//! verification_accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params);
//!
//! // Remove elem from accumulator
//! new_accumulator
//!                 .remove(&elem, &keypair.secret_key, &mut state)
//!                 .unwrap();
//!
//! // Add multiple elements. `additions` is a vector of elements to be added
//! let new_accumulator = accumulator
//!             .add_batch(additions, &keypair.secret_key, &mut state_2)
//!             .unwrap();
//!
//! // Now the accumulator manager needs to create membership witnesses for the batch `additions` he added
//! // above. This can be done faster than doing `get_membership_witness` for each member in `additions`.
//! // Create membership witnesses for multiple elements at once
//! let witnesses = new_accumulator
//!             .get_membership_witnesses_for_batch(&additions, &keypair.secret_key, &state)
//!             .unwrap();
//!
//! // Remove multiple elements. `&removals` is a slice of elements to be removed
//! let new_accumulator = accumulator
//!             .remove_batch(&removals, &keypair.secret_key, &mut state)
//!             .unwrap();
//!
//! // Add and remove multiple elements. `additions` is a vector of elements to be added and `&removals` is a slice of elements to be removed
//! let new_accumulator = accumulator
//!             .batch_updates(
//!                 additions,
//!                 &removals,
//!                 &keypair.secret_key,
//!                 &mut state,
//!             )
//!             .unwrap();
//!
//! // Above methods to update accumulator and generate witness require access to `State`. In cases when its
//! // not possible to provide access to `State`, use methods starting with `compute_` to compute the required
//! // value.
//!
//! // Adding an element. Assume that `State` has been checked for the absence of `new_elem`
//! let new = accumulator.compute_new_post_add(&new_elem, &keypair.secret_key);
//!
//! // Initialize accumulator from above update. Assume that `new_elem` will be added to the `State`
//! let new_accumulator = PositiveAccumulator::from_value(new);
//!
//! // Similarly, `compute_new_post_remove`, `compute_new_post_add_batch`, `compute_membership_witness`, etc
//! ```

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{batch_inversion, fields::Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, cfg_iter_mut, fmt::Debug, vec::Vec};
use dock_crypto_utils::serde_utils::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::Zeroize;

use crate::{
    batch_utils::Poly_d,
    error::VBAccumulatorError,
    persistence::State,
    setup::{PublicKey, SecretKey, SetupParams},
    witness::MembershipWitness,
};
use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Accumulator supporting only membership proofs. For more docs, check [`Accumulator`]
///
/// [`Accumulator`]: crate::positive::Accumulator
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PositiveAccumulator<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub E::G1Affine);

/// Trait to hold common functionality among both positive and universal accumulator
/// Methods changing or reading accumulator state take a mutable or immutable reference to `State` which
/// is a trait that should be implemented by a persistent database that tracks the accumulator's members.
/// Methods starting with `compute_` (or `_compute_` for common logic between Positive and Universal
/// accumulator) do not depend on `State` and contain the logic only for that operation. This is useful
/// when it is not possible to make the persistent database available to this code like when writing a WASM
/// wrapper or when the persistent database cannot be made to satisfy one or functions of the trait `State`.
/// Eg. function `_add` is used when adding a new element to the accumulator, it checks if the new element
/// is not already part of the `State` and if not, computes the new accumulator and adds the element
/// to the `State`; but the function `_compute_new_post_add` only computes the new accumulator, it does not
/// modify (check or add) the `State` and hence does not need the reference to it. However, note that it
/// is important to do the required checks and updates in `State`, eg. just by using `_compute_new_post_add`,
/// a membership witness can be created for an element not present in the accumulator that will satisfy the
/// verification (pairing) equation and thus make `verify_membership` return true. Thus, before creating
/// a membership witness, `State` should be checked.
pub trait Accumulator<E: Pairing> {
    /// The accumulated value of all the members. It is considered a digest of state of the accumulator
    fn value(&self) -> &E::G1Affine;

    /// Checks that should be done before adding the element to the accumulator, such as the element
    /// already being present
    fn check_before_add(
        &self,
        element: &E::ScalarField,
        state: &dyn State<E::ScalarField>,
    ) -> Result<(), VBAccumulatorError> {
        if state.has(element) {
            return Err(VBAccumulatorError::ElementPresent);
        }
        Ok(())
    }

    /// Checks that should be done before removing the element from the accumulator, such as the element
    /// already being absent
    fn check_before_remove(
        &self,
        element: &E::ScalarField,
        state: &dyn State<E::ScalarField>,
    ) -> Result<(), VBAccumulatorError> {
        if !state.has(element) {
            return Err(VBAccumulatorError::ElementAbsent);
        }
        Ok(())
    }

    /// Compute new accumulated value after addition. Described in section 2 of the paper
    fn _compute_new_post_add(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        // (element + sk) * self.V
        let y_plus_alpha = *element + sk.0;
        let newV = self
            .value()
            .mul_bigint(y_plus_alpha.into_bigint())
            .into_affine();
        (y_plus_alpha, newV)
    }

    /// Common code for adding a single member in both accumulators. Reads and writes to state. Described
    /// in section 2 of the paper
    fn _add(
        &self,
        element: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(E::ScalarField, E::G1Affine), VBAccumulatorError> {
        self.check_before_add(&element, state)?;
        let t = self._compute_new_post_add(&element, sk);
        state.add(element);
        Ok(t)
    }

    /// Compute new accumulated value after batch addition. Described in section 3 of the paper
    fn _compute_new_post_add_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        // d_A(-alpha)
        let d_alpha = Poly_d::<E::ScalarField>::eval_direct(elements, &-sk.0);
        // d_A(-alpha) * self.V
        let newV = self.value().mul_bigint(d_alpha.into_bigint()).into_affine();
        (d_alpha, newV)
    }

    /// Common code for adding a batch of members in both accumulators. Reads and writes to state. Described
    /// in section 3 of the paper
    fn _add_batch(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(E::ScalarField, E::G1Affine), VBAccumulatorError> {
        for element in elements.iter() {
            self.check_before_add(element, state)?;
        }
        let t = self._compute_new_post_add_batch(&elements, sk);
        for element in elements {
            state.add(element);
        }
        Ok(t)
    }

    /// Compute new accumulated value after removal. Described in section 2 of the paper
    fn _compute_new_post_remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        let mut y_plus_alpha = *element + sk.0;
        // 1/(element + sk) * self.V
        let y_plus_alpha_inv = y_plus_alpha.inverse().unwrap(); // Unwrap is fine as element has to equal secret key for it to panic
        let newV = self
            .value()
            .mul_bigint(y_plus_alpha_inv.into_bigint())
            .into_affine();
        y_plus_alpha.zeroize();
        (y_plus_alpha_inv, newV)
    }

    /// Common code for removing a single member from both accumulators. Reads and writes to state.
    /// Described in section 2 of the paper
    fn _remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(E::ScalarField, E::G1Affine), VBAccumulatorError> {
        self.check_before_remove(element, state)?;
        let t = self._compute_new_post_remove(element, sk);
        state.remove(element);
        Ok(t)
    }

    /// Compute new accumulated value after batch removals. Described in section 3 of the paper
    fn _compute_new_post_remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        // 1/d_D(-alpha) * self.V
        let mut d_alpha = Poly_d::<E::ScalarField>::eval_direct(elements, &-sk.0);
        let d_alpha_inv = d_alpha.inverse().unwrap(); // Unwrap is fine as 1 or more elements has to equal secret key for it to panic
        let newV = self
            .value()
            .mul_bigint(d_alpha_inv.into_bigint())
            .into_affine();
        d_alpha.zeroize();
        (d_alpha_inv, newV)
    }

    /// Common code for removing a batch of members from both accumulators. Reads and writes to state.
    /// Described in section 3 of the paper
    fn _remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(E::ScalarField, E::G1Affine), VBAccumulatorError> {
        for element in elements {
            self.check_before_remove(element, state)?;
        }
        let t = self._compute_new_post_remove_batch(elements, sk);
        for element in elements {
            state.remove(element);
        }
        Ok(t)
    }

    /// Compute new accumulated value after batch additions and removals. Described in section 3 of the paper
    fn _compute_new_post_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (E::ScalarField, E::G1Affine) {
        // d_A(-alpha)/d_D(-alpha) * self.V
        let d_alpha_add = Poly_d::<E::ScalarField>::eval_direct(additions, &-sk.0);
        let d_alpha = if !removals.is_empty() {
            let d_alpha_rem = Poly_d::<E::ScalarField>::eval_direct(removals, &-sk.0);
            let d_alpha_rem_inv = d_alpha_rem.inverse().unwrap(); // Unwrap is fine as 1 or more elements has to equal secret key for it to panic
            d_alpha_add * d_alpha_rem_inv
        } else {
            d_alpha_add
        };
        let newV = self.value().mul_bigint(d_alpha.into_bigint()).into_affine();
        (d_alpha, newV)
    }

    /// Common code for adding and removing batches (1 batch each) of elements in both accumulators.
    /// Reads and writes to state. Described in section 3 of the paper
    fn _batch_updates(
        &self,
        additions: Vec<E::ScalarField>,
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(E::ScalarField, E::G1Affine), VBAccumulatorError> {
        for element in additions.iter() {
            self.check_before_add(element, state)?;
        }
        for element in removals {
            self.check_before_remove(element, state)?;
        }
        let t = self._compute_new_post_batch_updates(&additions, removals, sk);
        for element in additions {
            state.add(element);
        }
        for element in removals {
            state.remove(element);
        }
        Ok(t)
    }

    /// Compute membership witness
    fn compute_membership_witness(
        &self,
        member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> MembershipWitness<E::G1Affine> {
        // 1/(element + sk) * self.V
        let mut y_plus_alpha_inv = (*member + sk.0).inverse().unwrap();
        let witness = self.value().mul_bigint(y_plus_alpha_inv.into_bigint());
        y_plus_alpha_inv.zeroize();
        MembershipWitness(witness.into_affine())
    }

    /// Get membership witness for an element present in accumulator. Described in section 2 of the paper
    fn get_membership_witness(
        &self,
        member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &dyn State<E::ScalarField>,
    ) -> Result<MembershipWitness<E::G1Affine>, VBAccumulatorError> {
        if !state.has(member) {
            return Err(VBAccumulatorError::ElementAbsent);
        }
        Ok(self.compute_membership_witness(member, sk))
    }

    /// Compute membership witness for batch
    fn compute_membership_witnesses_for_batch(
        &self,
        members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> Vec<MembershipWitness<E::G1Affine>> {
        // For each element in `elements`, compute 1/(element + sk)
        let mut y_sk: Vec<E::ScalarField> = cfg_iter!(members).map(|e| *e + sk.0).collect();
        batch_inversion(&mut y_sk);
        let wits =
            multiply_field_elems_with_same_group_elem(self.value().into_group(), y_sk.as_slice());
        cfg_iter_mut!(y_sk).for_each(|y| y.zeroize());
        MembershipWitness::projective_points_to_membership_witnesses(wits)
    }

    /// Get membership witnesses for multiple elements present in accumulator. Returns witnesses in the
    /// order of passed elements. It is more efficient than computing multiple witnesses independently as
    /// it uses windowed multiplication and batch invert. Will throw error even if one element is not present
    fn get_membership_witnesses_for_batch(
        &self,
        members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &dyn State<E::ScalarField>,
    ) -> Result<Vec<MembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        for element in members {
            if !state.has(element) {
                return Err(VBAccumulatorError::ElementAbsent);
            }
        }
        Ok(self.compute_membership_witnesses_for_batch(members, sk))
    }

    /// Check if element present in accumulator given the accumulated value. Described in section 2 of the paper
    fn verify_membership_given_accumulated(
        V: &E::G1Affine,
        member: &E::ScalarField,
        witness: &MembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        // e(witness, element*P_tilde + Q_tilde) == e(V, P_tilde) => e(witness, element*P_tilde + Q_tilde) * e(V, P_tilde)^-1 == 1

        // element * P_tilde
        let mut P_tilde_times_y_plus_Q_tilde = params.P_tilde.into_group();
        P_tilde_times_y_plus_Q_tilde *= *member;

        // element * P_tilde + Q_tilde
        P_tilde_times_y_plus_Q_tilde += pk.0;

        // e(witness, element*P_tilde + Q_tilde) * e(V, -P_tilde) == 1
        E::multi_pairing(
            [witness.0, *V],
            [P_tilde_times_y_plus_Q_tilde, -params.P_tilde.into_group()],
        )
        .is_zero()
    }

    /// Check if element present in accumulator. Described in section 2 of the paper
    fn verify_membership(
        &self,
        member: &E::ScalarField,
        witness: &MembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        Self::verify_membership_given_accumulated(self.value(), member, witness, pk, params)
    }

    /// Create an `Accumulator` using the accumulated value. This is used for membership verification
    /// purposes only
    fn from_accumulated(accumulated: E::G1Affine) -> Self;

    fn randomized_value(&self, randomizer: &E::ScalarField) -> E::G1Affine {
        (*self.value() * randomizer).into_affine()
    }
}

impl<E: Pairing> Accumulator<E> for PositiveAccumulator<E> {
    fn value(&self) -> &E::G1Affine {
        &self.0
    }

    /// Create a `PositiveAccumulator` using the accumulated value. This is used for membership verification
    /// purposes only
    fn from_accumulated(accumulated: E::G1Affine) -> Self {
        Self(accumulated)
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for PositiveAccumulator<E> {
    fn as_ref(&self) -> &E::G1Affine {
        self.value()
    }
}

impl<E: Pairing> PositiveAccumulator<E> {
    /// Create a new positive accumulator
    pub fn initialize(params_gen: impl AsRef<E::G1Affine>) -> Self {
        Self(*params_gen.as_ref())
    }

    /// Compute new accumulated value after addition
    pub fn compute_new_post_add(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> E::G1Affine {
        self._compute_new_post_add(element, sk).1
    }

    /// Add an element to the accumulator and state
    pub fn add(
        &self,
        element: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._add(element, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Compute new accumulated value after batch addition
    pub fn compute_new_post_add_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> E::G1Affine {
        self._compute_new_post_add_batch(elements, sk).1
    }

    /// Add a batch of members in the accumulator
    pub fn add_batch(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._add_batch(elements, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Compute new accumulated value after removal
    pub fn compute_new_post_remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> E::G1Affine {
        self._compute_new_post_remove(element, sk).1
    }

    /// Remove an element from the accumulator and state
    pub fn remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove(element, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Compute new accumulated value after batch removal
    pub fn compute_new_post_remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> E::G1Affine {
        self._compute_new_post_remove_batch(elements, sk).1
    }

    /// Removing a batch of members from the accumulator
    pub fn remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove_batch(elements, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Compute new accumulated value after batch additions and removals
    pub fn compute_new_post_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> E::G1Affine {
        self._compute_new_post_batch_updates(additions, removals, sk)
            .1
    }

    /// Adding and removing batches of elements from the accumulator
    pub fn batch_updates(
        &self,
        additions: Vec<E::ScalarField>,
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._batch_updates(additions, removals, sk, state)?;
        Ok(Self(acc_pub))
    }

    pub fn from_value(value: E::G1Affine) -> Self {
        Self(value)
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::{Duration, Instant};

    use crate::batch_utils::Omega;
    use ark_bls12_381::Bls12_381;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    use crate::{persistence::test::*, setup::Keypair, test_serialization};

    use super::*;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    /// Setup a positive accumulator, its keys, params and state for testing.
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

    #[test]
    fn membership() {
        // Test to check membership in accumulator
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        test_serialization!(PositiveAccumulator<Bls12_381>, accumulator);

        let mut total_mem_check_time = Duration::default();
        let count = 100;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err());

            assert!(!state.has(&elem));
            let computed_new = accumulator.compute_new_post_add(&elem, &keypair.secret_key);
            accumulator = accumulator
                .add(elem, &keypair.secret_key, &mut state)
                .unwrap();
            assert_eq!(computed_new, *accumulator.value());
            assert!(state.has(&elem));

            assert!(accumulator
                .add(elem, &keypair.secret_key, &mut state)
                .is_err());

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let mut expected_V = m_wit.0.into_group();
            expected_V *= elem + keypair.secret_key.0;
            assert_eq!(expected_V, *accumulator.value());

            assert_eq!(
                accumulator.compute_membership_witness(&elem, &keypair.secret_key),
                m_wit
            );

            // Witness can be serialized
            test_serialization!(MembershipWitness<<Bls12_381 as Pairing>::G1Affine>, m_wit);

            let verification_accumulator =
                PositiveAccumulator::from_accumulated(*accumulator.value());
            let start = Instant::now();
            assert!(verification_accumulator.verify_membership(
                &elem,
                &m_wit,
                &keypair.public_key,
                &params
            ));
            total_mem_check_time += start.elapsed();

            // Randomizing the witness and accumulator
            let random = Fr::rand(&mut rng);
            let randomized_accum = accumulator.randomized_value(&random);
            let randomized_wit = m_wit.randomize(&random);
            let verification_accumulator = PositiveAccumulator::from_accumulated(randomized_accum);
            assert!(verification_accumulator.verify_membership(
                &elem,
                &randomized_wit,
                &keypair.public_key,
                &params
            ));

            elems.push(elem);
        }

        for elem in elems {
            assert!(state.has(&elem));
            let computed_new = accumulator.compute_new_post_remove(&elem, &keypair.secret_key);
            accumulator = accumulator
                .remove(&elem, &keypair.secret_key, &mut state)
                .unwrap();
            assert_eq!(computed_new, *accumulator.value());
            assert!(!state.has(&elem));
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err())
        }

        println!(
            "Total time to verify {} individual memberships {:?}",
            count, total_mem_check_time
        );
    }

    #[test]
    fn batch_update_and_membership() {
        // Tests batch updates to accumulator and batch membership witness generation
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator_1, mut state_1) = setup_positive_accum(&mut rng);

        // Create more accumulators to compare. Same elements will be added and removed from them as accumulator_1
        let mut accumulator_2: PositiveAccumulator<Bls12_381> =
            PositiveAccumulator::initialize(&params);
        let mut state_2 = InMemoryState::<Fr>::new();
        let mut accumulator_3: PositiveAccumulator<Bls12_381> =
            PositiveAccumulator::initialize(&params);
        let mut state_3 = InMemoryState::<Fr>::new();
        let mut accumulator_4: PositiveAccumulator<Bls12_381> =
            PositiveAccumulator::initialize(&params);
        let mut state_4 = InMemoryState::<Fr>::new();

        let additions: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9].into_iter().map(|i| additions[i]).collect();

        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i];
            accumulator_1 = accumulator_1
                .add(elem, &keypair.secret_key, &mut state_1)
                .unwrap();
        }

        // Adding empty batch does not change accumulator
        let computed_new = accumulator_1.compute_new_post_add_batch(&[], &keypair.secret_key);
        let accumulator_same = accumulator_1
            .add_batch(vec![], &keypair.secret_key, &mut state_1)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_same.value());
        assert_eq!(*accumulator_1.value(), computed_new);

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());

        // Add as a batch
        let computed_new =
            accumulator_2.compute_new_post_add_batch(&additions, &keypair.secret_key);
        accumulator_2 = accumulator_2
            .add_batch(additions.clone(), &keypair.secret_key, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);
        assert_eq!(computed_new, *accumulator_2.value());

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove(&removals[i], &keypair.secret_key, &mut state_1)
                .unwrap();
        }

        // Removing empty batch does not change accumulator
        let computed_new = accumulator_1.compute_new_post_remove_batch(&[], &keypair.secret_key);
        let accumulator_same = accumulator_1
            .remove_batch(&[], &keypair.secret_key, &mut state_1)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_same.value());
        assert_eq!(*accumulator_1.value(), computed_new);

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());

        // Remove as a batch
        let computed_new =
            accumulator_2.compute_new_post_remove_batch(&removals, &keypair.secret_key);
        accumulator_2 = accumulator_2
            .remove_batch(&removals, &keypair.secret_key, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);
        assert_eq!(computed_new, *accumulator_2.value());

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions.clone();
        for e in removals.iter() {
            accumulator_3 = accumulator_3
                .add(*e, &keypair.secret_key, &mut state_3)
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove in call as a batch
        let computed_new: <Bls12_381 as Pairing>::G1Affine = accumulator_3
            .compute_new_post_batch_updates(&new_additions, &removals, &keypair.secret_key);
        accumulator_3 = accumulator_3
            .batch_updates(
                new_additions.clone(),
                &removals,
                &keypair.secret_key,
                &mut state_3,
            )
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_3.value());
        assert_eq!(*accumulator_2.value(), *accumulator_3.value());
        assert_eq!(state_1.db, state_3.db);
        assert_eq!(state_2.db, state_3.db);
        assert_eq!(computed_new, *accumulator_3.value());

        let verification_accumulator =
            PositiveAccumulator::from_accumulated(*accumulator_3.value());
        let witnesses = accumulator_3
            .get_membership_witnesses_for_batch(&new_additions, &keypair.secret_key, &state_3)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(verification_accumulator.verify_membership(
                &new_additions[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        assert_eq!(
            accumulator_3
                .compute_membership_witnesses_for_batch(&new_additions, &keypair.secret_key),
            witnesses
        );

        // Add a batch
        let computed_new =
            accumulator_4.compute_new_post_batch_updates(&additions, &[], &keypair.secret_key);
        accumulator_4 = accumulator_4
            .batch_updates(additions, &[], &keypair.secret_key, &mut state_4)
            .unwrap();
        assert_eq!(computed_new, *accumulator_4.value());

        // Remove a batch
        let computed_new =
            accumulator_4.compute_new_post_batch_updates(&[], &removals, &keypair.secret_key);
        accumulator_4 = accumulator_4
            .batch_updates(vec![], &removals, &keypair.secret_key, &mut state_4)
            .unwrap();
        assert_eq!(computed_new, *accumulator_4.value());
        // Effect should be same as that of adding and removing them together
        assert_eq!(*accumulator_1.value(), *accumulator_4.value());
        assert_eq!(state_1.db, state_4.db);

        let verification_accumulator =
            PositiveAccumulator::from_accumulated(*accumulator_4.value());
        let witnesses = accumulator_4
            .get_membership_witnesses_for_batch(&new_additions, &keypair.secret_key, &state_4)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(verification_accumulator.verify_membership(
                &new_additions[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
    }

    #[test]
    fn pre_filled_accumulator() {
        // Incase updating an accumulator is expensive like making a blockchain txn, a cheaper strategy
        // is to add the members to the accumulator beforehand but not giving out the witnesses yet.
        // Eg. accumulator manager wants to add a million members over an year, rather than publishing
        // the new accumulator after each addition, the manager can initialize the accumulator with a million
        // member ids (member ids are either predictable like monotonically increasing numbers or the manager
        // can internally keep a of map random ids like UUIDs to a number). Now when the manager actually
        // wants to allow a member to prove membership, he can create a witness for that member but the
        // accumulator value remains same. It should be noted though that changing the accumulator
        // value causes change in all existing witnesses and thus its better to make a good estimate
        // of the number of members during prefill stage
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        // Manager estimates that he will have `total_members` members over the course of time
        let total_members = 100;

        // Prefill the accumulator
        let members: Vec<Fr> = (0..total_members).map(|_| Fr::rand(&mut rng)).collect();
        accumulator = accumulator
            .add_batch(members.clone(), &keypair.secret_key, &mut state)
            .unwrap();

        // Accumulator for verification only
        let verification_accumulator = PositiveAccumulator::from_accumulated(*accumulator.value());

        // Manager decides to give a user his witness
        let member_1 = &members[12];
        let witness_1 = accumulator
            .get_membership_witness(member_1, &keypair.secret_key, &mut state)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_1,
            &witness_1,
            &keypair.public_key,
            &params
        ));

        // Manager decides to give another user his witness
        let member_2 = &members[55];
        let witness_2 = accumulator
            .get_membership_witness(member_2, &keypair.secret_key, &mut state)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_2,
            &witness_2,
            &keypair.public_key,
            &params
        ));

        // Previous user's witness still works
        assert!(verification_accumulator.verify_membership(
            member_1,
            &witness_1,
            &keypair.public_key,
            &params
        ));

        // Manager decides to give another user his witness
        let member_3 = &members[30];
        let witness_3 = accumulator
            .get_membership_witness(member_3, &keypair.secret_key, &mut state)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_3,
            &witness_3,
            &keypair.public_key,
            &params
        ));

        // Previous users' witness still works
        assert!(verification_accumulator.verify_membership(
            member_1,
            &witness_1,
            &keypair.public_key,
            &params
        ));
        assert!(verification_accumulator.verify_membership(
            member_2,
            &witness_2,
            &keypair.public_key,
            &params
        ));

        // Manager decides to remove a member, the new accumulated value will be published along with witness update info
        let omega = Omega::new(&[], &[*member_2], accumulator.value(), &keypair.secret_key);
        accumulator = accumulator
            .remove(member_2, &keypair.secret_key, &mut state)
            .unwrap();

        let verification_accumulator = PositiveAccumulator::from_accumulated(*accumulator.value());

        // Manager decides to give another user his witness
        let member_4 = &members[70];
        let witness_4 = accumulator
            .get_membership_witness(member_4, &keypair.secret_key, &mut state)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_4,
            &witness_4,
            &keypair.public_key,
            &params
        ));

        // Older witnesses need to be updated

        // Update using knowledge of new accumulator and removed member only
        let witness_1_updated = witness_1
            .update_after_removal(member_1, member_2, accumulator.value())
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_1,
            &witness_1_updated,
            &keypair.public_key,
            &params
        ));
        let witness_3_updated = witness_3
            .update_after_removal(member_3, member_2, accumulator.value())
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_3,
            &witness_3_updated,
            &keypair.public_key,
            &params
        ));

        // Update using knowledge of witness info
        let witness_1_updated = witness_1
            .update_using_public_info_after_batch_updates(&[], &[*member_2], &omega, member_1)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_1,
            &witness_1_updated,
            &keypair.public_key,
            &params
        ));
        let witness_3_updated = witness_3
            .update_using_public_info_after_batch_updates(&[], &[*member_2], &omega, member_3)
            .unwrap();
        assert!(verification_accumulator.verify_membership(
            member_3,
            &witness_3_updated,
            &keypair.public_key,
            &params
        ));
    }
}
