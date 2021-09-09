#![allow(non_snake_case)]

//! Positive accumulator that support single as well as batched additions, removals and generating
//! membership witness for single or a multiple elements at once. Described in section 2 of the paper.
//! Creating proof of knowledge of signature and verifying it:
//! # Examples
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//! use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
//! use vb_accumulator::persistence::State;
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//!
//! let accumulator = PositiveAccumulator::initialize(&params);
//!
//! // `state` should be a persistent db implementing the trait `State`
//! // `elem` is being added to the accumulator
//! let new_accumulator = accumulator
//!                 .add(elem, &keypair.secret_key, &mut state)
//!                 .unwrap();
//!
//! // Create membership witness
//! let m_wit = new_accumulator
//!                 .get_membership_witness(&elem, &keypair.secret_key, &state)
//!                 .unwrap();
//!
//! // Verify membership witness
//! new_accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params);
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
//! // Create membership witnesses for multiple elements at once
//! let witnesses = new_accumulator
//!             .get_membership_witness_for_batch(&additions, &keypair.secret_key, &state)
//!             .unwrap();
//! ```

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::fields::Field;
use ark_ff::{batch_inversion, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
    One,
};

use crate::batch_utils::Poly_d;
use crate::error::VBAccumulatorError;
use crate::persistence::State;
use crate::setup::{PublicKey, SecretKey, SetupParams};
use crate::utils::multiply_field_elems_refs_with_same_group_elem;
use crate::witness::MembershipWitness;

/// Accumulator supporting only membership proofs
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PositiveAccumulator<E: PairingEngine>(pub E::G1Affine);

/// Trait to hold common functionality among both positive and universal accumulator
pub trait Accumulator<E: PairingEngine> {
    /// The accumulated value of all the members. It is considered a digest of state of the accumulator
    fn value(&self) -> &E::G1Affine;

    /// Checks to do before adding the element to the accumulator like element being already present
    fn check_before_add(
        &self,
        element: &E::Fr,
        state: &dyn State<E::Fr>,
    ) -> Result<(), VBAccumulatorError> {
        if state.has(element) {
            return Err(VBAccumulatorError::ElementPresent);
        }
        Ok(())
    }

    /// Checks to do before removing the element from the accumulator like element being already
    /// absent
    fn check_before_remove(
        &self,
        element: &E::Fr,
        state: &dyn State<E::Fr>,
    ) -> Result<(), VBAccumulatorError> {
        if !state.has(element) {
            return Err(VBAccumulatorError::ElementAbsent);
        }
        Ok(())
    }

    /// Common code for adding a single member in both accumulators. Described in section 2 of the paper
    fn _add(
        &self,
        element: E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<(E::Fr, E::G1Affine), VBAccumulatorError> {
        self.check_before_add(&element, state)?;
        // (element + sk) * self.V
        let y_plus_alpha = element + sk.0;
        let newV = self.value().mul(y_plus_alpha.into_repr());

        state.add(element);

        Ok((y_plus_alpha, newV.into_affine()))
    }

    /// Common code for adding a batch of members in both accumulators. Described in section 2 of the paper
    fn _add_batch(
        &self,
        elements: Vec<E::Fr>,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<(E::Fr, E::G1Affine), VBAccumulatorError> {
        for element in elements.iter() {
            self.check_before_add(&element, state)?;
        }
        // d_A(-alpha)
        let d_alpha = Poly_d::<E::Fr>::eval_direct(&elements, &-sk.0);
        // d_A(-alpha) * self.V
        let newV = self.value().mul(d_alpha.into_repr());

        for element in elements {
            state.add(element);
        }

        Ok((d_alpha, newV.into_affine()))
    }

    /// Common code for removing a single member from both accumulators. Described in section 2 of the paper
    fn _remove(
        &self,
        element: &E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<(E::Fr, E::G1Affine), VBAccumulatorError> {
        self.check_before_remove(&element, state)?;
        // 1/(element + sk) * self.V
        let y_plus_alpha_inv = (*element + sk.0).inverse().unwrap(); // Unwrap is fine as element has to equal secret key for it to panic
        let newV = self.value().mul(y_plus_alpha_inv.into_repr());

        state.remove(&element);

        Ok((y_plus_alpha_inv, newV.into_affine()))
    }

    /// Common code for removing a batch of members from both accumulators. Described in section 3 of the paper
    fn _remove_batch(
        &self,
        elements: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<(E::Fr, E::G1Affine), VBAccumulatorError> {
        for element in elements {
            self.check_before_remove(&element, state)?;
        }
        // 1/d_D(-alpha) * self.V
        let d_alpha = Poly_d::<E::Fr>::eval_direct(&elements, &-sk.0);
        let d_alpha_inv = d_alpha.inverse().unwrap(); // Unwrap is fine as 1 or more elements has to equal secret key for it to panic
        let newV = self.value().mul(d_alpha_inv.into_repr());

        for element in elements {
            state.remove(element);
        }
        Ok((d_alpha_inv, newV.into_affine()))
    }

    /// Common code for adding and removing batches (1 batch each) of elements in both accumulators. Described in section 3 of the paper
    fn _batch_updates(
        &self,
        additions: Vec<E::Fr>,
        removals: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<(E::Fr, E::G1Affine), VBAccumulatorError> {
        for element in additions.iter() {
            self.check_before_add(&element, state)?;
        }
        for element in removals {
            self.check_before_remove(&element, state)?;
        }

        // d_A(-alpha)/d_D(-alpha) * self.V
        let d_alpha_add = Poly_d::<E::Fr>::eval_direct(&additions, &-sk.0);
        let d_alpha = if removals.len() > 0 {
            let d_alpha_rem = Poly_d::<E::Fr>::eval_direct(removals, &-sk.0);
            let d_alpha_rem_inv = d_alpha_rem.inverse().unwrap(); // Unwrap is fine as 1 or more elements has to equal secret key for it to panic
            d_alpha_add * d_alpha_rem_inv
        } else {
            d_alpha_add
        };
        let newV = self.value().mul(d_alpha.into_repr());

        for element in additions {
            state.add(element);
        }
        for element in removals {
            state.remove(element);
        }
        Ok((d_alpha, newV.into_affine()))
    }

    /// Get membership witness for an element present in accumulator. Described in section 2 of the paper
    fn get_membership_witness(
        &self,
        element: &E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &dyn State<E::Fr>,
    ) -> Result<MembershipWitness<E::G1Affine>, VBAccumulatorError> {
        if !state.has(element) {
            return Err(VBAccumulatorError::ElementAbsent);
        }

        // 1/(element + sk) * self.V
        let y_plus_alpha_inv = (*element + sk.0).inverse().unwrap();
        let witness = self.value().mul(y_plus_alpha_inv.into_repr());

        Ok(MembershipWitness(witness.into_affine()))
    }

    /// Get membership witnesses for multiple elements present in accumulator. Returns witnesses in the
    /// order of passed elements. It is more efficient than computing multiple witnesses independently as
    /// it uses windowed multiplication and batch invert. Will throw error even if one element is not present
    fn get_membership_witness_for_batch(
        &self,
        elements: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &dyn State<E::Fr>,
    ) -> Result<Vec<MembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        for element in elements {
            if !state.has(element) {
                return Err(VBAccumulatorError::ElementAbsent);
            }
        }

        // For each element in `elements`, compute 1/(element + sk)
        let mut y_sk: Vec<E::Fr> = elements.iter().map(|e| *e + sk.0).collect();
        batch_inversion(&mut y_sk);

        Ok(
            MembershipWitness::projective_points_to_membership_witnesses(
                multiply_field_elems_refs_with_same_group_elem(
                    4,
                    self.value().into_projective(),
                    y_sk.iter(),
                ),
            ),
        )
    }

    /// Check if element present in accumulator. Described in section 2 of the paper
    fn verify_membership(
        &self,
        element: &E::Fr,
        witness: &MembershipWitness<E::G1Affine>,
        pk: &PublicKey<E::G2Affine>,
        params: &SetupParams<E>,
    ) -> bool {
        // e(witness, element*P_tilde + Q_tilde) == e(self.V, P_tilde) => e(witness, element*P_tilde + Q_tilde) * e(self.V, P_tilde)^-1 == 1

        // element * P_tilde
        let mut P_tilde_times_y = params.P_tilde.into_projective();
        P_tilde_times_y *= *element;

        // e(witness, element*P_tilde + Q_tilde) * e(self.V, -P_tilde) == 1
        E::product_of_pairings(&[
            (
                E::G1Prepared::from(witness.0),
                E::G2Prepared::from((P_tilde_times_y + pk.Q_tilde.into_projective()).into_affine()),
            ),
            (
                E::G1Prepared::from(*self.value()),
                E::G2Prepared::from(-params.P_tilde),
            ),
        ])
        .is_one()
    }
}

impl<E> Accumulator<E> for PositiveAccumulator<E>
where
    E: PairingEngine,
{
    fn value(&self) -> &E::G1Affine {
        &self.0
    }
}

impl<E> PositiveAccumulator<E>
where
    E: PairingEngine,
{
    /// Create a new positive accumulator
    pub fn initialize(setup_params: &SetupParams<E>) -> Self {
        Self(setup_params.P.clone())
    }

    /// Add an element to the accumulator and state
    pub fn add(
        &self,
        element: E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._add(element, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Add a batch of members in the accumulator
    pub fn add_batch(
        &self,
        elements: Vec<E::Fr>,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._add_batch(elements, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Remove an element from the accumulator and state
    pub fn remove(
        &self,
        element: &E::Fr,
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove(element, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Removing a batch of members from the accumulator
    pub fn remove_batch(
        &self,
        elements: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove_batch(elements, sk, state)?;
        Ok(Self(acc_pub))
    }

    /// Adding and removing batches of elements from the accumulator
    pub fn batch_updates(
        &self,
        additions: Vec<E::Fr>,
        removals: &[E::Fr],
        sk: &SecretKey<E::Fr>,
        state: &mut dyn State<E::Fr>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._batch_updates(additions, removals, sk, state)?;
        Ok(Self(acc_pub))
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::{Duration, Instant};

    use ark_bls12_381::Bls12_381;
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};

    use crate::persistence::test::*;
    use crate::setup::Keypair;
    use crate::test_serialization;

    use super::*;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

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
        let keypair = Keypair::<Bls12_381>::generate(rng, &params);

        let accumulator = PositiveAccumulator::initialize(&params);
        let state = InMemoryState::new();
        (params, keypair, accumulator, state)
    }

    #[test]
    fn membership() {
        // Test to check membership in accumulator
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        test_serialization!(PositiveAccumulator, accumulator);

        let mut total_mem_check_time = Duration::default();
        let count = 100;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err());

            assert!(!state.has(&elem));
            accumulator = accumulator
                .add(elem.clone(), &keypair.secret_key, &mut state)
                .unwrap();
            assert!(state.has(&elem));

            assert!(accumulator
                .add(elem.clone(), &keypair.secret_key, &mut state)
                .is_err());

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let mut expected_V = m_wit.0.into_projective();
            expected_V *= elem + keypair.secret_key.0;
            assert_eq!(expected_V, *accumulator.value());

            // Witness can be serialized
            test_serialization!(MembershipWitness, m_wit);

            let start = Instant::now();
            assert!(accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params));
            total_mem_check_time += start.elapsed();
            elems.push(elem);
        }

        for elem in elems {
            assert!(state.has(&elem));
            accumulator = accumulator
                .remove(&elem, &keypair.secret_key, &mut state)
                .unwrap();
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
        let mut accumulator_2 = PositiveAccumulator::initialize(&params);
        let mut state_2 = InMemoryState::<Fr>::new();
        let mut accumulator_3 = PositiveAccumulator::initialize(&params);
        let mut state_3 = InMemoryState::<Fr>::new();
        let mut accumulator_4 = PositiveAccumulator::initialize(&params);
        let mut state_4 = InMemoryState::<Fr>::new();

        let additions: Vec<Fr> = (0..10).into_iter().map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions[i].clone())
            .collect();

        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i].clone();
            accumulator_1 = accumulator_1
                .add(elem.clone(), &keypair.secret_key, &mut state_1)
                .unwrap();
        }

        // Adding empty batch does not change accumulator
        let accumulator_same = accumulator_1
            .add_batch(vec![], &keypair.secret_key, &mut state_1)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_same.value());

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());
        // Add as a batch
        accumulator_2 = accumulator_2
            .add_batch(additions.clone(), &keypair.secret_key, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove(&removals[i], &keypair.secret_key, &mut state_1)
                .unwrap();
        }

        // Removing empty batch does not change accumulator
        let accumulator_same = accumulator_1
            .remove_batch(&[], &keypair.secret_key, &mut state_1)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_same.value());

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());
        // Remove as a batch
        accumulator_2 = accumulator_2
            .remove_batch(&removals, &keypair.secret_key, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions.clone();
        for e in removals.iter() {
            accumulator_3 = accumulator_3
                .add(e.clone(), &keypair.secret_key, &mut state_3)
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove in call as a batch
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

        let witnesses = accumulator_3
            .get_membership_witness_for_batch(&new_additions, &keypair.secret_key, &state_3)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(accumulator_3.verify_membership(
                &new_additions[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        // Add a batch
        accumulator_4 = accumulator_4
            .batch_updates(additions.clone(), &[], &keypair.secret_key, &mut state_4)
            .unwrap();
        // Remove a batch
        accumulator_4 = accumulator_4
            .batch_updates(vec![], &removals, &keypair.secret_key, &mut state_4)
            .unwrap();
        // Effect should be same as that of adding and removing them together
        assert_eq!(*accumulator_1.value(), *accumulator_4.value());
        assert_eq!(state_1.db, state_4.db);

        let witnesses = accumulator_4
            .get_membership_witness_for_batch(&new_additions, &keypair.secret_key, &state_4)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(accumulator_4.verify_membership(
                &new_additions[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
    }
}
