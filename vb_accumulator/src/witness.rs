#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! Protocols for updating single or a batch of membership and non-membership witnesses with and
//! without using the secret key. Described in sections 2, 3 and 6 of the paper
//! # Examples
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//! use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
//! use vb_accumulator::witness::MembershipWitness;
//! use vb_accumulator::batch_utils::Omega;
//! use vb_accumulator::persistence::State;
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//!
//! let accumulator = PositiveAccumulator::initialize(&params);
//! // Create membership witness for existing `elem`
//! let m_wit = accumulator
//!                 .get_membership_witness(&elem, &keypair.secret_key, &state)
//!                 .unwrap();
//!
//! // `state` should be a persistent database implementing the trait `State`
//! // `new_elem` is being added to the accumulator
//! let new_accumulator = accumulator
//!                 .add(new_elem, &keypair.secret_key, &mut state)
//!                 .unwrap();
//!
//! // Update witness after addition
//! let new_wit = m_wit.update_after_addition(
//!                         &elem,
//!                         &new_elem,
//!                         accumulator.value(),
//!                     );
//!
//! let new_accumulator = accumulator
//!                 .remove(&new_elem, &keypair.secret_key, &mut state)
//!                 .unwrap();
//!
//! // Update witness after removal
//! let new_wit = new_wit
//!                     .update_after_removal(&elem, &new_elem, new_accumulator.value())
//!                     .unwrap();
//!
//! // Similar API as above for non-membership witness, see tests for examples
//!
//!
//! // Batch update witnesses
//! let accumulator_1 = accumulator
//!             .add_batch(additions_1, &keypair.secret_key, &mut state)
//!             .unwrap();
//! let witnesses_1 = accumulator_1
//!             .get_membership_witnesses_for_batch(&additions_1, &keypair.secret_key, &state)
//!             .unwrap();
//!
//! let accumulator_2 = accumulator_1
//!             .add_batch(additions_2, &keypair.secret_key, &mut state)
//!             .unwrap();
//!
//! // Update witnesses of multiple members using secret key after multiple elements added to the accumulator
//! let new_wits = MembershipWitness::update_using_secret_key_after_batch_additions(
//!             &additions_2,
//!             &additions_1,
//!             &witnesses_1,
//!             accumulator_1.value(),
//!             &keypair.secret_key,
//!         )
//!         .unwrap();
//!
//! // Similar API for updating multiple witnesses when batch of removals or both additions and removals are done using
//! // `MembershipWitness::update_using_secret_key_after_batch_removals` and `MembershipWitness::update_using_secret_key_after_batch_updates` respectively.
//! // See tests for examples.
//!
//! // Similar API as above for non-membership witness, see tests for examples
//!
//! // Update witnesses of multiple members using public info after multiple elements added to the accumulator
//! // Accumulator manager creates `omega`
//! let omega = Omega::new(
//!             &additions,
//!             &removals,
//!             accumulator_before_update.value(),
//!             &keypair.secret_key,
//!         );
//!
//! // Old witness `m_wit` for `elem` is updated to `new_wit` using above omega
//! let new_wit = m_wit
//!                 .update_using_public_info_after_batch_updates(
//!                     &additions,
//!                     &removals,
//!                     &omega,
//!                     &elem,
//!                 )
//!                 .unwrap();
//!
//! // Similar API as above for non-membership witness, see tests for examples
//!
//! ```

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, fields::Field, One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, fmt::Debug, vec::Vec};
use dock_crypto_utils::serde_utils::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    batch_utils::{Omega, Poly_d, Poly_v_A, Poly_v_AD, Poly_v_D},
    error::VBAccumulatorError,
    setup::SecretKey,
};

use dock_crypto_utils::msm::WindowTable;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Trait to hold common functionality among both membership and non-membership witnesses
pub trait Witness<G: AffineRepr> {
    /// Compute an update to the witness after adding a single element in the accumulator. Expects
    /// the accumulator value before the addition. Described in section 2 of the paper
    fn compute_update_after_addition(
        element: &G::ScalarField,
        addition: &G::ScalarField,
        old_witness: &G,
        old_accumulator: &G,
    ) -> (G::ScalarField, G) {
        // (addition - element) * C + V
        let d_factor = *addition - *element;
        let mut new_witness = old_witness.mul_bigint(d_factor.into_bigint());
        new_witness += old_accumulator;
        (d_factor, new_witness.into_affine())
    }

    /// Compute an update to the witness after removing a single element from the accumulator. Expects
    /// the accumulator value after the removal. Described in section 2 of the paper
    fn compute_update_after_removal(
        element: &G::ScalarField,
        removal: &G::ScalarField,
        old_witness: &G,
        new_accumulator: &G,
    ) -> Result<(G::ScalarField, G), VBAccumulatorError> {
        // 1/(removal - element)
        let d_factor = (*removal - *element)
            .inverse()
            .ok_or(VBAccumulatorError::NewElementSameAsCurrent)?;

        // 1/(removal - element) * (C - V)
        let mut new_witness = old_witness.into_group();
        new_witness -= new_accumulator.into_group();
        new_witness *= d_factor;

        Ok((d_factor, new_witness.into_affine()))
    }

    /// Compute an update to several witnesses after adding a batch of elements in the accumulator.
    /// Expects the accumulator value before the addition and knowledge of the secret key. Intended to be
    /// used by the manager. Described in section 3 of the paper
    fn compute_update_using_secret_key_after_batch_additions(
        additions: &[G::ScalarField],
        elements: &[G::ScalarField],
        old_witnesses: &[G],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<(Vec<G::ScalarField>, Vec<G>), VBAccumulatorError> {
        if elements.len() != old_witnesses.len() {
            return Err(VBAccumulatorError::NeedSameNoOfElementsAndWitnesses);
        }
        // `d_A` = Evaluation of polynomial `d_A(y)` for each y in `elements`
        // `v_A` = Evaluation of polynomial `v_A(y)` for each y in `elements`
        let d_A: Vec<_> = cfg_iter!(elements)
            .map(|element| Poly_d::eval_direct(additions, element))
            .collect();
        let v_A = Poly_v_A::eval_direct_on_batch(additions, &sk.0, elements);
        // The same group element (self.V) has to multiplied by each inverse so creating a window table
        let table = WindowTable::new(elements.len(), old_accumulator.into_group());

        // Calculate d_A(y)*C_y + v_A(y)*V for each y in `elements`
        let new_wits: Vec<G::Group> = cfg_iter!(d_A)
            .zip(cfg_iter!(v_A))
            .enumerate()
            .map(|(i, (d, v))| {
                // d*C + v*V
                old_witnesses[i].mul_bigint(d.into_bigint()) + table.multiply(v)
            })
            .collect();
        Ok((d_A, G::Group::normalize_batch(&new_wits)))
    }

    /// Compute an update to several witnesses after removing a batch of elements from the accumulator.
    /// Expects the accumulator value after the removal and knowledge of the secret key. Intended to be
    /// used by the manager. Described in section 3 of the paper
    fn compute_update_using_secret_key_after_batch_removals(
        removals: &[G::ScalarField],
        elements: &[G::ScalarField],
        old_witnesses: &[G],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<(Vec<G::ScalarField>, Vec<G>), VBAccumulatorError> {
        if elements.len() != old_witnesses.len() {
            return Err(VBAccumulatorError::NeedSameNoOfElementsAndWitnesses);
        }
        // `d_D` = Evaluation of polynomial `d_D(y)` for each y in `elements`
        // `v_D` = Evaluation of polynomial `v_D(y)` for each y in `elements`
        let mut d_D: Vec<_> = cfg_iter!(elements)
            .map(|element| Poly_d::eval_direct(removals, element))
            .collect();

        let v_D = Poly_v_D::eval_direct_on_batch(removals, &sk.0, elements);
        // The same group element (self.V) has to multiplied by each inverse so creating a window table
        let table = WindowTable::new(elements.len(), old_accumulator.into_group());

        // Calculate 1/d_D(y) * C_y - v_D(y)/d_D(y) * V for each y in `elements`
        // Invert all d_D(y) in a batch for efficiency
        batch_inversion(&mut d_D);

        let new_wits: Vec<G::Group> = cfg_iter!(d_D)
            .zip(cfg_iter!(v_D))
            .enumerate()
            .map(|(i, (d_inv, v))| {
                let v_d_inv = *v * d_inv;
                // 1/d * C - v/d * V
                old_witnesses[i].mul_bigint(d_inv.into_bigint()) - table.multiply(&v_d_inv)
            })
            .collect();
        Ok((d_D, G::Group::normalize_batch(&new_wits)))
    }

    /// Compute an update to several witnesses after adding and removing batches of elements from the accumulator.
    /// Expects the accumulator value before the update and knowledge of the secret key. Intended to be
    /// used by the manager. Described in section 3 of the paper
    fn compute_update_using_secret_key_after_batch_updates(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        elements: &[G::ScalarField],
        old_witnesses: &[G],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<(Vec<G::ScalarField>, Vec<G>), VBAccumulatorError> {
        if elements.len() != old_witnesses.len() {
            return Err(VBAccumulatorError::NeedSameNoOfElementsAndWitnesses);
        }
        // `d_A` = Evaluation of polynomial `d_A(y)` for each y in `elements`
        // `d_D` = Evaluation of polynomial `d_D(y)` for each y in `elements`
        // `v_AD` = Evaluation of polynomial `v_{A,D}(y)` for each y in `elements`
        let (d_A, mut d_D): (Vec<_>, Vec<_>) = cfg_iter!(elements)
            .map(|element| {
                (
                    Poly_d::eval_direct(additions, element),
                    Poly_d::eval_direct(removals, element),
                )
            })
            .unzip();
        let v_AD = Poly_v_AD::eval_direct_on_batch(additions, removals, &sk.0, elements);
        // The same group element (self.V) has to multiplied by each inverse so creating a window table
        let table = WindowTable::new(elements.len(), old_accumulator.into_group());

        let mut d_factors = Vec::with_capacity(elements.len());

        // Calculate d_A(y)/d_D(y) * C_y + v_{A,D}(y)/d_D(y) * V for each y in `elements`
        // Invert all d_D(y) in a batch for efficiency
        batch_inversion(&mut d_D);
        let new_wits: Vec<G::Group> = d_A
            .into_iter()
            .zip(d_D.into_iter())
            .zip(v_AD.into_iter())
            .enumerate()
            .map(|(i, ((d_A_i, d_D_inv), v))| {
                let d_A_times_d_D_inv = d_A_i * d_D_inv;
                let v_d_inv = v * d_D_inv;
                // d_A_i/d_D * C + v_{A,D}/d_D * V
                let r = old_witnesses[i].mul_bigint(d_A_times_d_D_inv.into_bigint())
                    + table.multiply(&v_d_inv);
                d_factors.push(d_A_times_d_D_inv);
                r
            })
            .collect();
        Ok((d_factors, G::Group::normalize_batch(&new_wits)))
    }

    // NOTE: There are no add-only or remove-only variants of `compute_update_using_public_info` as the
    // manager will otherwise have to publish polynomials `v_A` or `v_D` respectively as well.

    /// Compute an update to the witness after adding and removing batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager. Described in section 4.1 of the paper
    fn compute_update_using_public_info_after_batch_updates(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        omega: &Omega<G>,
        element: &G::ScalarField,
        old_witness: &G,
    ) -> Result<(G::ScalarField, G), VBAccumulatorError> {
        // d_A(x)
        let d_A = Poly_d::eval_direct(additions, element);
        // 1/d_D(x)
        let d_D_inv = Poly_d::eval_direct(removals, element)
            .inverse()
            .ok_or(VBAccumulatorError::CannotBeZero)?;
        // d_A(x)/d_D(x)
        let d_A_times_d_D_inv = d_A * d_D_inv;

        // <powers_of_y, omega> * 1/d_D(x)
        let y_omega_ip = omega.inner_product_with_scaled_powers_of_y(element, &d_D_inv);

        // d_A(x)/d_D(x) * C + 1/d_D(x) * <powers_of_y, omega>
        let new_C = old_witness.mul_bigint(d_A_times_d_D_inv.into_bigint()) + y_omega_ip;
        Ok((d_A_times_d_D_inv, new_C.into_affine()))
    }

    /// Compute an update to the witness after adding and removing several batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager for each batch. Described in section 4.2 of the paper.
    fn compute_update_using_public_info_after_multiple_batch_updates(
        updates_and_omegas: Vec<(&[G::ScalarField], &[G::ScalarField], &Omega<G>)>,
        element: &G::ScalarField,
        old_witness: &G,
    ) -> Result<(G::ScalarField, G), VBAccumulatorError> {
        if updates_and_omegas.len() == 1 {
            return Self::compute_update_using_public_info_after_batch_updates(
                updates_and_omegas[0].0,
                updates_and_omegas[0].1,
                updates_and_omegas[0].2,
                element,
                old_witness,
            );
        }
        // Separate additions, removals and omegas in their own vectors
        let mut additions = Vec::with_capacity(updates_and_omegas.len());
        let mut removals = Vec::with_capacity(updates_and_omegas.len());
        let mut omegas = Vec::with_capacity(updates_and_omegas.len());
        for (a, r, omega) in updates_and_omegas {
            additions.push(a);
            removals.push(r);
            omegas.push(omega);
        }

        Self::compute_update_for_multiple_batches(additions, removals, omegas, element, old_witness)
    }

    fn compute_update_for_multiple_batches(
        additions: Vec<&[G::ScalarField]>,
        removals: Vec<&[G::ScalarField]>,
        omegas: Vec<&Omega<G>>,
        element: &G::ScalarField,
        old_witness: &G,
    ) -> Result<(G::ScalarField, G), VBAccumulatorError> {
        // d_{A_{i->j}} - product of all evaluations of polynomial d_A
        let mut d_A_ij = G::ScalarField::one();
        // d_{D_{i->j}} - product of all evaluations of polynomial d_D
        let mut d_D_ij = G::ScalarField::one();

        // omega_{i->j} - Sum of all omega scaled by factors
        // Maximum size of any omega vector, used to create the resulting vector from addition of all omegas
        let mut max_omega_size = 0;
        let mut omega_t_factors = Vec::with_capacity(omegas.len());
        for t in 0..omegas.len() {
            // Calculate factors for each `omega_t` in the computation of `omega_{i->j}`

            // Optimization: d_D and d_A don't need to be recomputed again. They can be retrieved by caching intermediate products
            // during evaluation of d_A_ij and d_D_ij by the efficiency gain is less than 1% and it comes at the cost of more memory
            // consumption and more complex code

            // `d_{D_{i->t-1}}`
            let d_D = removals
                .iter()
                .take(t)
                .map(|r| Poly_d::eval_direct(r, element))
                .fold(G::ScalarField::one(), |a, b| a * b);
            // `d_{A_{t->j}}`
            let d_A = additions
                .iter()
                .skip(t + 1)
                .map(|a| Poly_d::eval_direct(a, element))
                .fold(G::ScalarField::one(), |a, b| a * b);

            let d_A_times_d_D = d_A * d_D;
            // Store d_A_times_d_D to scale vector `omega[t]` later using multi-scalar multiplication
            omega_t_factors.push(d_A_times_d_D);

            if omegas[t].len() > max_omega_size {
                max_omega_size = omegas[t].len();
            }

            if additions.len() > t {
                d_A_ij *= Poly_d::eval_direct(additions[t], element);
            }
            if removals.len() > t {
                d_D_ij *= Poly_d::eval_direct(removals[t], element);
            }
        }

        let d_D_ij_inv = d_D_ij.inverse().ok_or(VBAccumulatorError::CannotBeZero)?;

        // The following is an optimized version of the next block of commented code. The goal here was to do just
        // one MSM rather than `max_omega_size`
        let mut bases = Vec::new();
        let mut scalars = Vec::new();
        let scaled_powers_of_y =
            Omega::<G>::scaled_powers_of_y(element, &d_D_ij_inv, max_omega_size);
        for i in 0..max_omega_size {
            // Add ith coefficient of each `omega_t` after multiplying the coefficient by the factor in t_th position.
            for (t, omega) in omegas.iter().enumerate() {
                if omega.len() > i {
                    bases.push(*omega.coefficient(i));
                    scalars.push(omega_t_factors[t] * scaled_powers_of_y[i]);
                }
            }
        }
        // <powers_of_y, omega> * 1/d_D(x)
        let y_omega_ip = G::Group::msm_unchecked(&bases, &scalars);

        // // Add all omega_t vectors
        // let mut final_omega = Vec::<G::Group>::with_capacity(max_omega_size);
        // for i in 0..max_omega_size {
        //     // Add ith coefficient of each `omega_t` after multiplying the coefficient by the factor in t_th position.
        //     let mut bases = Vec::new();
        //     let mut scalars = Vec::new();
        //     for (t, omega) in omegas.iter().enumerate() {
        //         if omega.len() > i {
        //             bases.push(*omega.coefficient(i));
        //             scalars.push(omega_t_factors[t]);
        //         }
        //     }
        //     final_omega.push(VariableBaseMSM::multi_scalar_mul(&bases, &scalars));
        // }
        //
        // // <powers_of_y, omega>
        // let final_omega = Omega(G::Group::batch_normalization_into_affine(&final_omega));
        // // <powers_of_y, omega> * 1/d_D(x)
        // let y_omega_ip = final_omega.inner_product_with_scaled_powers_of_y(element, d_D_ij_inv);

        let d_A_times_d_D_inv = d_A_ij * d_D_ij_inv;

        let new_C = old_witness.mul_bigint(d_A_times_d_D_inv.into_bigint()) + y_omega_ip;
        Ok((d_A_times_d_D_inv, new_C.into_affine()))
    }
}

/// Witness to check membership
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct MembershipWitness<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

/// Witness to check non-membership
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct NonMembershipWitness<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub d: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub C: G,
}

impl<G: AffineRepr> AsRef<G> for MembershipWitness<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<G> for NonMembershipWitness<G> {
    fn as_ref(&self) -> &G {
        &self.C
    }
}

impl<G: AffineRepr> From<G> for MembershipWitness<G> {
    fn from(value: G) -> Self {
        Self(value)
    }
}

impl<G> Witness<G> for MembershipWitness<G> where G: AffineRepr {}

impl<G> MembershipWitness<G>
where
    G: AffineRepr,
{
    /// Update a membership witness after an element is added to the accumulator. Needs the
    /// accumulator before the addition was done.
    pub fn update_after_addition(
        &self,
        member: &G::ScalarField,
        addition: &G::ScalarField,
        old_accumulator: &G,
    ) -> Self {
        // (addition - element) * C + V
        let (_, new_witness) =
            Self::compute_update_after_addition(member, addition, &self.0, old_accumulator);
        Self(new_witness)
    }

    /// Update a membership witness after an element is removed from the accumulator. Needs the
    /// accumulator after the removal was done.
    pub fn update_after_removal(
        &self,
        member: &G::ScalarField,
        removal: &G::ScalarField,
        new_accumulator: &G,
    ) -> Result<Self, VBAccumulatorError> {
        // 1/(removal - element) * (C - V)
        let (_, new_witness) =
            Self::compute_update_after_removal(member, removal, &self.0, new_accumulator)?;
        Ok(Self(new_witness))
    }

    /// Compute an update to several witnesses after adding a batch of elements in the accumulator.
    /// Expects the accumulator value before the addition and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_additions(
        additions: &[G::ScalarField],
        members: &[G::ScalarField],
        old_witnesses: &[MembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<Self>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.0).collect();
        let (_, wits) = Self::compute_update_using_secret_key_after_batch_additions(
            additions,
            members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::affine_points_to_membership_witnesses(wits))
    }

    /// Compute an update to several witnesses after removing a batch of elements from the accumulator.
    /// Expects the accumulator value after the removal and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_removals(
        removals: &[G::ScalarField],
        members: &[G::ScalarField],
        old_witnesses: &[MembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<MembershipWitness<G>>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.0).collect();
        let (_, wits) = Self::compute_update_using_secret_key_after_batch_removals(
            removals,
            members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::affine_points_to_membership_witnesses(wits))
    }

    /// Compute an update to several witnesses after adding and removing batches of elements from the accumulator.
    /// Expects the accumulator value before the update and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_updates(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        members: &[G::ScalarField],
        old_witnesses: &[MembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<MembershipWitness<G>>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.0).collect();
        let (_, wits) = Self::compute_update_using_secret_key_after_batch_updates(
            additions,
            removals,
            members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::affine_points_to_membership_witnesses(wits))
    }

    /// Compute an update to the witness after adding and removing batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager.
    pub fn update_using_public_info_after_batch_updates(
        &self,
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        omega: &Omega<G>,
        member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new_C) = Self::compute_update_using_public_info_after_batch_updates(
            additions, removals, omega, member, &self.0,
        )?;
        Ok(Self(new_C))
    }

    /// Compute an update to the witness after adding and removing several batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager for each batch.
    pub fn update_using_public_info_after_multiple_batch_updates(
        &self,
        updates_and_omegas: Vec<(&[G::ScalarField], &[G::ScalarField], &Omega<G>)>,
        member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new_C) = Self::compute_update_using_public_info_after_multiple_batch_updates(
            updates_and_omegas,
            member,
            &self.0,
        )?;
        Ok(Self(new_C))
    }

    pub fn projective_points_to_membership_witnesses(
        wits: Vec<G::Group>,
    ) -> Vec<MembershipWitness<G>> {
        let wits_affine = G::Group::normalize_batch(&wits);
        Self::affine_points_to_membership_witnesses(wits_affine)
    }

    pub fn affine_points_to_membership_witnesses(wits: Vec<G>) -> Vec<MembershipWitness<G>> {
        cfg_into_iter!(wits).map(MembershipWitness).collect()
    }

    pub fn randomize(&self, randomizer: &G::ScalarField) -> Self {
        Self((self.0 * randomizer).into_affine())
    }
}

impl<G> Witness<G> for NonMembershipWitness<G> where G: AffineRepr {}

impl<G> NonMembershipWitness<G>
where
    G: AffineRepr,
{
    /// Update a non-membership witness after an element is added to the accumulator. Needs the
    /// accumulator before the addition was done.
    pub fn update_after_addition(
        &self,
        non_member: &G::ScalarField,
        addition: &G::ScalarField,
        old_accumulator: &G,
    ) -> Self {
        let (d_factor, C) =
            Self::compute_update_after_addition(non_member, addition, &self.C, old_accumulator);

        // (addition - element) * self.d
        let d = d_factor * self.d;

        Self { C, d }
    }

    /// Update a non-membership witness after an element is removed from the accumulator. Needs the
    /// accumulator after the removal was done.
    pub fn update_after_removal(
        &self,
        non_member: &G::ScalarField,
        removal: &G::ScalarField,
        new_accumulator: &G,
    ) -> Result<Self, VBAccumulatorError> {
        let (d_factor, C) =
            Self::compute_update_after_removal(non_member, removal, &self.C, new_accumulator)?;

        // 1/(removal - element) * self.d
        let d = d_factor * self.d;

        Ok(Self { C, d })
    }

    /// Compute an update to several witnesses after adding a batch of elements in the accumulator.
    /// Expects the accumulator value before the addition and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_additions(
        additions: &[G::ScalarField],
        non_members: &[G::ScalarField],
        old_witnesses: &[NonMembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<Self>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.C).collect();
        let (d_factor, wits) = Self::compute_update_using_secret_key_after_batch_additions(
            additions,
            non_members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::prepare_non_membership_witnesses(
            d_factor,
            wits,
            old_witnesses,
        ))
    }

    /// Compute an update to several witnesses after removing a batch of elements from the accumulator.
    /// Expects the accumulator value after the removal and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_removals(
        removals: &[G::ScalarField],
        non_members: &[G::ScalarField],
        old_witnesses: &[NonMembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<Self>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.C).collect();
        let (d_factor, wits) = Self::compute_update_using_secret_key_after_batch_removals(
            removals,
            non_members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::prepare_non_membership_witnesses(
            d_factor,
            wits,
            old_witnesses,
        ))
    }

    /// Compute an update to several witnesses after adding and removing batches of elements from the accumulator.
    /// Expects the accumulator value before the update and knowledge of the secret key. Intended to be
    /// used by the manager
    pub fn update_using_secret_key_after_batch_updates(
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        non_members: &[G::ScalarField],
        old_witnesses: &[NonMembershipWitness<G>],
        old_accumulator: &G,
        sk: &SecretKey<G::ScalarField>,
    ) -> Result<Vec<Self>, VBAccumulatorError> {
        let old: Vec<G> = cfg_iter!(old_witnesses).map(|w| w.C).collect();
        let (d_factor, wits) = Self::compute_update_using_secret_key_after_batch_updates(
            additions,
            removals,
            non_members,
            &old,
            old_accumulator,
            sk,
        )?;
        Ok(Self::prepare_non_membership_witnesses(
            d_factor,
            wits,
            old_witnesses,
        ))
    }

    /// Compute an update to the witness after adding and removing batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager.
    pub fn update_using_public_info_after_batch_updates(
        &self,
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        omega: &Omega<G>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (d_factor, C) = Self::compute_update_using_public_info_after_batch_updates(
            additions, removals, omega, non_member, &self.C,
        )?;
        Ok(Self {
            d: d_factor * self.d,
            C,
        })
    }

    /// Compute an update to the witness after adding and removing several batches of elements from the accumulator.
    /// Expects the update-info (`Omega`) published by the manager for each batch.
    pub fn update_using_public_info_after_multiple_batch_updates(
        &self,
        updates_and_omegas: Vec<(&[G::ScalarField], &[G::ScalarField], &Omega<G>)>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (d_factor, C) = Self::compute_update_using_public_info_after_multiple_batch_updates(
            updates_and_omegas,
            non_member,
            &self.C,
        )?;
        Ok(Self {
            d: d_factor * self.d,
            C,
        })
    }

    pub fn randomize(&self, randomizer: &G::ScalarField) -> Self {
        Self {
            d: self.d * randomizer,
            C: (self.C * randomizer).into_affine(),
        }
    }

    fn prepare_non_membership_witnesses(
        d_factor: Vec<G::ScalarField>,
        new_wits: Vec<G>,
        old_wits: &[Self],
    ) -> Vec<Self> {
        cfg_into_iter!(d_factor)
            .zip(cfg_into_iter!(new_wits))
            .enumerate()
            .map(|(i, (d, C))| Self {
                d: old_wits[i].d * d,
                C,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    use crate::{
        persistence::State,
        positive::{tests::setup_positive_accum, Accumulator, PositiveAccumulator},
        setup::{Keypair, SetupParams},
        test_serialization,
        universal::{tests::setup_universal_accum, UniversalAccumulator},
    };

    #[test]
    fn single_membership_witness_update_positive_accumulator() {
        // Test to update membership witness after single addition or removal
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        let mut elems = vec![];
        let mut witnesses = vec![];
        let count = 10;

        let mut update_post_add_duration = Duration::default();
        let mut update_post_add_counter = 0;
        let mut update_post_remove_duration = Duration::default();
        let mut update_post_remove_counter = 0;

        // Add a new element, update witness of an existing member and check that the new witness is valid
        for i in 0..count {
            let elem = Fr::rand(&mut rng);
            let new_accumulator = accumulator
                .add(elem, &keypair.secret_key, &mut state)
                .unwrap();
            let wit = new_accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let verification_accumulator =
                PositiveAccumulator::from_accumulated(*new_accumulator.value());
            assert!(verification_accumulator.verify_membership(
                &elem,
                &wit,
                &keypair.public_key,
                &params
            ));
            elems.push(elem);
            witnesses.push(wit);

            // Update witness of each element before i, going backwards
            if i > 0 {
                let mut j = i;
                while j > 0 {
                    let verification_accumulator =
                        PositiveAccumulator::from_accumulated(*new_accumulator.value());
                    // Verification fails with old witness
                    assert!(!verification_accumulator.verify_membership(
                        &elems[j - 1],
                        &witnesses[j - 1],
                        &keypair.public_key,
                        &params
                    ));

                    let start = Instant::now();
                    // Update witness
                    let new_wit = witnesses[j - 1].update_after_addition(
                        &elems[j - 1],
                        &elems[i],
                        accumulator.value(),
                    );
                    update_post_add_duration += start.elapsed();
                    update_post_add_counter += 1;

                    // Verification succeeds with new witness
                    assert!(verification_accumulator.verify_membership(
                        &elems[j - 1],
                        &new_wit,
                        &keypair.public_key,
                        &params
                    ));
                    witnesses[j - 1] = new_wit;
                    j -= 1;
                }
            }
            accumulator = new_accumulator;
        }

        // Remove an existing element, update witness of an existing member and check that the new witness is valid
        let mut i = count - 1;
        loop {
            let new_accumulator = accumulator
                .remove(&elems[i], &keypair.secret_key, &mut state)
                .unwrap();
            let verification_accumulator =
                PositiveAccumulator::from_accumulated(*new_accumulator.value());
            let mut j = i;
            while j > 0 {
                // Update witness of each element before i, going backwards
                assert!(!verification_accumulator.verify_membership(
                    &elems[j - 1],
                    &witnesses[j - 1],
                    &keypair.public_key,
                    &params
                ));

                let start = Instant::now();
                let new_wit = witnesses[j - 1]
                    .update_after_removal(&elems[j - 1], &elems[i], new_accumulator.value())
                    .unwrap();
                update_post_remove_duration += start.elapsed();
                update_post_remove_counter += 1;

                assert!(verification_accumulator.verify_membership(
                    &elems[j - 1],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                witnesses[j - 1] = new_wit;
                j -= 1;
            }
            accumulator = new_accumulator;
            if i == 0 {
                break;
            }
            i -= 1;
        }

        println!(
            "Positive Accumulator: Single update witness time after {} additions {:?}",
            update_post_add_counter, update_post_add_duration
        );
        println!(
            "Positive Accumulator: Single update witness time after {} removals {:?}",
            update_post_remove_counter, update_post_remove_duration
        );
    }

    #[test]
    fn single_witness_update_universal_accumulator() {
        // Test to update non-membership witness after single addition or removal
        let max = 1000;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, initial_elements, mut state) =
            setup_universal_accum(&mut rng, max);

        let mut non_members = vec![];
        let mut non_membership_witnesses = vec![];

        let verification_accumulator = UniversalAccumulator::from_accumulated(*accumulator.value());
        let n = 100;
        for _ in 0..n {
            let elem = Fr::rand(&mut rng);
            let wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            assert!(verification_accumulator.verify_non_membership(
                &elem,
                &wit,
                &keypair.public_key,
                &params
            ));
            non_members.push(elem);
            non_membership_witnesses.push(wit);
        }

        let mut update_post_add_duration = Duration::default();
        let mut update_post_add_counter = 0;
        let mut update_post_remove_duration = Duration::default();
        let mut update_post_remove_counter = 0;

        let mut added_elems = vec![];

        // Add a new element, update witness of non-member and check that the new witness is valid
        for i in 0..100 {
            let elem = Fr::rand(&mut rng);
            let new_accumulator = accumulator
                .add(elem, &keypair.secret_key, &initial_elements, &mut state)
                .unwrap();
            added_elems.push(elem);

            let verification_accumulator =
                UniversalAccumulator::from_accumulated(*new_accumulator.value());
            for j in 0..n {
                assert!(!verification_accumulator.verify_non_membership(
                    &non_members[j],
                    &non_membership_witnesses[j],
                    &keypair.public_key,
                    &params
                ));

                let start = Instant::now();
                let new_wit = non_membership_witnesses[j].update_after_addition(
                    &non_members[j],
                    &added_elems[i],
                    accumulator.value(),
                );
                update_post_add_duration += start.elapsed();
                update_post_add_counter += 1;

                assert!(verification_accumulator.verify_non_membership(
                    &non_members[j],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                non_membership_witnesses[j] = new_wit;
            }
            accumulator = new_accumulator;
        }

        // Remove an existing element, update witness of a non-member and check that the new witness is valid
        for i in 0..100 {
            accumulator = accumulator
                .remove(
                    &added_elems[i],
                    &keypair.secret_key,
                    &initial_elements,
                    &mut state,
                )
                .unwrap();
            let verification_accumulator =
                UniversalAccumulator::from_accumulated(*accumulator.value());
            for j in 0..n {
                assert!(!verification_accumulator.verify_non_membership(
                    &non_members[j],
                    &non_membership_witnesses[j],
                    &keypair.public_key,
                    &params
                ));

                let start = Instant::now();
                let new_wit = non_membership_witnesses[j]
                    .update_after_removal(&non_members[j], &added_elems[i], accumulator.value())
                    .unwrap();
                update_post_remove_duration += start.elapsed();
                update_post_remove_counter += 1;

                assert!(verification_accumulator.verify_non_membership(
                    &non_members[j],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                non_membership_witnesses[j] = new_wit;
            }
        }

        println!(
            "Universal Accumulator: Single update witness time after {} additions {:?}",
            update_post_add_counter, update_post_add_duration
        );
        println!(
            "Universal Accumulator: Single update witness time after {} removals {:?}",
            update_post_remove_counter, update_post_remove_duration
        );
    }

    #[test]
    fn batch_updates_witnesses_positive_accumulator() {
        // Accumulator manager who knows the secret key batch updates witnesses

        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        let additions_1: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_2: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let additions_3: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_1[i])
            .collect();

        // Add elements in `additions_1`, compute witnesses for them, then add `additions_2` and update witnesses for elements in additions_1
        accumulator = accumulator
            .add_batch(additions_1.clone(), &keypair.secret_key, &mut state)
            .unwrap();
        let witnesses_1 = accumulator
            .get_membership_witnesses_for_batch(&additions_1, &keypair.secret_key, &state)
            .unwrap();
        let verification_accumulator = PositiveAccumulator::from_accumulated(*accumulator.value());
        for i in 0..witnesses_1.len() {
            assert!(verification_accumulator.verify_membership(
                &additions_1[i],
                &witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        let accumulator_2 = accumulator
            .add_batch(additions_2.clone(), &keypair.secret_key, &mut state)
            .unwrap();
        let verification_accumulator =
            PositiveAccumulator::from_accumulated(*accumulator_2.value());
        for i in 0..witnesses_1.len() {
            assert!(!verification_accumulator.verify_membership(
                &additions_1[i],
                &witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        let start = Instant::now();
        let new_wits = MembershipWitness::update_using_secret_key_after_batch_additions(
            &additions_2,
            &additions_1,
            &witnesses_1,
            accumulator.value(),
            &keypair.secret_key,
        )
        .unwrap();
        println!(
            "Updating {} membership witnesses after {} additions takes {:?}",
            additions_1.len(),
            additions_2.len(),
            start.elapsed()
        );

        assert_eq!(new_wits.len(), witnesses_1.len());
        for i in 0..new_wits.len() {
            assert!(verification_accumulator.verify_membership(
                &additions_1[i],
                &new_wits[i],
                &keypair.public_key,
                &params
            ));
        }

        // Compute membership witness for elements in `additions_2`, remove elements in `removals` and update witnesses for `additions_2`
        let witnesses_3 = accumulator_2
            .get_membership_witnesses_for_batch(&additions_2, &keypair.secret_key, &state)
            .unwrap();
        for i in 0..witnesses_3.len() {
            assert!(verification_accumulator.verify_membership(
                &additions_2[i],
                &witnesses_3[i],
                &keypair.public_key,
                &params
            ));
        }

        let accumulator_3 = accumulator_2
            .remove_batch(&removals, &keypair.secret_key, &mut state)
            .unwrap();
        let verification_accumulator =
            PositiveAccumulator::from_accumulated(*accumulator_3.value());
        for i in 0..witnesses_3.len() {
            assert!(!verification_accumulator.verify_membership(
                &additions_2[i],
                &witnesses_3[i],
                &keypair.public_key,
                &params
            ));
        }

        let start = Instant::now();
        let new_wits = MembershipWitness::update_using_secret_key_after_batch_removals(
            &removals,
            &additions_2,
            &witnesses_3,
            accumulator_2.value(),
            &keypair.secret_key,
        )
        .unwrap();
        println!(
            "Updating {} membership witnesses after {} removals takes {:?}",
            additions_2.len(),
            removals.len(),
            start.elapsed()
        );

        assert_eq!(new_wits.len(), witnesses_3.len());
        for i in 0..new_wits.len() {
            assert!(verification_accumulator.verify_membership(
                &additions_2[i],
                &new_wits[i],
                &keypair.public_key,
                &params
            ));
        }

        // Compute membership witness for elements remaining from `additions_1`, remove elements in `additions_2`, add elements in `addition_3`
        // and update witnesses for the remaining elements
        let mut remaining = additions_1;
        for e in removals {
            remaining.retain(|&x| x != e);
        }

        let witnesses_4 = accumulator_3
            .get_membership_witnesses_for_batch(&remaining, &keypair.secret_key, &state)
            .unwrap();
        for i in 0..witnesses_4.len() {
            assert!(verification_accumulator.verify_membership(
                &remaining[i],
                &witnesses_4[i],
                &keypair.public_key,
                &params
            ));
        }

        let accumulator_3_cloned = accumulator_3.clone();
        let mut state_cloned = state.clone();

        /// Update an accumulator with a batch of updates, update existing witnesses of given elements and check that new witnesses are valid
        fn check_batch_witness_update_using_secret_key(
            current_accm: &PositiveAccumulator<Bls12_381>,
            additions: Vec<Fr>,
            removals: &[Fr],
            elements: &[Fr],
            old_witnesses: &[MembershipWitness<G1Affine>],
            keypair: &Keypair<Bls12_381>,
            params: &SetupParams<Bls12_381>,
            state: &mut dyn State<Fr>,
        ) -> (
            PositiveAccumulator<Bls12_381>,
            Vec<MembershipWitness<G1Affine>>,
        ) {
            let accumulator_new = current_accm
                .batch_updates(additions.clone(), removals, &keypair.secret_key, state)
                .unwrap();
            let verification_accumulator =
                PositiveAccumulator::from_accumulated(*accumulator_new.value());
            for i in 0..old_witnesses.len() {
                assert!(!verification_accumulator.verify_membership(
                    &elements[i],
                    &old_witnesses[i],
                    &keypair.public_key,
                    params
                ));
            }

            let start = Instant::now();
            let new_witnesses = MembershipWitness::update_using_secret_key_after_batch_updates(
                &additions,
                removals,
                elements,
                old_witnesses,
                current_accm.value(),
                &keypair.secret_key,
            )
            .unwrap();
            println!(
                "Updating {} membership witnesses after {} additions and {} removals takes {:?}",
                elements.len(),
                additions.len(),
                removals.len(),
                start.elapsed()
            );

            assert_eq!(new_witnesses.len(), old_witnesses.len());
            for i in 0..new_witnesses.len() {
                assert!(verification_accumulator.verify_membership(
                    &elements[i],
                    &new_witnesses[i],
                    &keypair.public_key,
                    params
                ));
            }
            (accumulator_new, new_witnesses)
        }

        let (accumulator_4, _) = check_batch_witness_update_using_secret_key(
            &accumulator_3,
            additions_3.clone(),
            &additions_2,
            &remaining,
            &witnesses_4,
            &keypair,
            &params,
            &mut state,
        );
        let verification_accumulator_4 =
            PositiveAccumulator::from_accumulated(*accumulator_4.value());

        let (accumulator_4_new, witnesses_6) = check_batch_witness_update_using_secret_key(
            &accumulator_3_cloned,
            additions_3.clone(),
            &[],
            &remaining,
            &witnesses_4,
            &keypair,
            &params,
            &mut state_cloned,
        );
        let verification_accumulator_4_new =
            PositiveAccumulator::from_accumulated(*accumulator_4_new.value());

        let (accumulator_5_new, _) = check_batch_witness_update_using_secret_key(
            &accumulator_4_new,
            vec![],
            &additions_2,
            &remaining,
            &witnesses_6,
            &keypair,
            &params,
            &mut state_cloned,
        );
        let verification_accumulator_5_new =
            PositiveAccumulator::from_accumulated(*accumulator_5_new.value());

        // Public updates to witnesses - each one in `remaining` updates his witness using publicly published info from manager
        let omega_both = Omega::new(
            &additions_3,
            &additions_2,
            accumulator_3.value(),
            &keypair.secret_key,
        );
        test_serialization!(Omega<<Bls12_381 as Pairing>::G1Affine>, omega_both);

        let omega_add_only = Omega::new(
            &additions_3,
            &[],
            accumulator_3_cloned.value(),
            &keypair.secret_key,
        );
        test_serialization!(Omega<<Bls12_381 as Pairing>::G1Affine>, omega_add_only);

        let omega_remove_only = Omega::new(
            &[],
            &additions_2,
            accumulator_4_new.value(),
            &keypair.secret_key,
        );
        test_serialization!(Omega<<Bls12_381 as Pairing>::G1Affine>, omega_remove_only);

        for i in 0..remaining.len() {
            let new_wit = witnesses_4[i]
                .update_using_public_info_after_batch_updates(
                    &additions_3,
                    &additions_2,
                    &omega_both,
                    &remaining[i],
                )
                .unwrap();
            Omega::check(
                &additions_3,
                &additions_2,
                &remaining[i],
                accumulator_3.value(),
                &keypair.secret_key,
            );
            assert!(verification_accumulator_4.verify_membership(
                &remaining[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));

            let new_wit = witnesses_4[i]
                .update_using_public_info_after_batch_updates(
                    &additions_3,
                    &[],
                    &omega_add_only,
                    &remaining[i],
                )
                .unwrap();
            Omega::check(
                &additions_3,
                &[],
                &remaining[i],
                accumulator_3_cloned.value(),
                &keypair.secret_key,
            );
            assert!(verification_accumulator_4_new.verify_membership(
                &remaining[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));

            let new_wit = witnesses_6[i]
                .update_using_public_info_after_batch_updates(
                    &[],
                    &additions_2,
                    &omega_remove_only,
                    &remaining[i],
                )
                .unwrap();
            Omega::check(
                &[],
                &additions_2,
                &remaining[i],
                accumulator_4_new.value(),
                &keypair.secret_key,
            );
            assert!(verification_accumulator_5_new.verify_membership(
                &remaining[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }
    }

    #[test]
    fn update_witnesses_after_multiple_batch_updates_positive_accumulator() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        let mut elems = vec![];
        for _ in 0..10 {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator
                .add(elem, &keypair.secret_key, &mut state)
                .unwrap();
            elems.push(elem)
        }

        let witnesses = accumulator
            .get_membership_witnesses_for_batch(&elems, &keypair.secret_key, &state)
            .unwrap();
        for i in 0..10 {
            assert!(accumulator.verify_membership(
                &elems[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        let additions_1: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_2: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_3: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let removals_1: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_1[i])
            .collect();
        let removals_2: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_2[i])
            .collect();
        let removals_3: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_3[i])
            .collect();

        let mut accumulator_1 = accumulator
            .add_batch(additions_1.clone(), &keypair.secret_key, &mut state)
            .unwrap();
        accumulator_1 = accumulator_1
            .remove_batch(&removals_1, &keypair.secret_key, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(!accumulator_1.verify_membership(
                &elems[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        let omega_1 = Omega::new(
            &additions_1,
            &removals_1,
            accumulator.value(),
            &keypair.secret_key,
        );

        for (i, wit) in witnesses.iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(
                    vec![(additions_1.as_slice(), removals_1.as_slice(), &omega_1)],
                    &elems[i],
                )
                .unwrap();
            assert!(accumulator_1.verify_membership(
                &elems[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }

        let mut accumulator_2 = accumulator_1
            .add_batch(additions_2.clone(), &keypair.secret_key, &mut state)
            .unwrap();
        accumulator_2 = accumulator_2
            .remove_batch(&removals_2, &keypair.secret_key, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(!accumulator_2.verify_membership(
                &elems[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        let omega_2 = Omega::new(
            &additions_2,
            &removals_2,
            accumulator_1.value(),
            &keypair.secret_key,
        );

        for (i, wit) in witnesses.iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(
                    vec![
                        (additions_1.as_slice(), removals_1.as_slice(), &omega_1),
                        (additions_2.as_slice(), removals_2.as_slice(), &omega_2),
                    ],
                    &elems[i],
                )
                .unwrap();
            assert!(accumulator_2.verify_membership(
                &elems[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }

        let mut accumulator_3 = accumulator_2
            .add_batch(additions_3.clone(), &keypair.secret_key, &mut state)
            .unwrap();
        accumulator_3 = accumulator_3
            .remove_batch(&removals_3, &keypair.secret_key, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(!accumulator_3.verify_membership(
                &elems[i],
                &witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        let omega_3 = Omega::new(
            &additions_3,
            &removals_3,
            accumulator_2.value(),
            &keypair.secret_key,
        );

        for (i, wit) in witnesses.into_iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(
                    vec![
                        (additions_1.as_slice(), removals_1.as_slice(), &omega_1),
                        (additions_2.as_slice(), removals_2.as_slice(), &omega_2),
                        (additions_3.as_slice(), removals_3.as_slice(), &omega_3),
                    ],
                    &elems[i],
                )
                .unwrap();
            assert!(accumulator_3.verify_membership(
                &elems[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }
    }

    /// Create accumulator and check whether multiple batch updates can be applied to a witness
    fn multiple_batches_check(
        member: &Fr,
        initial_additions: Vec<Fr>,
        additions: Vec<Vec<Fr>>,
        removals: Vec<Vec<Fr>>,
    ) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

        accumulator = accumulator
            .add_batch(initial_additions, &keypair.secret_key, &mut state)
            .unwrap();

        let mut omegas = vec![];

        // Witness that will be updated with multiple batches
        let wit = accumulator
            .get_membership_witness(member, &keypair.secret_key, &mut state)
            .unwrap();

        // This witness is updated with only 1 batch in each iteration of the loop below
        let mut wit_temp = wit.clone();

        for i in 0..additions.len() {
            let omega = Omega::new(
                &additions[i],
                &removals[i],
                accumulator.value(),
                &keypair.secret_key,
            );
            accumulator = accumulator
                .batch_updates(
                    additions[i].clone(),
                    &removals[i],
                    &keypair.secret_key,
                    &mut state,
                )
                .unwrap();

            wit_temp = wit_temp
                .update_using_public_info_after_batch_updates(
                    &additions[i],
                    &removals[i],
                    &omega,
                    member,
                )
                .unwrap();
            assert!(accumulator.verify_membership(member, &wit_temp, &keypair.public_key, &params));
            omegas.push(omega);
        }

        let mut updates_and_omegas = vec![];
        for i in 0..additions.len() {
            updates_and_omegas.push((additions[i].as_slice(), removals[i].as_slice(), &omegas[i]));
        }

        let new_wit = wit
            .update_using_public_info_after_multiple_batch_updates(updates_and_omegas, member)
            .unwrap();

        assert!(accumulator.verify_membership(member, &new_wit, &keypair.public_key, &params));
    }

    #[test]
    fn update_witnesses_after_multiple_batch_updates_positive_accumulator_1() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let e0 = Fr::rand(&mut rng);
        let e1 = Fr::rand(&mut rng);
        let e2 = Fr::rand(&mut rng);
        let e3 = Fr::rand(&mut rng);
        let e4 = Fr::rand(&mut rng);
        let e5 = Fr::rand(&mut rng);
        let e6 = Fr::rand(&mut rng);
        let e7 = Fr::rand(&mut rng);
        let e8 = Fr::rand(&mut rng);
        let e9 = Fr::rand(&mut rng);

        let initial_additions = vec![e0, e1, e2];
        let additions = vec![vec![e3, e4], vec![e5, e6], vec![e7, e8, e9]];
        let removals = vec![vec![e0, e1], vec![e3], vec![e4]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6], vec![e7, e8, e9]];
        let removals = vec![vec![e0, e1], vec![e3], vec![]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6], vec![e7, e8, e9]];
        let removals = vec![vec![e0, e1], vec![], vec![]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6], vec![e7, e8, e9]];
        let removals = vec![vec![e0, e1], vec![], vec![e3, e4, e5]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6], vec![e7, e8]];
        let removals = vec![vec![e0, e1], vec![e3], vec![e4]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6, e7]];
        let removals = vec![vec![e0, e1], vec![e3]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4], vec![e5, e6, e7]];
        let removals = vec![vec![e0, e1], vec![]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4, e5, e6, e7, e8, e9], vec![], vec![]];
        let removals = vec![vec![e0], vec![], vec![e1, e3, e4, e5]];
        multiple_batches_check(&e2, initial_additions.clone(), additions, removals);

        let additions = vec![vec![e3, e4, e5, e6, e7, e8, e9], vec![], vec![], vec![]];
        let removals = vec![vec![e0], vec![], vec![e1, e3, e4, e5], vec![e6, e7, e8, e9]];
        multiple_batches_check(&e2, initial_additions, additions, removals);
    }

    #[test]
    fn update_witnesses_after_multiple_batch_updates_positive_accumulator_2() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);
        let e0 = Fr::rand(&mut rng);

        let elements: Vec<Fr> = (0..12).map(|_| Fr::rand(&mut rng)).collect();

        accumulator = accumulator
            .add_batch(
                vec![e0, elements[0], elements[1]],
                &keypair.secret_key,
                &mut state,
            )
            .unwrap();

        let wit = accumulator
            .get_membership_witness(&e0, &keypair.secret_key, &mut state)
            .unwrap();

        let mut wit_temp = wit.clone();

        let mut omegas = vec![];
        let mut additions = vec![];
        let mut removals = vec![];
        for i in (2..10).step_by(2) {
            additions.push(vec![elements[i], elements[i + 1]]);
            removals.push(vec![elements[i - 2], elements[i - 1]]);
            let omega = Omega::new(
                additions.last().unwrap(),
                removals.last().unwrap(),
                accumulator.value(),
                &keypair.secret_key,
            );
            omegas.push(omega);
            accumulator = accumulator
                .batch_updates(
                    additions.last().unwrap().clone(),
                    removals.last().unwrap(),
                    &keypair.secret_key,
                    &mut state,
                )
                .unwrap();
            wit_temp = wit_temp
                .update_using_public_info_after_batch_updates(
                    additions.last().unwrap(),
                    removals.last().unwrap(),
                    omegas.last().unwrap(),
                    &e0,
                )
                .unwrap();
            assert!(accumulator.verify_membership(&e0, &wit_temp, &keypair.public_key, &params));
        }

        let new_wit = wit
            .update_using_public_info_after_multiple_batch_updates(
                vec![
                    (&additions[0], &removals[0], &omegas[0]),
                    (&additions[1], &removals[1], &omegas[1]),
                    (&additions[2], &removals[2], &omegas[2]),
                    (&additions[3], &removals[3], &omegas[3]),
                ],
                &e0,
            )
            .unwrap();

        assert!(accumulator.verify_membership(&e0, &new_wit, &keypair.public_key, &params));
    }

    #[test]
    fn batch_updates_witnesses_universal_accumulator() {
        // Accumulator manager who knows the secret key batch updates witnesses

        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, accumulator, initial_elems, mut state) =
            setup_universal_accum(&mut rng, max);

        let additions_1: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_2: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_1[i])
            .collect();

        let mut non_members = vec![];
        let mut non_membership_witnesses = vec![];

        let n = 10;
        for _ in 0..n {
            let elem = Fr::rand(&mut rng);
            let wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &state, &params)
                .unwrap();
            non_members.push(elem);
            non_membership_witnesses.push(wit);
        }

        // Add elements in `additions_1`, batch update non-membership witnesses
        let accumulator_1 = accumulator
            .add_batch(
                additions_1.clone(),
                &keypair.secret_key,
                &initial_elems,
                &mut state,
            )
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_1.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        let non_membership_witnesses_1 =
            NonMembershipWitness::update_using_secret_key_after_batch_additions(
                &additions_1,
                &non_members,
                &non_membership_witnesses,
                accumulator.value(),
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            non_membership_witnesses.len(),
            non_membership_witnesses_1.len()
        );
        for i in 0..n {
            assert!(accumulator_1.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        // Remove elements from `removals`, batch update non-membership witnesses
        let accumulator_2 = accumulator_1
            .remove_batch(&removals, &keypair.secret_key, &initial_elems, &mut state)
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_2.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        let non_membership_witnesses_2 =
            NonMembershipWitness::update_using_secret_key_after_batch_removals(
                &removals,
                &non_members,
                &non_membership_witnesses_1,
                accumulator_1.value(),
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            non_membership_witnesses_1.len(),
            non_membership_witnesses_2.len()
        );
        for i in 0..n {
            assert!(accumulator_2.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_2[i],
                &keypair.public_key,
                &params
            ));
        }

        // Remove elements remaining from `additions_1`, add elements in `additions_2`
        // and update witnesses for the absent elements
        let mut remaining = additions_1;
        for e in removals {
            remaining.retain(|&x| x != e);
        }

        let accumulator_3 = accumulator_2
            .batch_updates(
                additions_2.clone(),
                &remaining,
                &keypair.secret_key,
                &initial_elems,
                &mut state,
            )
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_3.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_2[i],
                &keypair.public_key,
                &params
            ));
        }

        let non_membership_witnesses_3 =
            NonMembershipWitness::update_using_secret_key_after_batch_updates(
                &additions_2,
                &remaining,
                &non_members,
                &non_membership_witnesses_2,
                accumulator_2.value(),
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            non_membership_witnesses_2.len(),
            non_membership_witnesses_3.len()
        );
        for i in 0..n {
            assert!(accumulator_3.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_3[i],
                &keypair.public_key,
                &params
            ));
        }

        // Public updates to witnesses - each one in `remaining` updates his witness using publicly published info from manager
        let omega = Omega::new(
            &additions_2,
            &remaining,
            accumulator_2.value(),
            &keypair.secret_key,
        );

        for i in 0..non_members.len() {
            let new_wit = non_membership_witnesses_2[i]
                .update_using_public_info_after_batch_updates(
                    &additions_2,
                    &remaining,
                    &omega,
                    &non_members[i],
                )
                .unwrap();
            Omega::check(
                &additions_2,
                &remaining,
                &non_members[i],
                accumulator_2.value(),
                &keypair.secret_key,
            );
            assert!(accumulator_3.verify_non_membership(
                &non_members[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }
    }

    #[test]
    fn timing_public_batch_updates() {
        let max = 100010;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, initial_elems, mut state) =
            setup_universal_accum(&mut rng, max);

        let member = Fr::rand(&mut rng);
        let non_member = Fr::rand(&mut rng);

        accumulator = accumulator
            .add(member, &keypair.secret_key, &initial_elems, &mut state)
            .unwrap();

        let m_wit_initial = accumulator
            .get_membership_witness(&member, &keypair.secret_key, &state)
            .unwrap();
        let nm_wit_initial = accumulator
            .get_non_membership_witness(&non_member, &keypair.secret_key, &state, &params)
            .unwrap();

        let mut m_wit = m_wit_initial.clone();
        let mut nm_wit = nm_wit_initial.clone();

        let mut batched_public_info = vec![];

        let iterations = 1000;
        let batch_size = 100;
        let mut omega_add_duration = Duration::default();
        let mut omega_remove_duration = Duration::default();
        let mut membership_add_duration = Duration::default();
        let mut membership_remove_duration = Duration::default();
        let mut non_membership_add_duration = Duration::default();
        let mut non_membership_remove_duration = Duration::default();
        for i in 0..iterations {
            println!("Iteration {} starts", i);

            let updates = (0..batch_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            let start = Instant::now();
            let omega_addition =
                Omega::new(&updates, &[], accumulator.value(), &keypair.secret_key);
            let end = start.elapsed();
            omega_add_duration += end;

            // println!("Omega for {} additions takes {:?}", batch_size, end);

            batched_public_info.push((updates.clone(), vec![], omega_addition.clone()));

            accumulator = accumulator
                .add_batch(
                    updates.clone(),
                    &keypair.secret_key,
                    &initial_elems,
                    &mut state,
                )
                .unwrap();

            let start = Instant::now();
            m_wit = m_wit
                .update_using_public_info_after_batch_updates(
                    &updates,
                    &[],
                    &omega_addition,
                    &member,
                )
                .unwrap();
            let end = start.elapsed();
            membership_add_duration += end;
            println!(
                "Membership witness update for {} additions takes {:?}",
                batch_size, end
            );

            assert!(accumulator.verify_membership(&member, &m_wit, &keypair.public_key, &params));

            let start = Instant::now();
            nm_wit = nm_wit
                .update_using_public_info_after_batch_updates(
                    &updates,
                    &[],
                    &omega_addition,
                    &non_member,
                )
                .unwrap();
            let end = start.elapsed();
            non_membership_add_duration += end;
            println!(
                "Non-membership witness update for {} additions takes {:?}",
                batch_size, end
            );

            assert!(accumulator.verify_non_membership(
                &non_member,
                &nm_wit,
                &keypair.public_key,
                &params
            ));

            // ------------------------------Removal-------------------------

            let start = Instant::now();
            let omega_removal = Omega::new(&[], &updates, accumulator.value(), &keypair.secret_key);
            let end = start.elapsed();
            omega_remove_duration += end;

            // println!("Omega for {} removals takes {:?}", batch_size, end);

            batched_public_info.push((vec![], updates.clone(), omega_removal.clone()));

            accumulator = accumulator
                .remove_batch(&updates, &keypair.secret_key, &initial_elems, &mut state)
                .unwrap();

            let start = Instant::now();
            m_wit = m_wit
                .update_using_public_info_after_batch_updates(
                    &[],
                    &updates,
                    &omega_removal,
                    &member,
                )
                .unwrap();
            let end = start.elapsed();
            membership_remove_duration += end;
            println!(
                "Membership witness update for {} removals takes {:?}",
                batch_size, end
            );

            assert!(accumulator.verify_membership(&member, &m_wit, &keypair.public_key, &params));

            let start = Instant::now();
            nm_wit = nm_wit
                .update_using_public_info_after_batch_updates(
                    &[],
                    &updates,
                    &omega_removal,
                    &non_member,
                )
                .unwrap();
            let end = start.elapsed();
            non_membership_remove_duration += end;
            println!(
                "Non-membership witness update for {} removals takes {:?}",
                batch_size, end
            );

            assert!(accumulator.verify_non_membership(
                &non_member,
                &nm_wit,
                &keypair.public_key,
                &params
            ));

            println!("Iteration {} ends", i);
        }

        let updates_and_omegas = batched_public_info
            .iter()
            .map(|(a, r, o)| (a.as_slice(), r.as_slice(), o))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let new_m_wit = m_wit_initial
            .update_using_public_info_after_multiple_batch_updates(
                updates_and_omegas.clone(),
                &member,
            )
            .unwrap();
        let mem_wit_update_multiple_time = start.elapsed();

        assert!(accumulator.verify_membership(&member, &new_m_wit, &keypair.public_key, &params));

        let start = Instant::now();
        let new_nm_wit = nm_wit_initial
            .update_using_public_info_after_multiple_batch_updates(updates_and_omegas, &non_member)
            .unwrap();
        let non_mem_wit_update_multiple_time = start.elapsed();

        assert!(accumulator.verify_non_membership(
            &non_member,
            &new_nm_wit,
            &keypair.public_key,
            &params
        ));

        println!();
        println!("---------------------------------------");
        println!();
        println!(
            "Witness update timings for {} iterations each of batch size {}",
            iterations, batch_size
        );
        println!("Omega for batch additions: {:?}", omega_add_duration);
        println!(
            "Membership witness for batch additions: {:?}",
            membership_add_duration
        );
        println!(
            "Non-membership witness for batch additions: {:?}",
            non_membership_add_duration
        );
        println!("Omega for batch removals: {:?}", omega_remove_duration);
        println!(
            "Membership witness for batch removals: {:?}",
            membership_remove_duration
        );
        println!(
            "Non-membership witness for batch removals: {:?}",
            non_membership_remove_duration
        );

        let total = iterations * batch_size;
        println!(
            "Membership witness for all batch additions ({}x{}={}) and removals ({}x{}={}) in {} updates: {:?}",
            iterations,
            batch_size,
            total,
            iterations,
            batch_size,
            total,
            batched_public_info.len(),
            mem_wit_update_multiple_time
        );
        println!("Non-membership witness for all batch additions ({}x{}={}) and removals ({}x{}={})in {} updates: {:?}", iterations, batch_size, total, iterations, batch_size, total, batched_public_info.len(), non_mem_wit_update_multiple_time);
    }
}
