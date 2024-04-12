use crate::{
    error::VBAccumulatorError,
    kb_universal_accumulator::accumulator::KBUniversalAccumulator,
    positive::Accumulator,
    prelude::SecretKey,
    witness::{MembershipWitness, Witness},
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{batch_inversion, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, vec, vec::Vec};

use crate::prelude::Omega;
use dock_crypto_utils::msm::WindowTable;

use dock_crypto_utils::{cfg_iter_sum, ff::inner_product};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
#[serde(bound = "")]
pub struct KBUniversalAccumulatorMembershipWitness<G: AffineRepr>(pub MembershipWitness<G>);

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
#[serde(bound = "")]
pub struct KBUniversalAccumulatorNonMembershipWitness<G: AffineRepr>(pub MembershipWitness<G>);

impl<G: AffineRepr> From<MembershipWitness<G>> for KBUniversalAccumulatorMembershipWitness<G> {
    fn from(w: MembershipWitness<G>) -> Self {
        KBUniversalAccumulatorMembershipWitness(w)
    }
}

impl<G: AffineRepr> From<G> for KBUniversalAccumulatorMembershipWitness<G> {
    fn from(w: G) -> Self {
        KBUniversalAccumulatorMembershipWitness(MembershipWitness(w))
    }
}

impl<G: AffineRepr> From<MembershipWitness<G>> for KBUniversalAccumulatorNonMembershipWitness<G> {
    fn from(w: MembershipWitness<G>) -> Self {
        KBUniversalAccumulatorNonMembershipWitness(w)
    }
}

impl<G: AffineRepr> From<G> for KBUniversalAccumulatorNonMembershipWitness<G> {
    fn from(w: G) -> Self {
        KBUniversalAccumulatorNonMembershipWitness(MembershipWitness(w))
    }
}

// Any change to accumulator changes for membership and non-membership witness

impl<E: Pairing> KBUniversalAccumulator<E> {
    /// Update the membership witness on adding an element. Call this on the accumulator before update
    pub fn update_mem_wit_on_addition(
        &self,
        wit: &KBUniversalAccumulatorMembershipWitness<E::G1Affine>,
        member: &E::ScalarField,
        addition: &E::ScalarField,
    ) -> KBUniversalAccumulatorMembershipWitness<E::G1Affine> {
        wit.0
            .update_after_addition(member, addition, self.mem.value())
            .into()
    }

    /// Update the membership witness on removal of an element. Call this on the accumulator after update
    pub fn update_mem_wit_on_removal(
        &self,
        wit: &KBUniversalAccumulatorMembershipWitness<E::G1Affine>,
        member: &E::ScalarField,
        removal: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        Ok(wit
            .0
            .update_after_removal(member, removal, self.mem.value())?
            .into())
    }

    /// Update the membership witnesses on addition of a batch of elements. Call this on the accumulator before update
    pub fn update_mem_wit_using_secret_key_on_batch_additions(
        &self,
        additions: &[E::ScalarField],
        members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) = MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_additions(additions, members, &old, &self.mem.0, sk)?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }

    /// Update the membership witnesses on removal of a batch of elements. Call this on the accumulator before update
    pub fn update_mem_wit_using_secret_key_on_batch_removals(
        &self,
        removals: &[E::ScalarField],
        members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) =
            MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_removals(
                removals,
                members,
                &old,
                &self.mem.0,
                sk,
            )?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }

    /// Update the membership witnesses on addition and removal of a batch of elements. Call this on the accumulator before update
    pub fn update_mem_wit_using_secret_key_on_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) =
            MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_updates(
                additions,
                removals,
                members,
                &old,
                &self.mem.0,
                sk,
            )?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }

    /// Update the non-membership witness on adding an element. Call this on the accumulator after update
    pub fn update_non_mem_wit_on_addition(
        &self,
        wit: &KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>,
        non_member: &E::ScalarField,
        addition: &E::ScalarField,
    ) -> Result<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        Ok(wit
            .0
            .update_after_removal(non_member, addition, self.non_mem.value())?
            .into())
    }

    /// Update the non-membership witness on removal of an element. Call this on the accumulator before update
    pub fn update_non_mem_wit_on_removal(
        &self,
        wit: &KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>,
        non_member: &E::ScalarField,
        removal: &E::ScalarField,
    ) -> KBUniversalAccumulatorNonMembershipWitness<E::G1Affine> {
        wit.0
            .update_after_addition(non_member, removal, self.non_mem.value())
            .into()
    }

    /// Update the non-membership witnesses on addition of a batch of elements. Call this on the accumulator before update
    pub fn update_non_mem_wit_using_secret_key_on_batch_additions(
        &self,
        additions: &[E::ScalarField],
        non_members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) =
            MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_removals(
                additions,
                non_members,
                &old,
                &self.non_mem.0,
                sk,
            )?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }

    /// Update the non-membership witnesses on removal of a batch of elements. Call this on the accumulator before update
    pub fn update_non_mem_wit_using_secret_key_on_batch_removals(
        &self,
        removals: &[E::ScalarField],
        non_members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        self.update_witnesses_using_secret_key_on_non_mem_accum_update(
            removals,
            non_members,
            old_witnesses,
            sk,
        )
    }

    /// Update the non-membership witnesses on addition and removal of a batch of elements. Call this on the accumulator before update
    pub fn update_non_mem_wit_using_secret_key_on_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        non_members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) =
            MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_updates(
                removals,
                additions,
                non_members,
                &old,
                &self.non_mem.0,
                sk,
            )?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }

    pub fn update_non_mem_wit_using_secret_key_on_domain_extension(
        &self,
        new_elements: &[E::ScalarField],
        non_members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        // Domain extension is adding elements to the non-membership accumulator
        self.update_witnesses_using_secret_key_on_non_mem_accum_update(
            new_elements,
            non_members,
            old_witnesses,
            sk,
        )
    }

    /// Call this on the accumulator before update
    pub fn generate_omega_for_membership_witnesses(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> Omega<E::G1Affine> {
        Omega::new(additions, removals, self.mem.value(), sk)
    }

    /// Call this on the accumulator before update
    pub fn generate_omega_for_non_membership_witnesses(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> Omega<E::G1Affine> {
        Omega::new(removals, additions, self.non_mem.value(), sk)
    }

    /// Generate Omega when the domain of the accumulator is extended. This means new elements are
    /// added to the non-membership accumulator and hence those witnesses need to be updated.
    /// Call this on the accumulator before update
    pub fn generate_omega_for_non_membership_witnesses_on_domain_extension(
        &self,
        new_elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> Omega<E::G1Affine> {
        Omega::new(new_elements, &[], self.non_mem.value(), sk)
    }

    /// Update both membership and non-membership witnesses in a single call. Call this on the accumulator before update
    pub fn update_both_wit_using_secret_key_on_batch_updates(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        members: &[E::ScalarField],
        old_mem_witnesses: &[KBUniversalAccumulatorMembershipWitness<E::G1Affine>],
        non_members: &[E::ScalarField],
        old_non_mem_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<
        (
            Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>,
            Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>,
        ),
        VBAccumulatorError,
    > {
        if members.len() != old_mem_witnesses.len() {
            return Err(VBAccumulatorError::NeedSameNoOfElementsAndWitnesses);
        }
        if non_members.len() != old_non_mem_witnesses.len() {
            return Err(VBAccumulatorError::NeedSameNoOfElementsAndWitnesses);
        }
        let m = additions.len();
        let n = removals.len();
        let p = members.len();
        let q = non_members.len();
        let alpha = &sk.0;

        // (additions[0] + alpha), (additions[0] + alpha)*(additions[1] + alpha), ..., (additions[0] + alpha)*(additions[1] + alpha)*...(additions[m-1] + alpha)
        let mut factors_add = vec![E::ScalarField::one(); m];
        // (removals[0] + alpha), (removals[0] + alpha)*(removals[1] + alpha), ..., (removals[0] + alpha)*(removals[1] + alpha)*...(removals[n-1] + alpha)
        let mut factors_rem = vec![E::ScalarField::one(); n];
        // For each of the p members, mem_add_poly[i] = (additions[1] - members[i])*(additions[2] - members[i])*...(additions[m-1] - members[i]), (additions[2] - members[i])*(additions[3] - members[i])*...(additions[m-1] - members[i]), .., 1
        let mut mem_add_poly = vec![vec![E::ScalarField::one(); m]; p];
        // For each of the p members, mem_rem_poly[i] = 1, (removals[0] - members[i]), (removals[0] - x)*(removals[1] - members[i]), ..., (removals[0] - members[i])*(removals[1] - members[i])*...(removals[n-2] - members[i])
        let mut mem_rem_poly = vec![vec![E::ScalarField::one(); n]; p];
        let mut non_mem_add_poly = vec![vec![E::ScalarField::one(); n]; q];
        let mut non_mem_rem_poly = vec![vec![E::ScalarField::one(); m]; q];

        if !additions.is_empty() {
            factors_add[0] = additions[0] + alpha;
        }
        if !removals.is_empty() {
            factors_rem[0] = removals[0] + alpha;
        }

        for s in 1..m {
            factors_add[s] = factors_add[s - 1] * (additions[s] + alpha);
            for j in 0..p {
                mem_add_poly[j][m - 1 - s] =
                    mem_add_poly[j][m - s] * (additions[m - s] - members[j]);
            }
            for j in 0..q {
                non_mem_rem_poly[j][s] =
                    non_mem_rem_poly[j][s - 1] * (additions[s - 1] - non_members[j]);
            }
        }
        for s in 1..n {
            factors_rem[s] = factors_rem[s - 1] * (removals[s] + alpha);
            for j in 0..q {
                non_mem_add_poly[j][n - 1 - s] =
                    non_mem_add_poly[j][n - s] * (removals[n - s] - non_members[j]);
            }
            for j in 0..p {
                mem_rem_poly[j][s] = mem_rem_poly[j][s - 1] * (removals[s - 1] - members[j]);
            }
        }

        // 1/(additions[0] + alpha), 1/(additions[0] + alpha)*(additions[1] + alpha), ..., 1/(additions[0] + alpha)*(additions[1] + alpha)*...(additions[m-1] + alpha)
        let mut factors_add_inv = factors_add.clone();
        batch_inversion(&mut factors_add_inv);
        // 1/(removals[0] + alpha), 1/(removals[0] + alpha)*(removals[1] + alpha), ..., 1/(removals[0] + alpha)*(removals[1] + alpha)*...(removals[n-1] + alpha)
        let mut factors_rem_inv = factors_rem.clone();
        batch_inversion(&mut factors_rem_inv);

        let (mem_d_A, mut mem_d_D): (Vec<_>, Vec<_>) = cfg_into_iter!(0..p)
            .map(|i| {
                (
                    if additions.is_empty() {
                        E::ScalarField::one()
                    } else {
                        mem_add_poly[i][0] * (additions[0] - members[i])
                    },
                    if removals.is_empty() {
                        E::ScalarField::one()
                    } else {
                        mem_rem_poly[i][n - 1] * (removals[n - 1] - members[i])
                    },
                )
            })
            .unzip();
        let (non_mem_d_A, mut non_mem_d_D): (Vec<_>, Vec<_>) = cfg_into_iter!(0..q)
            .map(|i| {
                (
                    if removals.is_empty() {
                        E::ScalarField::one()
                    } else {
                        non_mem_add_poly[i][0] * (removals[0] - non_members[i])
                    },
                    if additions.is_empty() {
                        E::ScalarField::one()
                    } else {
                        non_mem_rem_poly[i][m - 1] * (additions[m - 1] - non_members[i])
                    },
                )
            })
            .unzip();

        batch_inversion(&mut mem_d_D);
        batch_inversion(&mut non_mem_d_D);

        let one = E::ScalarField::one();
        let zero = E::ScalarField::zero;

        let mem_v_AD = cfg_into_iter!(0..p)
            .map(|j| {
                // 1*mem_add_poly[0] + factors_add[0]*mem_add_poly[1] + ... + factors_add[m-2]*mem_add_poly[m-1]
                let mem_poly_v_A = cfg_into_iter!(0..m)
                    .map(|i| if i == 0 { &one } else { &factors_add[i - 1] })
                    .zip(cfg_iter!(mem_add_poly[j]))
                    .map(|(f, p)| *p * *f);
                let mem_poly_v_A = cfg_iter_sum!(mem_poly_v_A, zero);

                let mem_poly_v_D = inner_product(&factors_rem_inv, &mem_rem_poly[j]);

                mem_poly_v_A
                    - (mem_poly_v_D
                        * if additions.is_empty() {
                            E::ScalarField::one()
                        } else {
                            factors_add[m - 1]
                        })
            })
            .collect::<Vec<_>>();

        let non_mem_v_AD = cfg_into_iter!(0..q)
            .map(|j| {
                // 1*non_mem_add_poly[0] + factors_rem[0]*non_mem_add_poly[1] + ... + factors_rem[n-2]*non_mem_add_poly[n-1]
                let non_mem_poly_v_A = cfg_into_iter!(0..n)
                    .map(|i| if i == 0 { &one } else { &factors_rem[i - 1] })
                    .zip(cfg_iter!(non_mem_add_poly[j]))
                    .map(|(f, p)| *p * *f);
                let non_mem_poly_v_A = cfg_iter_sum!(non_mem_poly_v_A, zero);

                let non_mem_poly_v_D = inner_product(&factors_add_inv, &non_mem_rem_poly[j]);

                non_mem_poly_v_A
                    - (non_mem_poly_v_D
                        * if removals.is_empty() {
                            E::ScalarField::one()
                        } else {
                            factors_rem[n - 1]
                        })
            })
            .collect::<Vec<_>>();

        let mem_table = WindowTable::new(members.len(), self.mem.value().into_group());
        let non_mem_table = WindowTable::new(non_members.len(), self.non_mem.value().into_group());

        let new_mem_wits = cfg_into_iter!(mem_d_A)
            .zip(cfg_into_iter!(mem_d_D))
            .zip(cfg_into_iter!(mem_v_AD))
            .enumerate()
            .map(|(i, ((d_A_i, d_D_inv), v))| {
                let d_A_times_d_D_inv = d_A_i * d_D_inv;
                let v_d_inv = v * d_D_inv;
                // d_A_i/d_D * C + v_{A,D}/d_D * V
                let r = old_mem_witnesses[i]
                    .0
                     .0
                    .mul_bigint(d_A_times_d_D_inv.into_bigint())
                    + mem_table.multiply(&v_d_inv);
                r
            })
            .collect::<Vec<_>>();

        let new_non_mem_wits = cfg_into_iter!(non_mem_d_A)
            .zip(cfg_into_iter!(non_mem_d_D))
            .zip(cfg_into_iter!(non_mem_v_AD))
            .enumerate()
            .map(|(i, ((d_A_i, d_D_inv), v))| {
                let d_A_times_d_D_inv = d_A_i * d_D_inv;
                let v_d_inv = v * d_D_inv;
                // d_A_i/d_D * C + v_{A,D}/d_D * V
                let r = old_non_mem_witnesses[i]
                    .0
                     .0
                    .mul_bigint(d_A_times_d_D_inv.into_bigint())
                    + non_mem_table.multiply(&v_d_inv);
                r
            })
            .collect::<Vec<_>>();

        let new_mem_wits = cfg_into_iter!(E::G1::normalize_batch(&new_mem_wits))
            .map(|w| w.into())
            .collect::<Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>>();
        let new_non_mem_wits = cfg_into_iter!(E::G1::normalize_batch(&new_non_mem_wits))
            .map(|w| w.into())
            .collect::<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>>();
        Ok((new_mem_wits, new_non_mem_wits))
    }

    /// Call this on the accumulator before update
    pub fn generate_omega_for_both_witnesses(
        &self,
        additions: &[E::ScalarField],
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
    ) -> (Omega<E::G1Affine>, Omega<E::G1Affine>) {
        Omega::new_for_kb_universal_accumulator(
            additions,
            removals,
            &self.mem.value(),
            &self.non_mem.value(),
            sk,
        )
    }

    /// Update non-membership witnesses when the non-membership accumulator is updated
    fn update_witnesses_using_secret_key_on_non_mem_accum_update(
        &self,
        new_elements: &[E::ScalarField],
        non_members: &[E::ScalarField],
        old_witnesses: &[KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>],
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        let old: Vec<E::G1Affine> = cfg_iter!(old_witnesses).map(|w| w.0 .0).collect();
        let (_, new) =
            MembershipWitness::<E::G1Affine>::compute_update_using_secret_key_after_batch_additions(
                new_elements,
                non_members,
                &old,
                &self.non_mem.0,
                sk,
            )?;
        Ok(cfg_into_iter!(new)
            .map(|w| MembershipWitness(w).into())
            .collect())
    }
}

impl<G: AffineRepr> KBUniversalAccumulatorMembershipWitness<G> {
    pub fn update_using_public_info_after_batch_updates(
        &self,
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        omega: &Omega<G>,
        member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new) = MembershipWitness::compute_update_using_public_info_after_batch_updates(
            additions, removals, omega, member, &self.0 .0,
        )?;
        Ok(Self(MembershipWitness(new)))
    }

    pub fn update_using_public_info_after_multiple_batch_updates(
        &self,
        updates_and_omegas: Vec<(&[G::ScalarField], &[G::ScalarField], &Omega<G>)>,
        member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new) =
            MembershipWitness::compute_update_using_public_info_after_multiple_batch_updates(
                updates_and_omegas,
                member,
                &self.0 .0,
            )?;
        Ok(Self(MembershipWitness(new)))
    }
}

impl<G: AffineRepr> KBUniversalAccumulatorNonMembershipWitness<G> {
    pub fn update_using_public_info_after_batch_updates(
        &self,
        additions: &[G::ScalarField],
        removals: &[G::ScalarField],
        omega: &Omega<G>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new) = MembershipWitness::compute_update_using_public_info_after_batch_updates(
            removals, additions, omega, non_member, &self.0 .0,
        )?;
        Ok(Self(MembershipWitness(new)))
    }

    pub fn update_using_public_info_after_multiple_batch_updates(
        &self,
        updates_and_omegas: Vec<(&[G::ScalarField], &[G::ScalarField], &Omega<G>)>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new) =
            MembershipWitness::compute_update_using_public_info_after_multiple_batch_updates(
                cfg_into_iter!(updates_and_omegas)
                    .map(|(a, r, o)| (r, a, o))
                    .collect(),
                non_member,
                &self.0 .0,
            )?;
        Ok(Self(MembershipWitness(new)))
    }

    pub fn update_using_public_info_after_domain_extension(
        &self,
        new_elements: &[G::ScalarField],
        omega: &Omega<G>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new) = MembershipWitness::compute_update_using_public_info_after_batch_updates(
            new_elements,
            &[],
            omega,
            non_member,
            &self.0 .0,
        )?;
        Ok(Self(MembershipWitness(new)))
    }

    pub fn update_using_public_info_after_multiple_domain_extensions(
        &self,
        new_elements_and_omegas: Vec<(&[G::ScalarField], &Omega<G>)>,
        non_member: &G::ScalarField,
    ) -> Result<Self, VBAccumulatorError> {
        if new_elements_and_omegas.len() == 1 {
            return MembershipWitness::compute_update_using_public_info_after_batch_updates(
                new_elements_and_omegas[0].0,
                &[],
                new_elements_and_omegas[0].1,
                non_member,
                &self.0 .0,
            )
            .map(|(_, w)| Self(MembershipWitness(w)));
        }
        let mut new_elements = Vec::with_capacity(new_elements_and_omegas.len());
        let mut omegas = Vec::with_capacity(new_elements_and_omegas.len());
        for (a, omega) in new_elements_and_omegas {
            new_elements.push(a);
            omegas.push(omega);
        }

        MembershipWitness::compute_update_for_multiple_batches(
            new_elements,
            vec![],
            omegas,
            non_member,
            &self.0 .0,
        )
        .map(|(_, w)| Self(MembershipWitness(w)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb_universal_accumulator::accumulator::tests::setup_kb_universal_accum;
    use ark_bls12_381::Fr;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn single_witness_update_kb_universal_accumulator() {
        // Test to update non-membership witness after single addition or removal
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, domain, mut mem_state, mut non_mem_state) =
            setup_kb_universal_accum(&mut rng, max);

        let mut non_members = vec![];
        let mut non_membership_witnesses = vec![];

        let n = 10;
        for i in 0..n {
            let elem = domain[i].clone();
            let wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &non_mem_state)
                .unwrap();
            assert!(accumulator.verify_non_membership(&elem, &wit, &keypair.public_key, &params));
            non_members.push(elem);
            non_membership_witnesses.push(wit);
        }

        let mut update_m_post_add_duration = Duration::default();
        let mut update_m_post_add_counter = 0;
        let mut update_m_post_remove_duration = Duration::default();
        let mut update_m_post_remove_counter = 0;
        let mut update_nm_post_add_duration = Duration::default();
        let mut update_nm_post_add_counter = 0;
        let mut update_nm_post_remove_duration = Duration::default();
        let mut update_nm_post_remove_counter = 0;

        let mut members = vec![];
        let mut membership_witnesses = vec![];

        // Add a new element, update witness of non-member and check that the new witness is valid
        for i in 0..n {
            let elem = domain[n + i].clone();
            let new_accumulator = accumulator
                .add(
                    elem,
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();
            members.push(elem);
            membership_witnesses.push(
                new_accumulator
                    .get_membership_witness(&elem, &keypair.secret_key, &mem_state)
                    .unwrap(),
            );

            for j in 0..n {
                assert!(!new_accumulator.verify_non_membership(
                    &non_members[j],
                    &non_membership_witnesses[j],
                    &keypair.public_key,
                    &params
                ));

                let start = Instant::now();
                let new_wit = new_accumulator
                    .update_non_mem_wit_on_addition(
                        &non_membership_witnesses[j],
                        &non_members[j],
                        &members[i],
                    )
                    .unwrap();
                update_nm_post_add_duration += start.elapsed();
                update_nm_post_add_counter += 1;

                assert!(new_accumulator.verify_non_membership(
                    &non_members[j],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                non_membership_witnesses[j] = new_wit;
            }

            for k in 0..i {
                let start = Instant::now();
                let new_wit = accumulator.update_mem_wit_on_addition(
                    &membership_witnesses[k],
                    &members[k],
                    &elem,
                );
                update_m_post_add_duration += start.elapsed();
                update_m_post_add_counter += 1;

                assert!(new_accumulator.verify_membership(
                    &members[k],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                membership_witnesses[k] = new_wit;
            }

            accumulator = new_accumulator;
        }

        // Remove an existing element, update witness of a non-member and check that the new witness is valid
        for i in 0..n {
            let new_accumulator = accumulator
                .remove(
                    members[i].clone(),
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();
            for j in 0..n {
                assert!(!new_accumulator.verify_non_membership(
                    &non_members[j],
                    &non_membership_witnesses[j],
                    &keypair.public_key,
                    &params
                ));

                let start = Instant::now();
                let new_wit = accumulator.update_non_mem_wit_on_removal(
                    &non_membership_witnesses[j],
                    &non_members[j],
                    &members[i],
                );
                update_nm_post_remove_duration += start.elapsed();
                update_nm_post_remove_counter += 1;

                assert!(new_accumulator.verify_non_membership(
                    &non_members[j],
                    &new_wit,
                    &keypair.public_key,
                    &params
                ));
                non_membership_witnesses[j] = new_wit;
            }
            for k in i + 1..n {
                let start = Instant::now();
                let new_wit = new_accumulator
                    .update_mem_wit_on_removal(&membership_witnesses[k], &members[k], &members[i])
                    .unwrap();
                update_m_post_remove_duration += start.elapsed();
                update_m_post_remove_counter += 1;
                membership_witnesses[k] = new_wit;
            }
            accumulator = new_accumulator;
        }

        println!(
            "Universal Accumulator non-membership: Single update witness time after {} additions {:?}",
            update_nm_post_add_counter, update_nm_post_add_duration
        );
        println!(
            "Universal Accumulator non-membership: Single update witness time after {} removals {:?}",
            update_nm_post_remove_counter, update_nm_post_remove_duration
        );
        println!(
            "Universal Accumulator membership: Single update witness time after {} additions {:?}",
            update_m_post_add_counter, update_m_post_add_duration
        );
        println!(
            "Universal Accumulator membership: Single update witness time after {} removals {:?}",
            update_m_post_remove_counter, update_m_post_remove_duration
        );
    }

    #[test]
    fn batch_updates_witnesses_kb_universal_accumulator() {
        // Accumulator manager who knows the secret key batch updates witnesses
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, accumulator, domain, mut mem_state, mut non_mem_state) =
            setup_kb_universal_accum(&mut rng, max);

        let additions_1: Vec<Fr> = (0..10).map(|i| domain[i]).collect();
        let additions_2: Vec<Fr> = (20..30).map(|i| domain[i]).collect();
        let additions_3: Vec<Fr> = (30..40).map(|i| domain[i]).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_2[i])
            .collect();

        let mut non_members = vec![];
        let mut non_membership_witnesses = vec![];

        let n = 10;

        // Add elements in `additions_1`
        let accumulator_1 = accumulator
            .add_batch(
                additions_1.clone(),
                &keypair.secret_key,
                &mut mem_state,
                &mut non_mem_state,
            )
            .unwrap();
        let membership_witnesses_add_1 = accumulator_1
            .get_membership_witnesses_for_batch(&additions_1, &keypair.secret_key, &mem_state)
            .unwrap();

        for i in 50..50 + n {
            let elem = domain[i];
            let wit = accumulator_1
                .get_non_membership_witness(&elem, &keypair.secret_key, &non_mem_state)
                .unwrap();
            assert!(accumulator_1.verify_non_membership(&elem, &wit, &keypair.public_key, &params));
            non_members.push(elem);
            non_membership_witnesses.push(wit);
        }

        let new_elements = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
        let accumulator_2 = accumulator_1
            .extend_domain(
                &keypair.secret_key,
                new_elements.clone(),
                &mut non_mem_state,
            )
            .unwrap();
        assert_eq!(*accumulator_2.mem_value(), *accumulator_1.mem_value());
        assert_ne!(
            *accumulator_2.non_mem_value(),
            *accumulator_1.non_mem_value()
        );

        let (accumulator_2_mem, accumulator_2_non_mem) =
            accumulator_1.compute_extended(&new_elements, &keypair.secret_key);
        assert_eq!(*accumulator_2.mem_value(), accumulator_2_mem);
        assert_eq!(*accumulator_2.non_mem_value(), accumulator_2_non_mem);

        for i in 0..non_members.len() {
            assert!(!accumulator_2.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        non_membership_witnesses = accumulator_1
            .update_non_mem_wit_using_secret_key_on_domain_extension(
                &new_elements,
                &non_members,
                &non_membership_witnesses,
                &keypair.secret_key,
            )
            .unwrap();

        for i in 0..non_members.len() {
            assert!(accumulator_2.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        // Add elements in `additions_2`, batch update witnesses
        let accumulator_3 = accumulator_2
            .add_batch(
                additions_2.clone(),
                &keypair.secret_key,
                &mut mem_state,
                &mut non_mem_state,
            )
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_3.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }

        let membership_witnesses_1 = accumulator_1
            .update_mem_wit_using_secret_key_on_batch_additions(
                &additions_2,
                &additions_1,
                &membership_witnesses_add_1,
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            membership_witnesses_add_1.len(),
            membership_witnesses_1.len()
        );
        for i in 0..additions_1.len() {
            assert!(accumulator_3.verify_membership(
                &additions_1[i],
                &membership_witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        let non_membership_witnesses_1 = accumulator_2
            .update_non_mem_wit_using_secret_key_on_batch_additions(
                &additions_2,
                &non_members,
                &non_membership_witnesses,
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            non_membership_witnesses.len(),
            non_membership_witnesses_1.len()
        );
        for i in 0..n {
            assert!(accumulator_3.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        // Remove elements from `removals`, batch update witnesses
        let accumulator_4 = accumulator_3
            .remove_batch(
                removals.clone(),
                &keypair.secret_key,
                &mut mem_state,
                &mut non_mem_state,
            )
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_4.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_1[i],
                &keypair.public_key,
                &params
            ));
        }

        let membership_witnesses_2 = accumulator_3
            .update_mem_wit_using_secret_key_on_batch_removals(
                &removals,
                &additions_1,
                &membership_witnesses_1,
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(membership_witnesses_2.len(), membership_witnesses_1.len());
        for i in 0..additions_1.len() {
            assert!(accumulator_4.verify_membership(
                &additions_1[i],
                &membership_witnesses_2[i],
                &keypair.public_key,
                &params
            ));
        }

        let non_membership_witnesses_2 = accumulator_3
            .update_non_mem_wit_using_secret_key_on_batch_removals(
                &removals,
                &non_members,
                &non_membership_witnesses_1,
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(
            non_membership_witnesses_2.len(),
            non_membership_witnesses_1.len()
        );
        for i in 0..n {
            assert!(accumulator_4.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_2[i],
                &keypair.public_key,
                &params
            ));
        }

        // Remove elements remaining from `additions_2`, add elements in `additions_3`
        // and update witnesses for the absent elements
        let mut remaining = additions_2.clone();
        for e in removals {
            remaining.retain(|&x| x != e);
        }

        let accumulator_5 = accumulator_4
            .batch_updates(
                additions_3.clone(),
                remaining.clone(),
                &keypair.secret_key,
                &mut mem_state,
                &mut non_mem_state,
            )
            .unwrap();
        for i in 0..n {
            assert!(!accumulator_5.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_2[i],
                &keypair.public_key,
                &params
            ));
        }

        let start = Instant::now();
        let membership_witnesses_3 = accumulator_4
            .update_mem_wit_using_secret_key_on_batch_updates(
                &additions_3,
                &remaining,
                &additions_1,
                &membership_witnesses_2,
                &keypair.secret_key,
            )
            .unwrap();
        let non_membership_witnesses_3 = accumulator_4
            .update_non_mem_wit_using_secret_key_on_batch_updates(
                &additions_3,
                &remaining,
                &non_members,
                &non_membership_witnesses_2,
                &keypair.secret_key,
            )
            .unwrap();
        let wit_update_time = start.elapsed();

        assert_eq!(membership_witnesses_2.len(), membership_witnesses_3.len());
        for i in 0..additions_1.len() {
            assert!(accumulator_5.verify_membership(
                &additions_1[i],
                &membership_witnesses_3[i],
                &keypair.public_key,
                &params
            ));
        }

        assert_eq!(
            non_membership_witnesses_2.len(),
            non_membership_witnesses_3.len()
        );
        for i in 0..n {
            assert!(accumulator_5.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_3[i],
                &keypair.public_key,
                &params
            ));
        }

        let (membership_witnesses_2_, non_membership_witnesses_2_) = accumulator_4
            .update_both_wit_using_secret_key_on_batch_updates(
                &[],
                &[],
                &additions_1,
                &membership_witnesses_2,
                &non_members,
                &non_membership_witnesses_2,
                &keypair.secret_key,
            )
            .unwrap();
        assert_eq!(membership_witnesses_2_, membership_witnesses_2);
        assert_eq!(non_membership_witnesses_2_, non_membership_witnesses_2);

        let start = Instant::now();
        let (membership_witnesses_4, non_membership_witnesses_4) = accumulator_4
            .update_both_wit_using_secret_key_on_batch_updates(
                &additions_3,
                &remaining,
                &additions_1,
                &membership_witnesses_2,
                &non_members,
                &non_membership_witnesses_2,
                &keypair.secret_key,
            )
            .unwrap();
        let wit_update_time_1 = start.elapsed();

        assert_eq!(membership_witnesses_3, membership_witnesses_4);
        assert_eq!(non_membership_witnesses_3, non_membership_witnesses_4);

        println!(
            "Time to update witnesses in separate calls {:?}",
            wit_update_time
        );
        println!(
            "Time to generate witnesses in single call {:?}",
            wit_update_time_1
        );

        let start = Instant::now();
        let omega_mem = accumulator_4.generate_omega_for_membership_witnesses(
            &additions_3,
            &remaining,
            &keypair.secret_key,
        );
        let omega_non_mem = accumulator_4.generate_omega_for_non_membership_witnesses(
            &additions_3,
            &remaining,
            &keypair.secret_key,
        );
        let omega_time = start.elapsed();

        for i in 0..additions_1.len() {
            let new_wit = membership_witnesses_2[i]
                .update_using_public_info_after_batch_updates(
                    &additions_3,
                    &remaining,
                    &omega_mem,
                    &additions_1[i],
                )
                .unwrap();
            assert!(accumulator_5.verify_membership(
                &additions_1[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }

        for i in 0..non_members.len() {
            let new_wit = non_membership_witnesses_2[i]
                .update_using_public_info_after_batch_updates(
                    &additions_3,
                    &remaining,
                    &omega_non_mem,
                    &non_members[i],
                )
                .unwrap();
            assert!(accumulator_5.verify_non_membership(
                &non_members[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }

        let start = Instant::now();
        let (omega_mem_1, omega_non_mem_1) = accumulator_4.generate_omega_for_both_witnesses(
            &additions_3,
            &remaining,
            &keypair.secret_key,
        );
        let omega_time_1 = start.elapsed();

        assert_eq!(omega_mem, omega_mem_1);
        assert_eq!(omega_non_mem, omega_non_mem_1);

        let new_elements = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<Fr>>();
        let accumulator_6 = accumulator_5
            .extend_domain(
                &keypair.secret_key,
                new_elements.clone(),
                &mut non_mem_state,
            )
            .unwrap();
        let omega_domain = accumulator_5
            .generate_omega_for_non_membership_witnesses_on_domain_extension(
                &new_elements,
                &keypair.secret_key,
            );
        for i in 0..non_members.len() {
            assert!(!accumulator_6.verify_non_membership(
                &non_members[i],
                &non_membership_witnesses_4[i],
                &keypair.public_key,
                &params
            ));
            let new_wit = non_membership_witnesses_4[i]
                .update_using_public_info_after_domain_extension(
                    &new_elements,
                    &omega_domain,
                    &non_members[i],
                )
                .unwrap();
            assert!(accumulator_6.verify_non_membership(
                &non_members[i],
                &new_wit,
                &keypair.public_key,
                &params
            ));
        }

        println!(
            "Time to generate Omega for witnesses in separate calls {:?}",
            omega_time
        );
        println!(
            "Time to generate Omega for witnesses in single calls {:?}",
            omega_time_1
        );

        let (_, __) =
            accumulator_4.generate_omega_for_both_witnesses(&[], &remaining, &keypair.secret_key);

        let (_, __) =
            accumulator_4.generate_omega_for_both_witnesses(&additions_3, &[], &keypair.secret_key);
    }
}
