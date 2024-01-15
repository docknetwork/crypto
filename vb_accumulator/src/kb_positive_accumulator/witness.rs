use crate::{
    error::VBAccumulatorError,
    witness::{MembershipWitness, Witness},
};
use ark_ec::pairing::Pairing;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, vec::Vec};
use short_group_sig::bb_sig::SignatureG1 as BBSig;

use crate::{batch_utils::Omega, kb_positive_accumulator::setup::SecretKey};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Membership witness in for the positive accumulator
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
pub struct KBPositiveAccumulatorWitness<E: Pairing> {
    /// The BB signature on the member
    pub signature: BBSig<E>,
    /// The membership witness in the non-adaptive accumulator
    pub accum_witness: MembershipWitness<E::G1Affine>,
}

impl<E: Pairing> KBPositiveAccumulatorWitness<E> {
    /// Get the member in the non-adaptive accumulator
    pub fn get_accumulator_member(&self) -> &E::ScalarField {
        &self.signature.1
    }

    /// Update witness after removal of an element from accumulator. The removed element is expected to be passed as members
    /// of the non-adaptive accumulator
    pub fn update_after_removal(
        &self,
        removal: &E::ScalarField,
        new_accumulator: &E::G1Affine,
    ) -> Result<Self, VBAccumulatorError> {
        let new_wit = self.accum_witness.update_after_removal(
            self.get_accumulator_member(),
            removal,
            new_accumulator,
        )?;
        Ok(Self {
            signature: self.signature.clone(),
            accum_witness: new_wit,
        })
    }

    pub fn update_using_secret_key_after_batch_removals(
        removals: &[E::ScalarField],
        old_witnesses: &[KBPositiveAccumulatorWitness<E>],
        old_accumulator: &E::G1Affine,
        sk: &SecretKey<E::ScalarField>,
    ) -> Result<Vec<KBPositiveAccumulatorWitness<E>>, VBAccumulatorError> {
        let members = cfg_into_iter!(old_witnesses)
            .map(|w| *w.get_accumulator_member())
            .collect::<Vec<_>>();
        let old_accum_wits = cfg_into_iter!(old_witnesses)
            .map(|w| w.accum_witness.0)
            .collect::<Vec<_>>();
        let (_, new_wits) =
            MembershipWitness::compute_update_using_secret_key_after_batch_removals(
                removals,
                &members,
                &old_accum_wits,
                old_accumulator,
                &sk.accum,
            )?;
        Ok(cfg_into_iter!(new_wits)
            .zip(cfg_into_iter!(old_witnesses))
            .map(|(aw, w)| KBPositiveAccumulatorWitness {
                signature: w.signature.clone(),
                accum_witness: MembershipWitness(aw),
            })
            .collect::<Vec<_>>())
    }

    pub fn update_using_public_info_after_batch_updates(
        &self,
        removals: &[E::ScalarField],
        omega: &Omega<E::G1Affine>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, new_wit) =
            MembershipWitness::<E::G1Affine>::compute_update_using_public_info_after_batch_updates(
                &[],
                removals,
                omega,
                self.get_accumulator_member(),
                &self.accum_witness.0,
            )?;
        Ok(KBPositiveAccumulatorWitness {
            signature: self.signature.clone(),
            accum_witness: MembershipWitness(new_wit),
        })
    }

    pub fn update_using_public_info_after_multiple_batch_updates(
        &self,
        removals_and_omegas: Vec<(&[E::ScalarField], &Omega<E::G1Affine>)>,
    ) -> Result<Self, VBAccumulatorError> {
        if removals_and_omegas.len() == 1 {
            return self.update_using_public_info_after_batch_updates(
                removals_and_omegas[0].0,
                removals_and_omegas[0].1,
            );
        }
        let mut removals = Vec::with_capacity(removals_and_omegas.len());
        let mut omegas = Vec::with_capacity(removals_and_omegas.len());
        for (r, omega) in removals_and_omegas {
            removals.push(r);
            omegas.push(omega);
        }
        let (_, new_wit) = MembershipWitness::compute_update_for_multiple_batches(
            Vec::new(),
            removals,
            omegas,
            self.get_accumulator_member(),
            &self.accum_witness.0,
        )?;
        Ok(KBPositiveAccumulatorWitness {
            signature: self.signature.clone(),
            accum_witness: MembershipWitness(new_wit),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::{
        kb_positive_accumulator::adaptive_accumulator::{
            tests::setup_kb_positive_accum, KBPositiveAccumulator,
        },
        persistence::State,
    };
    use ark_bls12_381::{Bls12_381, Fr};

    use crate::kb_positive_accumulator::setup::{PublicKey, SetupParams};
    use ark_std::{
        cfg_iter,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn single_membership_witness_update() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, mut accumulator, mut state) = setup_kb_positive_accum(&mut rng);

        let mut members = vec![];
        let mut witnesses = vec![];
        let count = 10;

        let mut update_post_remove_duration = Duration::default();
        let mut update_post_remove_counter = 0;

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            let wit = accumulator
                .add::<Blake2b512>(&elem, &sk, &params, &mut state)
                .unwrap();
            accumulator
                .verify_membership(&elem, &wit, &pk, &params)
                .unwrap();
            members.push(elem);
            witnesses.push(wit);
        }

        // Remove an existing element, update witness of an existing member and check that the new witness is valid
        let mut i = count - 1;
        loop {
            let new_accumulator = accumulator
                .remove::<Blake2b512>(&members[i], &sk, &mut state)
                .unwrap();
            let mut j = i;
            while j > 0 {
                // Update witness of each element before i, going backwards
                assert!(new_accumulator
                    .verify_membership(&members[j - 1], &witnesses[j - 1], &pk, &params)
                    .is_err());

                let start = Instant::now();
                let new_wit = witnesses[j - 1]
                    .update_after_removal(
                        witnesses[i].get_accumulator_member(),
                        new_accumulator.value(),
                    )
                    .unwrap();
                update_post_remove_duration += start.elapsed();
                update_post_remove_counter += 1;

                new_accumulator
                    .verify_membership(&members[j - 1], &new_wit, &pk, &params)
                    .unwrap();
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
            "KB Positive Accumulator: Single update witness time after {} removals {:?}",
            update_post_remove_counter, update_post_remove_duration
        );
    }

    #[test]
    fn batch_updates_witnesses() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, accumulator, mut state) = setup_kb_positive_accum(&mut rng);

        let additions_1: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_2: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let additions_3: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let remove_indices = vec![0, 1, 6, 9];
        let removals = remove_indices
            .iter()
            .map(|i| additions_1[*i])
            .collect::<Vec<Fr>>();

        // Add elements in `additions_1`, compute witnesses for them, then add `additions_2`
        let wits = accumulator
            .add_batch::<Blake2b512>(additions_1.clone(), &sk, &params, &mut state)
            .unwrap();
        let witnesses_1 = accumulator
            .get_witnesses_for_batch::<Blake2b512>(&additions_1, &sk, &params, &mut state)
            .unwrap();
        assert_eq!(wits, witnesses_1);
        for i in 0..witnesses_1.len() {
            accumulator
                .verify_membership(&additions_1[i], &witnesses_1[i], &pk, &params)
                .unwrap();
        }

        let witnesses_2 = accumulator
            .add_batch::<Blake2b512>(additions_2.clone(), &sk, &params, &mut state)
            .unwrap();
        for i in 0..witnesses_2.len() {
            accumulator
                .verify_membership(&additions_2[i], &witnesses_2[i], &pk, &params)
                .unwrap();
        }

        let removed_members = remove_indices
            .iter()
            .map(|i| *witnesses_1[*i].get_accumulator_member())
            .collect::<Vec<Fr>>();

        for k in 0..removed_members.len() {
            assert!(state.has(&removed_members[k]));
        }
        for k in 0..witnesses_2.len() {
            assert!(state.has(witnesses_2[k].get_accumulator_member()));
        }

        // Remove elements in `removals` and update witnesses for `additions_2`
        let accumulator_2 = accumulator
            .remove_batch::<Blake2b512>(&removals, &sk, &mut state)
            .unwrap();
        for i in 0..witnesses_1.len() {
            assert!(accumulator_2
                .verify_membership(&additions_1[i], &witnesses_1[i], &pk, &params)
                .is_err());
        }
        for i in 0..witnesses_2.len() {
            assert!(accumulator_2
                .verify_membership(&additions_2[i], &witnesses_2[i], &pk, &params)
                .is_err());
        }

        for k in 0..removed_members.len() {
            assert!(!state.has(&removed_members[k]));
        }
        for k in 0..witnesses_2.len() {
            assert!(state.has(witnesses_2[k].get_accumulator_member()));
        }

        let new_wits = KBPositiveAccumulatorWitness::update_using_secret_key_after_batch_removals(
            &removed_members,
            &witnesses_2,
            accumulator.value(),
            &sk,
        )
        .unwrap();
        assert_eq!(new_wits.len(), witnesses_2.len());
        for i in 0..new_wits.len() {
            accumulator_2
                .verify_membership(&additions_2[i], &new_wits[i], &pk, &params)
                .unwrap();
        }

        // Compute membership witness for elements remaining from `additions_1`, remove elements in `additions_2`, add elements in `addition_3`
        // and update witnesses for the remaining elements
        let mut remaining = additions_1;
        for e in removals {
            remaining.retain(|&x| x != e);
        }

        let witnesses_3 = accumulator_2
            .get_witnesses_for_batch::<Blake2b512>(&remaining, &sk, &params, &mut state)
            .unwrap();
        for i in 0..witnesses_3.len() {
            accumulator_2
                .verify_membership(&remaining[i], &witnesses_3[i], &pk, &params)
                .unwrap();
        }

        let accumulator_2_cloned = accumulator_2.clone();
        let mut state_cloned = state.clone();

        /// Update an accumulator with a batch of updates, update existing witnesses of given elements and check that new witnesses are valid
        fn check_batch_witness_update_using_secret_key(
            current_accm: &KBPositiveAccumulator<Bls12_381>,
            additions: Vec<Fr>,
            removals: &[Fr],
            elements: &[Fr],
            old_witnesses: &[KBPositiveAccumulatorWitness<Bls12_381>],
            state: &mut dyn State<Fr>,
            sk: &SecretKey<Fr>,
            pk: &PublicKey<Bls12_381>,
            params: &SetupParams<Bls12_381>,
        ) -> (
            KBPositiveAccumulator<Bls12_381>,
            Vec<KBPositiveAccumulatorWitness<Bls12_381>>,
        ) {
            let (accumulator_new, _wits) = current_accm
                .batch_updates::<Blake2b512>(additions.clone(), removals, sk, params, state)
                .unwrap();
            if !removals.is_empty() {
                for i in 0..old_witnesses.len() {
                    assert!(accumulator_new
                        .verify_membership(&elements[i], &old_witnesses[i], pk, params)
                        .is_err());
                }
            }

            let removed_members = cfg_into_iter!(removals)
                .map(|r| {
                    KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, sk)
                })
                .collect::<Vec<_>>();
            let new_witnesses =
                KBPositiveAccumulatorWitness::update_using_secret_key_after_batch_removals(
                    &removed_members,
                    old_witnesses,
                    current_accm.value(),
                    sk,
                )
                .unwrap();
            assert_eq!(new_witnesses.len(), old_witnesses.len());
            for i in 0..new_witnesses.len() {
                accumulator_new
                    .verify_membership(&elements[i], &new_witnesses[i], pk, params)
                    .unwrap();
            }
            (accumulator_new, new_witnesses)
        }

        let (accumulator_4, witnesses_4) = check_batch_witness_update_using_secret_key(
            &accumulator_2,
            additions_3.clone(),
            &additions_2,
            &remaining,
            &witnesses_3,
            &mut state,
            &sk,
            &pk,
            &params,
        );
        let verification_accumulator_4 =
            KBPositiveAccumulator::<Bls12_381>::from_accumulated(*accumulator_4.value());

        let (accumulator_4_new, witnesses_6) = check_batch_witness_update_using_secret_key(
            &accumulator_2_cloned,
            additions_3.clone(),
            &[],
            &remaining,
            &witnesses_3,
            &mut state_cloned,
            &sk,
            &pk,
            &params,
        );
        let _verification_accumulator_4_new =
            KBPositiveAccumulator::<Bls12_381>::from_accumulated(*accumulator_4_new.value());

        let (_accumulator_5_new, _) = check_batch_witness_update_using_secret_key(
            &accumulator_4_new,
            vec![],
            &additions_2,
            &remaining,
            &witnesses_6,
            &mut state_cloned,
            &sk,
            &pk,
            &params,
        );

        // Public updates to witnesses - each one in `remaining` updates his witness using publicly published info from manager
        let omega = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
            &additions_2,
            accumulator_2.value(),
            &sk,
        );

        let removed_members = cfg_into_iter!(additions_2.as_slice())
            .map(|r| KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk))
            .collect::<Vec<_>>();

        for k in 0..additions_2.len() {
            assert_eq!(removed_members[k], *witnesses_2[k].get_accumulator_member());
        }

        for i in 0..remaining.len() {
            Omega::check_for_kb_positive_accumulator::<Blake2b512>(
                &additions_2,
                &remaining[i],
                accumulator_2.value(),
                &sk,
            );
            let new_wit = witnesses_3[i]
                .update_using_public_info_after_batch_updates(&removed_members, &omega)
                .unwrap();
            assert_eq!(witnesses_4[i], new_wit);
            verification_accumulator_4
                .verify_membership(&remaining[i], &new_wit, &pk, &params)
                .unwrap();
        }
    }

    #[test]
    fn update_witnesses_after_multiple_batch_updates() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, accumulator, mut state) = setup_kb_positive_accum(&mut rng);

        let mut members = vec![];
        for _ in 0..10 {
            let elem = Fr::rand(&mut rng);
            accumulator
                .add::<Blake2b512>(&elem, &sk, &params, &mut state)
                .unwrap();
            members.push(elem)
        }

        let witnesses = accumulator
            .get_witnesses_for_batch::<Blake2b512>(&members, &sk, &params, &mut state)
            .unwrap();
        for i in 0..10 {
            accumulator
                .verify_membership(&members[i], &witnesses[i], &pk, &params)
                .unwrap();
        }

        let additions_1: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_2: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let additions_3: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let removals_1: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_1[i])
            .collect();
        let removed_members_1 = cfg_iter!(removals_1)
            .map(|r| KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk))
            .collect::<Vec<_>>();
        let removals_2: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_2[i])
            .collect();
        let removed_members_2 = cfg_iter!(removals_2)
            .map(|r| KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk))
            .collect::<Vec<_>>();
        let removals_3: Vec<Fr> = vec![0, 1, 6, 9]
            .into_iter()
            .map(|i| additions_3[i])
            .collect();
        let removed_members_3 = cfg_iter!(removals_3)
            .map(|r| KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk))
            .collect::<Vec<_>>();

        accumulator
            .add_batch::<Blake2b512>(additions_1.clone(), &sk, &params, &mut state)
            .unwrap();
        let accumulator_1 = accumulator
            .remove_batch::<Blake2b512>(&removals_1, &sk, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(accumulator_1
                .verify_membership(&members[i], &witnesses[i], &pk, &params)
                .is_err());
        }
        let omega_1 = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
            &removals_1,
            accumulator.value(),
            &sk,
        );

        for (i, wit) in witnesses.iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(vec![(
                    removed_members_1.as_slice(),
                    &omega_1,
                )])
                .unwrap();
            accumulator_1
                .verify_membership(&members[i], &new_wit, &pk, &params)
                .unwrap();
        }

        accumulator_1
            .add_batch::<Blake2b512>(additions_2.clone(), &sk, &params, &mut state)
            .unwrap();
        let accumulator_2 = accumulator_1
            .remove_batch::<Blake2b512>(&removals_2, &sk, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(accumulator_2
                .verify_membership(&members[i], &witnesses[i], &pk, &params)
                .is_err());
        }
        let omega_2 = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
            &removals_2,
            accumulator_1.value(),
            &sk,
        );

        for (i, wit) in witnesses.iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(vec![
                    (removed_members_1.as_slice(), &omega_1),
                    (removed_members_2.as_slice(), &omega_2),
                ])
                .unwrap();
            accumulator_2
                .verify_membership(&members[i], &new_wit, &pk, &params)
                .unwrap();
        }

        accumulator_2
            .add_batch::<Blake2b512>(additions_3.clone(), &sk, &params, &mut state)
            .unwrap();
        let accumulator_3 = accumulator_2
            .remove_batch::<Blake2b512>(&removals_3, &sk, &mut state)
            .unwrap();
        for i in 0..witnesses.len() {
            assert!(accumulator_3
                .verify_membership(&members[i], &witnesses[i], &pk, &params)
                .is_err());
        }
        let omega_3 = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
            &removals_3,
            accumulator_2.value(),
            &sk,
        );

        for (i, wit) in witnesses.into_iter().enumerate() {
            let new_wit = wit
                .update_using_public_info_after_multiple_batch_updates(vec![
                    (removed_members_1.as_slice(), &omega_1),
                    (removed_members_2.as_slice(), &omega_2),
                    (removed_members_3.as_slice(), &omega_3),
                ])
                .unwrap();
            accumulator_3
                .verify_membership(&members[i], &new_wit, &pk, &params)
                .unwrap();
        }
    }

    fn multiple_batches_check(
        member: &Fr,
        initial_additions: Vec<Fr>,
        additions: Vec<Vec<Fr>>,
        removals: Vec<Vec<Fr>>,
    ) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, sk, pk, mut accumulator, mut state) = setup_kb_positive_accum(&mut rng);

        accumulator
            .add_batch::<Blake2b512>(initial_additions, &sk, &params, &mut state)
            .unwrap();

        let mut omegas = vec![];
        let mut removed_members = vec![];

        // Witness that will be updated with multiple batches
        let wit = accumulator
            .get_witness::<Blake2b512>(member, &sk, &params, &mut state)
            .unwrap();

        // This witness is updated with only 1 batch in each iteration of the loop below
        let mut wit_temp = wit.clone();

        for i in 0..additions.len() {
            let omega = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
                &removals[i],
                accumulator.value(),
                &sk,
            );
            let new = accumulator
                .batch_updates::<Blake2b512>(
                    additions[i].clone(),
                    &removals[i],
                    &sk,
                    &params,
                    &mut state,
                )
                .unwrap();
            accumulator = new.0;
            let removed = cfg_into_iter!(removals[i].as_slice())
                .map(|r| {
                    KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk)
                })
                .collect::<Vec<_>>();
            wit_temp = wit_temp
                .update_using_public_info_after_batch_updates(&removed, &omega)
                .unwrap();
            accumulator
                .verify_membership(member, &wit_temp, &pk, &params)
                .unwrap();
            omegas.push(omega);
            removed_members.push(removed);
        }

        let mut updates_and_omegas = vec![];
        for i in 0..additions.len() {
            updates_and_omegas.push((removed_members[i].as_slice(), &omegas[i]));
        }

        let new_wit = wit
            .update_using_public_info_after_multiple_batch_updates(updates_and_omegas)
            .unwrap();

        accumulator
            .verify_membership(member, &new_wit, &pk, &params)
            .unwrap();
    }

    #[test]
    fn update_witnesses_after_multiple_batch_updates_1() {
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
    fn update_witnesses_after_multiple_batch_updates_2() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, mut accumulator, mut state) = setup_kb_positive_accum(&mut rng);
        let e0 = Fr::rand(&mut rng);

        let elements: Vec<Fr> = (0..12).map(|_| Fr::rand(&mut rng)).collect();

        accumulator
            .add_batch::<Blake2b512>(vec![e0, elements[0], elements[1]], &sk, &params, &mut state)
            .unwrap();

        let wit = accumulator
            .get_witness::<Blake2b512>(&e0, &sk, &params, &mut state)
            .unwrap();

        let mut wit_temp = wit.clone();

        let mut omegas = vec![];
        let mut additions = vec![];
        let mut removals = vec![];
        let mut removed_members = vec![];
        for i in (2..10).step_by(2) {
            additions.push(vec![elements[i], elements[i + 1]]);
            removals.push(vec![elements[i - 2], elements[i - 1]]);
            removed_members.push(
                cfg_into_iter!(removals.last().unwrap())
                    .map(|r| {
                        KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(r, &sk)
                    })
                    .collect::<Vec<_>>(),
            );
            let omega = Omega::new_for_kb_positive_accumulator::<Blake2b512>(
                removals.last().unwrap(),
                accumulator.value(),
                &sk,
            );
            omegas.push(omega);
            let new = accumulator
                .batch_updates::<Blake2b512>(
                    additions.last().unwrap().clone(),
                    removals.last().unwrap(),
                    &sk,
                    &params,
                    &mut state,
                )
                .unwrap();
            accumulator = new.0;
            wit_temp = wit_temp
                .update_using_public_info_after_batch_updates(
                    removed_members.last().unwrap(),
                    omegas.last().unwrap(),
                )
                .unwrap();
            accumulator
                .verify_membership(&e0, &wit_temp, &pk, &params)
                .unwrap();
        }

        let new_wit = wit
            .update_using_public_info_after_multiple_batch_updates(vec![
                (&removed_members[0], &omegas[0]),
                (&removed_members[1], &omegas[1]),
                (&removed_members[2], &omegas[2]),
                (&removed_members[3], &omegas[3]),
            ])
            .unwrap();

        accumulator
            .verify_membership(&e0, &new_wit, &pk, &params)
            .unwrap();
    }
}
