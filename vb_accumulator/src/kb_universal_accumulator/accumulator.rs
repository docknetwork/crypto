//! A universal accumulator contructed from 2 positive accumulators where one accumulator accumulates all the members, say *Acc_M*,
//! and the other accumulates all the non-members, say *Acc_N*. Thus in an empty universal accumulator, all possible elements, called
//! the *domain* are present in the accumulator *Acc_N*. Adding an element to the universal accumulator results in adding the element to *Acc_M* and
//! removing it from *Acc_N* and removing an element from the universal accumulator results in adding it to *Acc_N* and removing from *Acc_M*.
//! A membership witness in the universal accumulator is a membership witness in *Acc_M* and a non-membership witness is a membership witness in *Acc_N*

use crate::{
    batch_utils::Poly_d,
    error::VBAccumulatorError,
    kb_universal_accumulator::witness::{
        KBUniversalAccumulatorMembershipWitness, KBUniversalAccumulatorNonMembershipWitness,
    },
    persistence::State,
    positive::{Accumulator, PositiveAccumulator},
    setup::{PublicKey, SecretKey, SetupParams},
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KBUniversalAccumulator<E: Pairing> {
    /// The accumulator accumulating all the members
    pub mem: PositiveAccumulator<E>,
    /// The accumulator accumulating all the non-members
    pub non_mem: PositiveAccumulator<E>,
}

impl<E: Pairing> KBUniversalAccumulator<E> {
    /// Initialize a new accumulator. `domain` is the set of all possible accumulator members. Initialization includes adding
    /// the `domain` to the accumulator, accumulating all non-members
    pub fn initialize(
        params_gen: impl AsRef<E::G1Affine>,
        sk: &SecretKey<E::ScalarField>,
        domain: Vec<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let mem = PositiveAccumulator::initialize(params_gen);
        let mut non_mem = mem.clone();
        non_mem = non_mem.add_batch(domain, sk, non_mem_state)?;
        Ok(Self { mem, non_mem })
    }

    pub fn initialize_given_initialized_non_members_accumulator(
        params_gen: impl AsRef<E::G1Affine>,
        non_mem: PositiveAccumulator<E>,
    ) -> Self {
        let mem = PositiveAccumulator::initialize(params_gen);
        Self { mem, non_mem }
    }

    /// Add new elements to an already initialized accumulator that were not part of its `domain`.
    pub fn extend_domain(
        &self,
        sk: &SecretKey<E::ScalarField>,
        new_elements: Vec<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let mut new = self.clone();
        new.non_mem = new.non_mem.add_batch(new_elements, sk, non_mem_state)?;
        Ok(new)
    }

    /// Add an element to the accumulator updating both the internal accumulators.
    pub fn add(
        &self,
        element: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &mut dyn State<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let mut new = self.clone();
        // Remove from non-membership accumulator
        new.non_mem = new.non_mem.remove(&element, sk, non_mem_state)?;
        // Add to membership accumulator
        new.mem = new.mem.add(element, sk, mem_state)?;
        Ok(new)
    }

    /// Remove an element from the accumulator updating both the internal accumulators.
    pub fn remove(
        &self,
        element: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &mut dyn State<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let mut new = self.clone();
        new.mem = new.mem.remove(&element, sk, mem_state)?;
        new.non_mem = new.non_mem.add(element, sk, non_mem_state)?;
        Ok(new)
    }

    pub fn add_batch(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &mut dyn State<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in &elements {
            self.non_mem.check_before_remove(element, non_mem_state)?;
            self.mem.check_before_add(element, mem_state)?;
        }
        let mut new = self.clone();
        let update = Poly_d::<E::ScalarField>::eval_direct(&elements, &-sk.0);
        let update_inv = update.inverse().unwrap();
        for element in elements {
            non_mem_state.remove(&element);
            mem_state.add(element);
        }
        new.mem = PositiveAccumulator((*new.mem.value() * update).into());
        new.non_mem = PositiveAccumulator((*new.non_mem.value() * update_inv).into());
        Ok(new)
    }

    pub fn remove_batch(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &mut dyn State<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in &elements {
            self.mem.check_before_remove(element, mem_state)?;
            self.non_mem.check_before_add(element, non_mem_state)?;
        }
        let mut new = self.clone();
        let update = Poly_d::<E::ScalarField>::eval_direct(&elements, &-sk.0);
        let update_inv = update.inverse().unwrap();
        for element in elements {
            mem_state.remove(&element);
            non_mem_state.add(element);
        }
        new.non_mem = PositiveAccumulator((*new.non_mem.value() * update).into());
        new.mem = PositiveAccumulator((*new.mem.value() * update_inv).into());
        Ok(new)
    }

    pub fn batch_updates(
        &self,
        additions: Vec<E::ScalarField>,
        removals: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &mut dyn State<E::ScalarField>,
        non_mem_state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in &additions {
            self.mem.check_before_add(element, mem_state)?;
            self.non_mem.check_before_remove(element, non_mem_state)?;
        }
        for element in &removals {
            self.mem.check_before_remove(element, mem_state)?;
            self.non_mem.check_before_add(element, non_mem_state)?;
        }

        let mut new = self.clone();
        let update_add = if !additions.is_empty() {
            Poly_d::<E::ScalarField>::eval_direct(&additions, &-sk.0)
        } else {
            E::ScalarField::one()
        };
        let update_rem = if !removals.is_empty() {
            Poly_d::<E::ScalarField>::eval_direct(&removals, &-sk.0)
        } else {
            E::ScalarField::one()
        };
        let update_mem = update_add * update_rem.inverse().unwrap();

        for element in additions {
            non_mem_state.remove(&element);
            mem_state.add(element);
        }
        for element in removals {
            mem_state.remove(&element);
            non_mem_state.add(element);
        }
        new.mem = PositiveAccumulator((*new.mem.value() * update_mem).into());
        new.non_mem =
            PositiveAccumulator((*new.non_mem.value() * update_mem.inverse().unwrap()).into());
        Ok(new)
    }

    pub fn get_membership_witness(
        &self,
        member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        mem_state: &dyn State<E::ScalarField>,
    ) -> Result<KBUniversalAccumulatorMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        self.mem
            .get_membership_witness(member, sk, mem_state)
            .map(|w| w.into())
    }

    pub fn get_membership_witnesses_for_batch(
        &self,
        members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        mem_state: &dyn State<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorMembershipWitness<E::G1Affine>>, VBAccumulatorError> {
        self.mem
            .get_membership_witnesses_for_batch(members, sk, mem_state)
            .map(|ws| ws.into_iter().map(|w| w.into()).collect())
    }

    pub fn get_non_membership_witness(
        &self,
        non_member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        non_mem_state: &dyn State<E::ScalarField>,
    ) -> Result<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>, VBAccumulatorError> {
        self.non_mem
            .get_membership_witness(non_member, sk, non_mem_state)
            .map(|w| w.into())
    }

    pub fn get_non_membership_witnesses_for_batch(
        &self,
        non_members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        non_mem_state: &dyn State<E::ScalarField>,
    ) -> Result<Vec<KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>>, VBAccumulatorError>
    {
        self.non_mem
            .get_membership_witnesses_for_batch(non_members, sk, non_mem_state)
            .map(|ws| ws.into_iter().map(|w| w.into()).collect())
    }

    pub fn verify_membership(
        &self,
        member: &E::ScalarField,
        witness: &KBUniversalAccumulatorMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        self.mem.verify_membership(member, &witness.0, pk, params)
    }

    pub fn verify_non_membership(
        &self,
        non_member: &E::ScalarField,
        witness: &KBUniversalAccumulatorNonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> bool {
        self.non_mem
            .verify_membership(non_member, &witness.0, pk, params)
    }

    pub fn mem_value(&self) -> &E::G1Affine {
        self.mem.value()
    }

    pub fn non_mem_value(&self) -> &E::G1Affine {
        self.non_mem.value()
    }

    pub fn value(&self) -> (&E::G1Affine, &E::G1Affine) {
        (self.mem.value(), self.non_mem.value())
    }

    pub fn from_accumulated(
        mem_accumulated: E::G1Affine,
        non_mem_accumulated: E::G1Affine,
    ) -> Self {
        Self {
            mem: PositiveAccumulator::from_accumulated(mem_accumulated),
            non_mem: PositiveAccumulator::from_accumulated(non_mem_accumulated),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    use crate::{persistence::test::*, setup::Keypair};

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
        let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
        let keypair = Keypair::<Bls12_381>::generate_using_rng(rng, &params);

        let domain = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
        let mem_state = InMemoryState::new();
        let mut non_mem_state = InMemoryState::new();
        let accumulator = KBUniversalAccumulator::initialize(
            &params,
            &keypair.secret_key,
            domain.clone(),
            &mut non_mem_state,
        )
        .unwrap();
        (
            params,
            keypair,
            accumulator,
            domain,
            mem_state,
            non_mem_state,
        )
    }

    #[test]
    fn membership_non_membership() {
        // Test to check membership and non-membership in accumulator
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, domain, mut mem_state, mut non_mem_state) =
            setup_kb_universal_accum(&mut rng, max);

        let mut total_mem_check_time = Duration::default();
        let mut total_non_mem_check_time = Duration::default();
        let count = max;
        for i in 0..count {
            let elem = domain[i].clone();
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &mem_state)
                .is_err());

            let mut start = Instant::now();
            let nm_wit = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &non_mem_state)
                .unwrap();
            assert!(accumulator.verify_non_membership(
                &elem,
                &nm_wit,
                &keypair.public_key,
                &params
            ));
            total_non_mem_check_time += start.elapsed();

            assert!(!mem_state.has(&elem));
            assert!(non_mem_state.has(&elem));

            accumulator = accumulator
                .add(
                    elem,
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();

            assert!(mem_state.has(&elem));
            assert!(!non_mem_state.has(&elem));

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &mem_state)
                .unwrap();

            start = Instant::now();
            assert!(accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params));
            total_mem_check_time += start.elapsed();
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

        let (params, keypair, mut accumulator_1, domain, mut mem_state, mut non_mem_state) =
            setup_kb_universal_accum(&mut rng, max);

        // Create more accumulators to compare. Same elements will be added and removed from them as accumulator_1
        let mut accumulator_2: KBUniversalAccumulator<Bls12_381> = accumulator_1.clone();
        let mut state_2_mem = mem_state.clone();
        let mut state_2_non_mem = non_mem_state.clone();

        let mut accumulator_3: KBUniversalAccumulator<Bls12_381> = accumulator_1.clone();
        let mut state_3_mem = mem_state.clone();
        let mut state_3_non_mem = non_mem_state.clone();

        let additions: Vec<Fr> = (0..10).map(|i| domain[i]).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9].into_iter().map(|i| additions[i]).collect();

        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i];
            accumulator_1 = accumulator_1
                .add(
                    elem,
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();
        }

        // Add as a batch
        accumulator_2 = accumulator_2
            .add_batch(
                additions.clone(),
                &keypair.secret_key,
                &mut state_2_mem,
                &mut state_2_non_mem,
            )
            .unwrap();
        assert_eq!(accumulator_1.value(), accumulator_2.value());
        assert_eq!(mem_state.db, state_2_mem.db);
        assert_eq!(non_mem_state.db, state_2_non_mem.db);

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove(
                    removals[i],
                    &keypair.secret_key,
                    &mut mem_state,
                    &mut non_mem_state,
                )
                .unwrap();
        }

        // Remove as a batch
        accumulator_2 = accumulator_2
            .remove_batch(
                removals.clone(),
                &keypair.secret_key,
                &mut state_2_mem,
                &mut state_2_non_mem,
            )
            .unwrap();
        assert_eq!(accumulator_1.value(), accumulator_2.value());
        assert_eq!(mem_state.db, state_2_mem.db);
        assert_eq!(non_mem_state.db, state_2_non_mem.db);

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions;
        for e in removals.iter() {
            accumulator_3 = accumulator_3
                .add(
                    *e,
                    &keypair.secret_key,
                    &mut state_3_mem,
                    &mut state_3_non_mem,
                )
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(accumulator_1.value(), accumulator_3.value());
        assert_ne!(accumulator_2.value(), accumulator_3.value());

        // Add and remove as a batch
        accumulator_3 = accumulator_3
            .batch_updates(
                new_additions.clone(),
                removals.clone(),
                &keypair.secret_key,
                &mut state_3_mem,
                &mut state_3_non_mem,
            )
            .unwrap();
        assert_eq!(accumulator_1.value(), accumulator_3.value());
        assert_eq!(accumulator_2.value(), accumulator_3.value());

        assert_eq!(mem_state.db, state_2_mem.db);
        assert_eq!(non_mem_state.db, state_2_non_mem.db);
        assert_eq!(mem_state.db, state_3_mem.db);
        assert_eq!(non_mem_state.db, state_3_non_mem.db);

        let mem_witnesses = accumulator_3
            .get_membership_witnesses_for_batch(&new_additions, &keypair.secret_key, &state_3_mem)
            .unwrap();
        for i in 0..new_additions.len() {
            assert!(accumulator_3.verify_membership(
                &new_additions[i],
                &mem_witnesses[i],
                &keypair.public_key,
                &params
            ));
        }
        let npn_mem_witnesses = accumulator_3
            .get_non_membership_witnesses_for_batch(
                &removals,
                &keypair.secret_key,
                &state_3_non_mem,
            )
            .unwrap();
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
