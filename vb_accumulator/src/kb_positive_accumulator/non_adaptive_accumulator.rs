//! A non-adaptive accumulator

use crate::{
    error::VBAccumulatorError,
    persistence::State,
    prelude::{Accumulator, SecretKey},
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonAdaptivePositiveAccumulator<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub E::G1Affine,
);

impl<E: Pairing> Accumulator<E> for NonAdaptivePositiveAccumulator<E> {
    fn value(&self) -> &E::G1Affine {
        &self.0
    }

    fn from_accumulated(accumulated: E::G1Affine) -> Self {
        NonAdaptivePositiveAccumulator(accumulated)
    }
}

impl<E: Pairing> NonAdaptivePositiveAccumulator<E> {
    pub fn initialize<R: RngCore>(rng: &mut R, params_gen: impl AsRef<E::G1Affine>) -> Self {
        let u = E::ScalarField::rand(rng);
        Self((*params_gen.as_ref() * u).into())
    }

    pub fn add(
        &self,
        element: E::ScalarField,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(), VBAccumulatorError> {
        self.check_before_add(&element, state)?;
        state.add(element);
        Ok(())
    }

    pub fn remove(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove(element, sk, state)?;
        Ok(Self(acc_pub))
    }

    pub fn add_batch(
        &self,
        elements: Vec<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(), VBAccumulatorError> {
        for element in elements.iter() {
            self.check_before_add(element, state)?;
        }
        for element in elements {
            state.add(element);
        }
        Ok(())
    }

    pub fn remove_batch(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (_, acc_pub) = self._remove_batch(elements, sk, state)?;
        Ok(Self(acc_pub))
    }

    pub fn batch_updates(
        &self,
        additions: Vec<E::ScalarField>,
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        for element in additions.iter() {
            self.check_before_add(element, state)?;
        }
        for element in removals {
            self.check_before_remove(element, state)?;
        }
        let (_, acc_pub) = self._compute_new_post_remove_batch(removals, sk);
        for element in additions {
            state.add(element);
        }
        for element in removals {
            state.remove(element);
        }
        Ok(NonAdaptivePositiveAccumulator(acc_pub))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{persistence::test::*, prelude::SetupParams, setup::Keypair, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn membership() {
        // Test to check membership in accumulator
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
        let mut accumulator = NonAdaptivePositiveAccumulator::initialize(&mut rng, &params);
        let mut state = InMemoryState::new();
        test_serialization!(NonAdaptivePositiveAccumulator<Bls12_381>, accumulator);

        let count = 100;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err());

            assert!(!state.has(&elem));
            let old_accum = accumulator.value().clone();
            accumulator.add(elem.clone(), &mut state).unwrap();
            assert_eq!(old_accum, *accumulator.value());
            assert!(state.has(&elem));

            assert!(accumulator.add(elem, &mut state).is_err());

            let m_wit = accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .unwrap();
            let mut expected_V = m_wit.0.into_group();
            expected_V *= elem + keypair.secret_key.0;
            assert_eq!(expected_V, *accumulator.value());

            let verification_accumulator =
                NonAdaptivePositiveAccumulator::from_accumulated(*accumulator.value());
            assert!(verification_accumulator.verify_membership(
                &elem,
                &m_wit,
                &keypair.public_key,
                &params
            ));

            elems.push(elem);
        }

        for elem in elems {
            assert!(state.has(&elem));
            let old_accum = accumulator.value().clone();
            accumulator = accumulator
                .remove(&elem, &keypair.secret_key, &mut state)
                .unwrap();
            assert_eq!(
                old_accum * (keypair.secret_key.0 + elem).inverse().unwrap(),
                *accumulator.value()
            );
            assert!(!state.has(&elem));
            assert!(accumulator
                .get_membership_witness(&elem, &keypair.secret_key, &state)
                .is_err())
        }
    }

    #[test]
    fn batch_update_and_membership() {
        // Tests batch updates to accumulator and batch membership witness generation
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
        let mut accumulator_1 =
            NonAdaptivePositiveAccumulator::<Bls12_381>::initialize(&mut rng, &params);
        let mut state_1 = InMemoryState::new();

        // Create more accumulators to compare. Same elements will be added and removed from them as accumulator_1
        let mut accumulator_2 = accumulator_1.clone();
        let mut state_2 = InMemoryState::<Fr>::new();
        let mut accumulator_3 = accumulator_1.clone();
        let mut state_3 = InMemoryState::<Fr>::new();
        let mut accumulator_4 = accumulator_1.clone();
        let mut state_4 = InMemoryState::<Fr>::new();

        let additions: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let removals: Vec<Fr> = vec![0, 1, 6, 9].into_iter().map(|i| additions[i]).collect();

        let mut old: <Bls12_381 as Pairing>::G1Affine = *accumulator_1.value();
        // Add one by one
        for i in 0..additions.len() {
            let elem = additions[i];
            accumulator_1.add(elem, &mut state_1).unwrap();
        }

        // Adding does not change accumulator
        assert_eq!(*accumulator_1.value(), old);

        // Add as a batch
        accumulator_2
            .add_batch(additions.clone(), &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove(&removals[i], &keypair.secret_key, &mut state_1)
                .unwrap();
        }

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
            accumulator_3.add(*e, &mut state_3).unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove in a single call as a batch
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

        let verification_accumulator =
            NonAdaptivePositiveAccumulator::from_accumulated(*accumulator_3.value());
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

        // Add a batch
        old = *accumulator_4.value();
        accumulator_4 = accumulator_4
            .batch_updates(additions, &[], &keypair.secret_key, &mut state_4)
            .unwrap();
        assert_eq!(old, *accumulator_4.value());

        // Remove a batch
        accumulator_4 = accumulator_4
            .batch_updates(vec![], &removals, &keypair.secret_key, &mut state_4)
            .unwrap();
        // Effect should be same as that of adding and removing them together
        assert_eq!(*accumulator_1.value(), *accumulator_4.value());
        assert_eq!(state_1.db, state_4.db);

        let verification_accumulator =
            NonAdaptivePositiveAccumulator::from_accumulated(*accumulator_4.value());
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
}
