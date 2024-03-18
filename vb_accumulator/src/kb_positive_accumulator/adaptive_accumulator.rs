//! An adaptive positive accumulator contructed from a non-adaptive accumulator and BB signature scheme. Adding an element to the accumulator
//! involves creating a BB signature over that element and adding the randomness from the signature in the non-adaptive accumulator.
//! This adaptive accumulator's witness comprises of the BB signature and the witness in the non-adaptive accumulator. Adding to
//! this accumulator does not change its value but removing does. Same for existing witnesses, it does not change on addition but removal

use crate::{
    error::VBAccumulatorError,
    kb_positive_accumulator::non_adaptive_accumulator::NonAdaptivePositiveAccumulator,
    persistence::State,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec::Vec};
use digest::DynDigest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::bb_sig::SignatureG1 as BBSig;

use crate::positive::Accumulator;

use crate::kb_positive_accumulator::setup::{PublicKey, SecretKey, SetupParams};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::kb_positive_accumulator::witness::KBPositiveAccumulatorWitness;

/// A dynamic positive accumulator
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct KBPositiveAccumulator<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub NonAdaptivePositiveAccumulator<E>,
);

impl<E: Pairing> KBPositiveAccumulator<E> {
    pub fn initialize<R: RngCore>(rng: &mut R, params_gen: impl AsRef<E::G1Affine>) -> Self {
        Self(NonAdaptivePositiveAccumulator::initialize(rng, params_gen))
    }

    /// Add an element to the accumulator. Returns the membership witness of that element
    pub fn add<D: Default + DynDigest + Clone>(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SetupParams<E>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<KBPositiveAccumulatorWitness<E>, VBAccumulatorError> {
        let signature = BBSig::new_deterministic::<D>(element, &sk.sig, &params.sig);
        self.0.add(signature.1.clone(), state)?;
        let accum_witness = self
            .0
            .get_membership_witness(&signature.1, &sk.accum, state)?;
        Ok(KBPositiveAccumulatorWitness {
            signature,
            accum_witness,
        })
    }

    /// Removes an element from the accumulator. Returns the new value of the accumulator
    pub fn remove<D: Default + DynDigest + Clone>(
        &self,
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let member = Self::accumulator_member::<D>(element, sk);
        let new = self.0.remove(&member, &sk.accum, state)?;
        Ok(Self(new))
    }

    /// Add a batch of elements to the accumulator. Returns the membership witness of that batch
    pub fn add_batch<D: Default + DynDigest + Clone>(
        &self,
        elements: Vec<E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        params: &SetupParams<E>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Vec<KBPositiveAccumulatorWitness<E>>, VBAccumulatorError> {
        let sigs = cfg_into_iter!(elements)
            .map(|e| BBSig::new_deterministic::<D>(&e, &sk.sig, &params.sig))
            .collect::<Vec<_>>();
        let members = cfg_iter!(sigs).map(|s| s.1).collect::<Vec<_>>();
        let w = self
            .0
            .compute_membership_witnesses_for_batch(&members, &sk.accum);
        self.0.add_batch(members, state)?;
        let wits = cfg_into_iter!(sigs)
            .zip(cfg_into_iter!(w))
            .map(|(signature, accum_witness)| KBPositiveAccumulatorWitness {
                signature,
                accum_witness,
            })
            .collect::<Vec<_>>();
        Ok(wits)
    }

    /// Removes a batch of elements from the accumulator. Returns the new value of the accumulator
    pub fn remove_batch<D: Default + DynDigest + Clone>(
        &self,
        elements: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let members = cfg_into_iter!(elements)
            .map(|element| Self::accumulator_member::<D>(element, sk))
            .collect::<Vec<_>>();
        let new = self.0.remove_batch(&members, &sk.accum, state)?;
        Ok(Self(new))
    }

    /// Add and removes batches of elements. Returns the new accumulator value and the membership witnesses of the added batch.
    pub fn batch_updates<D: Default + DynDigest + Clone>(
        &self,
        additions: Vec<E::ScalarField>,
        removals: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        params: &SetupParams<E>,
        state: &mut dyn State<E::ScalarField>,
    ) -> Result<(Self, Vec<KBPositiveAccumulatorWitness<E>>), VBAccumulatorError> {
        let sigs = cfg_into_iter!(additions)
            .map(|e| BBSig::new_deterministic::<D>(&e, &sk.sig, &params.sig))
            .collect::<Vec<_>>();
        let additions = cfg_iter!(sigs).map(|s| s.1).collect::<Vec<_>>();
        let removals = cfg_into_iter!(removals)
            .map(|element| Self::accumulator_member::<D>(element, sk))
            .collect::<Vec<_>>();
        let new = KBPositiveAccumulator(self.0.remove_batch(&removals, &sk.accum, state)?);
        let w = new
            .0
            .compute_membership_witnesses_for_batch(&additions, &sk.accum);
        self.0.add_batch(additions, state)?;
        let wits = cfg_into_iter!(sigs)
            .zip(cfg_into_iter!(w))
            .map(|(signature, accum_witness)| KBPositiveAccumulatorWitness {
                signature,
                accum_witness,
            })
            .collect::<Vec<_>>();
        Ok((new, wits))
    }

    /// Get membership witness of an element
    pub fn get_witness<D: Default + DynDigest + Clone>(
        &self,
        member: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SetupParams<E>,
        state: &dyn State<E::ScalarField>,
    ) -> Result<KBPositiveAccumulatorWitness<E>, VBAccumulatorError> {
        let signature = BBSig::new_deterministic::<D>(member, &sk.sig, &params.sig);
        let accum_witness = self
            .0
            .get_membership_witness(&signature.1, &sk.accum, state)?;
        Ok(KBPositiveAccumulatorWitness {
            signature,
            accum_witness,
        })
    }

    pub fn get_witnesses_for_batch<D: Default + DynDigest + Clone>(
        &self,
        members: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        params: &SetupParams<E>,
        state: &dyn State<E::ScalarField>,
    ) -> Result<Vec<KBPositiveAccumulatorWitness<E>>, VBAccumulatorError> {
        let sigs = cfg_into_iter!(members)
            .map(|e| BBSig::new_deterministic::<D>(e, &sk.sig, &params.sig))
            .collect::<Vec<_>>();
        let members = cfg_iter!(sigs).map(|s| s.1).collect::<Vec<_>>();
        let w = self
            .0
            .get_membership_witnesses_for_batch(&members, &sk.accum, state)?;
        let wits = cfg_into_iter!(sigs)
            .zip(cfg_into_iter!(w))
            .map(|(signature, accum_witness)| KBPositiveAccumulatorWitness {
                signature,
                accum_witness,
            })
            .collect::<Vec<_>>();
        Ok(wits)
    }

    pub fn verify_membership(
        &self,
        member: &E::ScalarField,
        witness: &KBPositiveAccumulatorWitness<E>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
    ) -> Result<(), VBAccumulatorError> {
        witness.signature.verify(member, &pk.sig, &params.sig)?;
        self.0
            .verify_membership(
                witness.get_accumulator_member(),
                &witness.accum_witness,
                &pk.accum,
                &params.accum,
            )
            .then(|| ())
            .ok_or(VBAccumulatorError::InvalidWitness)
    }

    pub fn value(&self) -> &E::G1Affine {
        &self.0 .0
    }

    pub fn from_accumulated(accumulated: E::G1Affine) -> Self {
        Self(NonAdaptivePositiveAccumulator(accumulated))
    }

    /// The value corresponding to `element` that is added to the non-adaptive accumulator
    pub fn accumulator_member<D: Default + DynDigest + Clone>(
        element: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
    ) -> E::ScalarField {
        BBSig::<E>::generate_random_for_message::<D>(element, &sk.sig)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{persistence::test::*, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    pub fn setup_kb_positive_accum(
        rng: &mut StdRng,
    ) -> (
        SetupParams<Bls12_381>,
        SecretKey<Fr>,
        PublicKey<Bls12_381>,
        KBPositiveAccumulator<Bls12_381>,
        InMemoryState<Fr>,
    ) {
        let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
        let sk = SecretKey::new(rng);
        let pk = PublicKey::new(&sk, &params);
        let accumulator = KBPositiveAccumulator::initialize(rng, &params.accum);
        let state = InMemoryState::new();
        (params, sk, pk, accumulator, state)
    }

    #[test]
    fn membership() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, mut accumulator, mut state) = setup_kb_positive_accum(&mut rng);
        test_serialization!(KBPositiveAccumulator<Bls12_381>, accumulator);

        let count = 10;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            assert!(accumulator
                .get_witness::<Blake2b512>(&elem, &sk, &params, &state)
                .is_err());

            let accum_member =
                KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(&elem, &sk);
            assert!(!state.has(&accum_member));
            let wit = accumulator
                .add::<Blake2b512>(&elem, &sk, &params, &mut state)
                .unwrap();
            assert!(state.has(&accum_member));

            assert!(accumulator
                .add::<Blake2b512>(&elem, &sk, &params, &mut state)
                .is_err());

            let m_wit = accumulator
                .get_witness::<Blake2b512>(&elem, &sk, &params, &mut state)
                .unwrap();
            let mut expected_V = m_wit.accum_witness.0.into_group();
            expected_V *= accum_member + sk.accum.0;
            assert_eq!(expected_V, *accumulator.value());

            assert_eq!(m_wit, wit);

            let verification_accumulator =
                KBPositiveAccumulator::from_accumulated(*accumulator.value());
            verification_accumulator
                .verify_membership(&elem, &m_wit, &pk, &params)
                .unwrap();

            elems.push(elem);
        }

        for elem in elems {
            let accum_member =
                KBPositiveAccumulator::<Bls12_381>::accumulator_member::<Blake2b512>(&elem, &sk);
            assert!(state.has(&accum_member));
            let old_accum = accumulator.value().clone();
            accumulator = accumulator
                .remove::<Blake2b512>(&elem, &sk, &mut state)
                .unwrap();
            assert_eq!(
                old_accum * (sk.accum.0 + accum_member).inverse().unwrap(),
                *accumulator.value()
            );
            assert!(!state.has(&elem));
            assert!(accumulator
                .get_witness::<Blake2b512>(&elem, &sk, &params, &mut state)
                .is_err())
        }
    }

    #[test]
    fn batch_update_and_membership() {
        // Tests batch updates to accumulator and batch membership witness generation
        let mut rng = StdRng::seed_from_u64(0u64);
        let (params, sk, pk, mut accumulator_1, mut state_1) = setup_kb_positive_accum(&mut rng);

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
            accumulator_1
                .add::<Blake2b512>(&elem, &sk, &params, &mut state_1)
                .unwrap();
        }

        // Adding does not change accumulator
        assert_eq!(*accumulator_1.value(), old);

        // Add as a batch
        let wits = accumulator_2
            .add_batch::<Blake2b512>(additions.clone(), &sk, &params, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        for i in 0..additions.len() {
            accumulator_2
                .verify_membership(&additions[i], &wits[i], &pk, &params)
                .unwrap();
        }

        // Remove one by one
        for i in 0..removals.len() {
            accumulator_1 = accumulator_1
                .remove::<Blake2b512>(&removals[i], &sk, &mut state_1)
                .unwrap();
        }

        assert_ne!(*accumulator_1.value(), *accumulator_2.value());

        // Remove as a batch
        accumulator_2 = accumulator_2
            .remove_batch::<Blake2b512>(&removals, &sk, &mut state_2)
            .unwrap();
        assert_eq!(*accumulator_1.value(), *accumulator_2.value());
        assert_eq!(state_1.db, state_2.db);

        // Need to make `accumulator_3` same as `accumulator_1` and `accumulator_2` by doing batch addition and removal simultaneously.
        // To do the removals, first they need to be added to the accumulator and the additions elements need to be adjusted.
        let mut new_additions = additions.clone();
        for e in removals.iter() {
            accumulator_3
                .add::<Blake2b512>(e, &sk, &params, &mut state_3)
                .unwrap();
            new_additions.retain(|&x| x != *e);
        }

        assert_ne!(*accumulator_1.value(), *accumulator_3.value());
        assert_ne!(*accumulator_2.value(), *accumulator_3.value());

        // Add and remove in a single call as a batch
        let upd = accumulator_3
            .batch_updates::<Blake2b512>(
                new_additions.clone(),
                &removals,
                &sk,
                &params,
                &mut state_3,
            )
            .unwrap();
        accumulator_3 = upd.0;
        assert_eq!(*accumulator_1.value(), *accumulator_3.value());
        assert_eq!(*accumulator_2.value(), *accumulator_3.value());
        assert_eq!(state_1.db, state_3.db);
        assert_eq!(state_2.db, state_3.db);

        for i in 0..new_additions.len() {
            accumulator_3
                .verify_membership(&new_additions[i], &upd.1[i], &pk, &params)
                .unwrap();
        }

        let verification_accumulator =
            KBPositiveAccumulator::from_accumulated(*accumulator_3.value());
        let witnesses = accumulator_3
            .get_witnesses_for_batch::<Blake2b512>(&new_additions, &sk, &params, &state_3)
            .unwrap();
        for i in 0..new_additions.len() {
            verification_accumulator
                .verify_membership(&new_additions[i], &witnesses[i], &pk, &params)
                .unwrap();
        }

        // Add a batch
        old = *accumulator_4.value();
        let upd = accumulator_4
            .batch_updates::<Blake2b512>(additions.clone(), &[], &sk, &params, &mut state_4)
            .unwrap();
        accumulator_4 = upd.0;
        assert_eq!(old, *accumulator_4.value());
        for i in 0..additions.len() {
            accumulator_4
                .verify_membership(&additions[i], &upd.1[i], &pk, &params)
                .unwrap();
        }

        // Remove a batch
        let upd = accumulator_4
            .batch_updates::<Blake2b512>(vec![], &removals, &sk, &params, &mut state_4)
            .unwrap();
        accumulator_4 = upd.0;
        assert_eq!(upd.1.len(), 0);
        // Effect should be same as that of adding and removing them together
        assert_eq!(*accumulator_1.value(), *accumulator_4.value());
        assert_eq!(state_1.db, state_4.db);

        let verification_accumulator =
            KBPositiveAccumulator::from_accumulated(*accumulator_4.value());
        let witnesses = accumulator_4
            .get_witnesses_for_batch::<Blake2b512>(&new_additions, &sk, &params, &mut state_4)
            .unwrap();
        for i in 0..new_additions.len() {
            verification_accumulator
                .verify_membership(&new_additions[i], &witnesses[i], &pk, &params)
                .unwrap();
        }
    }
}
