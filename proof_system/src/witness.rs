use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};

pub use serialization::*;

/// Secret data that the prover will prove knowledge of, this data is known only to the prover
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Witness<E: PairingEngine> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    AccumulatorMembership(Membership<E>),
    AccumulatorNonMembership(NonMembership<E>),
    PedersenCommitment(#[serde_as(as = "Vec<FieldBytes>")] Vec<E::Fr>),
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Witnesses<E>(pub Vec<Witness<E>>)
where
    E: PairingEngine;

/// Secret data corresponding when proving knowledge of BBS+ sig
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub signature: BBSSignatureG1<E>,
    #[serde_as(as = "BTreeMap<Same, FieldBytes>")]
    pub unrevealed_messages: BTreeMap<usize, E::Fr>,
}

/// Secret data corresponding when proving accumulator membership
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Membership<E: PairingEngine> {
    #[serde_as(as = "FieldBytes")]
    pub element: E::Fr,
    pub witness: MembershipWitness<E::G1Affine>,
}

/// Secret data corresponding when proving accumulator non-membership
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct NonMembership<E: PairingEngine> {
    #[serde_as(as = "FieldBytes")]
    pub element: E::Fr,
    pub witness: NonMembershipWitness<E::G1Affine>,
}

impl<E> Witnesses<E>
where
    E: PairingEngine,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Witness<E>) -> usize {
        self.0.push(item);
        self.0.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a `Witness` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_witness(
        signature: BBSSignatureG1<E>,
        unrevealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Witness<E> {
        Witness::PoKBBSSignatureG1(PoKBBSSignatureG1 {
            signature,
            unrevealed_messages,
        })
    }
}

/// Create a `Witness` variant for proving membership in accumulator
impl<E: PairingEngine> Membership<E> {
    pub fn new_as_witness(element: E::Fr, witness: MembershipWitness<E::G1Affine>) -> Witness<E> {
        Witness::AccumulatorMembership(Membership { element, witness })
    }
}

/// Create a `Witness` variant for proving non-membership in accumulator
impl<E: PairingEngine> NonMembership<E> {
    pub fn new_as_witness(
        element: E::Fr,
        witness: NonMembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorNonMembership(NonMembership { element, witness })
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine> CanonicalSerialize for Witness<E> {
        impl_serialize!();
    }

    impl<E: PairingEngine> CanonicalDeserialize for Witness<E> {
        impl_deserialize!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use crate::test_utils::sig_setup;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::ProjectiveCurve;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn witness_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (msgs, _, _, sig) = sig_setup(&mut rng, 5);

        let mut witnesses: Witnesses<Bls12_381> = Witnesses::new();

        let wit_1 = PoKBBSSignatureG1::new_as_witness(
            sig,
            msgs.into_iter()
                .enumerate()
                .map(|(i, m)| (i, m))
                .collect::<BTreeMap<usize, Fr>>(),
        );
        test_serialization!(Witness<Bls12_381>, wit_1);

        witnesses.add(wit_1);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_2 = Membership::new_as_witness(
            Fr::rand(&mut rng),
            MembershipWitness(G1Proj::rand(&mut rng).into_affine()),
        );
        test_serialization!(Witness<Bls12_381>, wit_2);

        witnesses.add(wit_2);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_3 = NonMembership::new_as_witness(
            Fr::rand(&mut rng),
            NonMembershipWitness {
                d: Fr::rand(&mut rng),
                C: G1Proj::rand(&mut rng).into_affine(),
            },
        );
        test_serialization!(Witness<Bls12_381>, wit_3);

        witnesses.add(wit_3);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_4 = Witness::PedersenCommitment(vec![
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ]);
        test_serialization!(Witness<Bls12_381>, wit_4);

        witnesses.add(wit_4);
        test_serialization!(Witnesses<Bls12_381>, witnesses);
    }
}
