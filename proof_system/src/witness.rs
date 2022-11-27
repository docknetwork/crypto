use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    cmp,
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    string::String,
    vec::Vec,
};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};
use zeroize::Zeroize;

use crate::error::ProofSystemError;
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
    /// Message being encrypted
    Saver(#[serde_as(as = "FieldBytes")] E::Fr),
    /// Message whose bounds are checked
    BoundCheckLegoGroth16(#[serde_as(as = "FieldBytes")] E::Fr),
    R1CSLegoGroth16(R1CSCircomWitness<E>),
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Witnesses<E>(pub Vec<Witness<E>>)
where
    E: PairingEngine;

/// Secret data when proving knowledge of BBS+ sig
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

impl<E: PairingEngine> Zeroize for PoKBBSSignatureG1<E> {
    fn zeroize(&mut self) {
        self.signature.zeroize();
        self.unrevealed_messages
            .values_mut()
            .for_each(|v| v.zeroize());
    }
}

impl<E: PairingEngine> Drop for PoKBBSSignatureG1<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secret data when proving accumulator membership
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

impl<E: PairingEngine> Zeroize for Membership<E> {
    fn zeroize(&mut self) {
        self.element.zeroize();
        self.witness.zeroize();
    }
}

impl<E: PairingEngine> Drop for Membership<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secret data when proving accumulator non-membership
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

impl<E: PairingEngine> Zeroize for NonMembership<E> {
    fn zeroize(&mut self) {
        self.element.zeroize();
        self.witness.zeroize();
    }
}

impl<E: PairingEngine> Drop for NonMembership<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Witness for the Circom program. Only contains circuit wires that are explicitly set by the prover
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSCircomWitness<E: PairingEngine> {
    /// Map of name -> value(s) for all inputs including public and private
    #[serde_as(as = "BTreeMap<Same, Vec<FieldBytes>>")]
    pub inputs: BTreeMap<String, Vec<E::Fr>>,
    /// Names of the public inputs
    #[serde_as(as = "Vec<Same>")]
    pub public: Vec<String>,
    /// Names of the private inputs
    #[serde_as(as = "Vec<Same>")]
    pub private: Vec<String>,
    pub public_count: usize,
    pub private_count: usize,
    pub total_count: usize,
}

impl<E: PairingEngine> Zeroize for R1CSCircomWitness<E> {
    fn zeroize(&mut self) {
        self.inputs.values_mut().for_each(|v| v.zeroize());
    }
}

impl<E: PairingEngine> Drop for R1CSCircomWitness<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
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

impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    /// Create a `Witness` variant for proving knowledge of BBS+ signature
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

impl<E: PairingEngine> Membership<E> {
    /// Create a `Witness` variant for proving membership in accumulator
    pub fn new_as_witness(element: E::Fr, witness: MembershipWitness<E::G1Affine>) -> Witness<E> {
        Witness::AccumulatorMembership(Membership { element, witness })
    }
}

impl<E: PairingEngine> NonMembership<E> {
    /// Create a `Witness` variant for proving non-membership in accumulator
    pub fn new_as_witness(
        element: E::Fr,
        witness: NonMembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorNonMembership(NonMembership { element, witness })
    }
}

impl<E: PairingEngine> R1CSCircomWitness<E> {
    pub fn new() -> Self {
        Self {
            inputs: BTreeMap::new(),
            public: Vec::new(),
            private: Vec::new(),
            public_count: 0,
            private_count: 0,
            total_count: 0,
        }
    }

    pub fn set_public(&mut self, name: String, value: Vec<E::Fr>) {
        self.total_count += value.len();
        self.public_count += value.len();
        self.public.push(name.clone());
        self.inputs.insert(name, value);
    }

    /// Set a private input signal. Ensure that this function is called for signals
    /// in the same order as they are declared in the circuit.
    pub fn set_private(&mut self, name: String, value: Vec<E::Fr>) {
        self.total_count += value.len();
        self.private_count += value.len();
        self.private.push(name.clone());
        self.inputs.insert(name, value);
    }

    /// Get the 1st `n` private inputs to the circuit. The order is determined by the order in which
    /// `Self::set_private` was called.
    pub fn get_first_n_private_inputs(&self, n: usize) -> Result<Vec<E::Fr>, ProofSystemError> {
        if self.private_count < n {
            return Err(ProofSystemError::R1CSInsufficientPrivateInputs(
                self.private_count,
                n,
            ));
        }
        let mut inputs = Vec::with_capacity(n);
        for name in self.private.iter() {
            if n == inputs.len() {
                break;
            }
            let vals = self.inputs.get(name).unwrap();
            let m = cmp::min(n - inputs.len(), vals.len());
            inputs.extend_from_slice(&vals[0..m]);
        }
        Ok(inputs)
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine> CanonicalSerialize for Witness<E> {
        impl_serialize_witness!();
    }

    impl<E: PairingEngine> CanonicalDeserialize for Witness<E> {
        impl_deserialize_witness!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::ProjectiveCurve;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use test_utils::bbs_plus::sig_setup;
    use test_utils::test_serialization;

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
