use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cmp, collections::BTreeMap, fmt::Debug, string::String, vec::Vec};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use dock_crypto_utils::serde_utils::*;
use ps_signature::Signature;
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
pub enum Witness<E: Pairing> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    AccumulatorMembership(Membership<E>),
    AccumulatorNonMembership(NonMembership<E>),
    PedersenCommitment(#[serde_as(as = "Vec<ArkObjectBytes>")] Vec<E::ScalarField>),
    /// Message being encrypted
    Saver(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    /// Message whose bounds are checked
    BoundCheckLegoGroth16(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    R1CSLegoGroth16(R1CSCircomWitness<E>),
    PoKPSSignature(PoKPSSignature<E>),
}

macro_rules! delegate {
    ($([$idx: ident])? $self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                PoKPSSignature
            : $($tt)+
        }
    }}
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                PoKPSSignature
            : $($tt)+
        }

        $err
    }}
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Witnesses<E>(pub Vec<Witness<E>>)
where
    E: Pairing;

/// Secret data when proving knowledge of PS sig
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKPSSignature<E: Pairing> {
    pub signature: Signature<E>,
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub unrevealed_messages: BTreeMap<usize, E::ScalarField>,
}

impl<E: Pairing> PoKPSSignature<E> {
    /// Create a `Witness` variant for proving knowledge of BBS+ signature
    pub fn new_as_witness(
        signature: Signature<E>,
        unrevealed_messages: BTreeMap<usize, E::ScalarField>,
    ) -> Witness<E> {
        Witness::PoKPSSignature(PoKPSSignature {
            signature,
            unrevealed_messages,
        })
    }
}

/// Secret data when proving knowledge of BBS+ sig
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: Pairing> {
    pub signature: BBSSignatureG1<E>,
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub unrevealed_messages: BTreeMap<usize, E::ScalarField>,
}

impl<E: Pairing> Zeroize for PoKBBSSignatureG1<E> {
    fn zeroize(&mut self) {
        self.signature.zeroize();
        self.unrevealed_messages
            .values_mut()
            .for_each(|v| v.zeroize());
    }
}

impl<E: Pairing> Drop for PoKBBSSignatureG1<E> {
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
pub struct Membership<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: E::ScalarField,
    pub witness: MembershipWitness<E::G1Affine>,
}

impl<E: Pairing> Zeroize for Membership<E> {
    fn zeroize(&mut self) {
        self.element.zeroize();
        self.witness.zeroize();
    }
}

impl<E: Pairing> Drop for Membership<E> {
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
pub struct NonMembership<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: E::ScalarField,
    pub witness: NonMembershipWitness<E::G1Affine>,
}

impl<E: Pairing> Zeroize for NonMembership<E> {
    fn zeroize(&mut self) {
        self.element.zeroize();
        self.witness.zeroize();
    }
}

impl<E: Pairing> Drop for NonMembership<E> {
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
pub struct R1CSCircomWitness<E: Pairing> {
    /// Map of name -> value(s) for all inputs including public and private
    #[serde_as(as = "BTreeMap<Same, Vec<ArkObjectBytes>>")]
    pub inputs: BTreeMap<String, Vec<E::ScalarField>>,
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

impl<E: Pairing> Zeroize for R1CSCircomWitness<E> {
    fn zeroize(&mut self) {
        self.inputs.values_mut().for_each(|v| v.zeroize());
    }
}

impl<E: Pairing> Drop for R1CSCircomWitness<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<E> Witnesses<E>
where
    E: Pairing,
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

impl<E: Pairing> PoKBBSSignatureG1<E> {
    /// Create a `Witness` variant for proving knowledge of BBS+ signature
    pub fn new_as_witness(
        signature: BBSSignatureG1<E>,
        unrevealed_messages: BTreeMap<usize, E::ScalarField>,
    ) -> Witness<E> {
        Witness::PoKBBSSignatureG1(PoKBBSSignatureG1 {
            signature,
            unrevealed_messages,
        })
    }
}

impl<E: Pairing> Membership<E> {
    /// Create a `Witness` variant for proving membership in accumulator
    pub fn new_as_witness(
        element: E::ScalarField,
        witness: MembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorMembership(Membership { element, witness })
    }
}

impl<E: Pairing> NonMembership<E> {
    /// Create a `Witness` variant for proving non-membership in accumulator
    pub fn new_as_witness(
        element: E::ScalarField,
        witness: NonMembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorNonMembership(NonMembership { element, witness })
    }
}

impl<E: Pairing> R1CSCircomWitness<E> {
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

    pub fn set_public(&mut self, name: String, value: Vec<E::ScalarField>) {
        self.total_count += value.len();
        self.public_count += value.len();
        self.public.push(name.clone());
        self.inputs.insert(name, value);
    }

    /// Set a private input signal. Ensure that this function is called for signals
    /// in the same order as they are declared in the circuit.
    pub fn set_private(&mut self, name: String, value: Vec<E::ScalarField>) {
        self.total_count += value.len();
        self.private_count += value.len();
        self.private.push(name.clone());
        self.inputs.insert(name, value);
    }

    /// Get the 1st `n` private inputs to the circuit. The order is determined by the order in which
    /// `Self::set_private` was called.
    pub fn get_first_n_private_inputs(
        &self,
        n: usize,
    ) -> Result<Vec<E::ScalarField>, ProofSystemError> {
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
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
    };
    use ark_std::io::{Read, Write};

    impl<E: Pairing> Valid for Witness<E> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing> CanonicalSerialize for Witness<E> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            delegate!([index]self with variant as s {
                CanonicalSerialize::serialize_with_mode(&index, &mut writer, compress)?;
                CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
            })
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            delegate!([index]self: |statement| {
                index.serialized_size(compress) + CanonicalSerialize::serialized_size(statement, compress)
            })
        }
    }

    impl<E: Pairing> CanonicalDeserialize for Witness<E> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let idx: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

            delegate_reverse!(
                idx or else Err(SerializationError::InvalidData) => with variant as build
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate).map(build)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::CurveGroup;
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
