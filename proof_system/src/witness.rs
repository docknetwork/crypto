use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cmp, collections::BTreeMap, fmt::Debug, string::String, vec::Vec};
use bbs_plus::{
    signature::SignatureG1 as BBSSignatureG1, signature_23::Signature23G1 as BBSSignature23G1,
};
use coconut_crypto::Signature;
use dock_crypto_utils::serde_utils::*;
use kvac::bddt_2016::mac::MAC;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ProofSystemError;

/// Secret data that the prover will prove knowledge of, this data is known only to the prover
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Witness<E: Pairing> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    VBAccumulatorMembership(Membership<E::G1Affine>),
    VBAccumulatorNonMembership(NonMembership<E::G1Affine>),
    PedersenCommitment(#[serde_as(as = "Vec<ArkObjectBytes>")] Vec<E::ScalarField>),
    /// Message being encrypted
    Saver(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    /// Message whose bounds are checked
    BoundCheckLegoGroth16(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    R1CSLegoGroth16(R1CSCircomWitness<E>),
    PoKPSSignature(PoKPSSignature<E>),
    PoKBBSSignature23G1(PoKBBSSignature23G1<E>),
    /// For bound check using Bulletproofs++ protocol. Its the message whose bounds are checked
    BoundCheckBpp(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    BoundCheckSmc(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    BoundCheckSmcWithKV(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    PublicInequality(#[serde_as(as = "ArkObjectBytes")] E::ScalarField),
    KBUniAccumulatorMembership(KBUniMembership<E::G1Affine>),
    KBUniAccumulatorNonMembership(KBUniNonMembership<E::G1Affine>),
    KBPosAccumulatorMembership(KBPosMembership<E>),
    PoKOfBDDT16MAC(PoKOfBDDT16MAC<E::G1Affine>),
}

macro_rules! delegate {
    ($([$idx: ident])? $self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                PoKBBSSignatureG1,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                PoKPSSignature,
                PoKBBSSignature23G1,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKV,
                PublicInequality,
                KBUniAccumulatorMembership,
                KBUniAccumulatorNonMembership,
                KBPosAccumulatorMembership,
                PoKOfBDDT16MAC
            : $($tt)+
        }
    }}
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                PoKBBSSignatureG1,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                PoKPSSignature,
                PoKBBSSignature23G1,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKV,
                PublicInequality,
                KBUniAccumulatorMembership,
                KBUniAccumulatorNonMembership,
                KBPosAccumulatorMembership,
                PoKOfBDDT16MAC
            : $($tt)+
        }

        $err
    }}
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Witnesses<E: Pairing>(pub Vec<Witness<E>>);

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
            .for_each(|v| v.zeroize())
    }
}

impl<E: Pairing> Drop for PoKBBSSignatureG1<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secret data when proving knowledge of BBS sig
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignature23G1<E: Pairing> {
    pub signature: BBSSignature23G1<E>,
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub unrevealed_messages: BTreeMap<usize, E::ScalarField>,
}

impl<E: Pairing> Zeroize for PoKBBSSignature23G1<E> {
    fn zeroize(&mut self) {
        self.signature.zeroize();
        self.unrevealed_messages
            .values_mut()
            .for_each(|v| v.zeroize())
    }
}

impl<E: Pairing> Drop for PoKBBSSignature23G1<E> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secret data when proving VB accumulator membership
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct Membership<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: G::ScalarField,
    pub witness: MembershipWitness<G>,
}

/// Secret data when proving VB accumulator non-membership
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct NonMembership<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: G::ScalarField,
    pub witness: NonMembershipWitness<G>,
}

/// Secret data when proving KB universal accumulator membership
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct KBUniMembership<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: G::ScalarField,
    pub witness:
        vb_accumulator::kb_universal_accumulator::witness::KBUniversalAccumulatorMembershipWitness<
            G,
        >,
}

/// Secret data when proving KB universal accumulator non-membership
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct KBUniNonMembership<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: G::ScalarField,
    pub witness: vb_accumulator::kb_universal_accumulator::witness::KBUniversalAccumulatorNonMembershipWitness<G>,
}

/// Secret data when proving KB universal accumulator membership
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct KBPosMembership<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: E::ScalarField,
    pub witness: vb_accumulator::kb_positive_accumulator::witness::KBPositiveAccumulatorWitness<E>,
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

impl<E: Pairing> Witnesses<E> {
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
        Witness::PoKBBSSignatureG1(Self {
            signature,
            unrevealed_messages,
        })
    }
}

impl<E: Pairing> PoKBBSSignature23G1<E> {
    /// Create a `Witness` variant for proving knowledge of BBS signature
    pub fn new_as_witness(
        signature: BBSSignature23G1<E>,
        unrevealed_messages: BTreeMap<usize, E::ScalarField>,
    ) -> Witness<E> {
        Witness::PoKBBSSignature23G1(Self {
            signature,
            unrevealed_messages,
        })
    }
}

impl<G: AffineRepr> Membership<G> {
    /// Create a `Witness` variant for proving membership in VB accumulator
    pub fn new_as_witness<E: Pairing<G1Affine = G>>(
        element: G::ScalarField,
        witness: MembershipWitness<G>,
    ) -> Witness<E> {
        Witness::VBAccumulatorMembership(Self { element, witness })
    }
}

impl<G: AffineRepr> NonMembership<G> {
    /// Create a `Witness` variant for proving non-membership in VB accumulator
    pub fn new_as_witness<E: Pairing<G1Affine = G>>(
        element: G::ScalarField,
        witness: NonMembershipWitness<G>,
    ) -> Witness<E> {
        Witness::VBAccumulatorNonMembership(Self { element, witness })
    }
}

impl<G: AffineRepr> KBUniMembership<G> {
    /// Create a `Witness` variant for proving membership in KB universal accumulator
    pub fn new_as_witness<E: Pairing<G1Affine = G>>(
        element: G::ScalarField,
        witness: vb_accumulator::kb_universal_accumulator::witness::KBUniversalAccumulatorMembershipWitness<G>,
    ) -> Witness<E> {
        Witness::KBUniAccumulatorMembership(Self { element, witness })
    }
}

impl<G: AffineRepr> KBUniNonMembership<G> {
    /// Create a `Witness` variant for proving non-membership in KB universal accumulator
    pub fn new_as_witness<E: Pairing<G1Affine = G>>(
        element: G::ScalarField,
        witness: vb_accumulator::kb_universal_accumulator::witness::KBUniversalAccumulatorNonMembershipWitness<G>,
    ) -> Witness<E> {
        Witness::KBUniAccumulatorNonMembership(Self { element, witness })
    }
}

impl<E: Pairing> KBPosMembership<E> {
    /// Create a `Witness` variant for proving non-membership in KB universal accumulator
    pub fn new_as_witness(
        element: E::ScalarField,
        witness: vb_accumulator::kb_positive_accumulator::witness::KBPositiveAccumulatorWitness<E>,
    ) -> Witness<E> {
        Witness::KBPosAccumulatorMembership(Self { element, witness })
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
        n: u32,
    ) -> Result<Vec<E::ScalarField>, ProofSystemError> {
        if self.private_count < n as usize {
            return Err(ProofSystemError::R1CSInsufficientPrivateInputs(
                self.private_count as usize,
                n as usize,
            ));
        }
        let mut inputs = Vec::with_capacity(n as usize);
        for name in self.private.iter() {
            if n as usize == inputs.len() {
                break;
            }
            let vals = self.inputs.get(name).unwrap();
            let m = cmp::min(n as usize - inputs.len(), vals.len());
            inputs.extend_from_slice(&vals[0..m]);
        }
        Ok(inputs)
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKOfBDDT16MAC<G: AffineRepr> {
    pub mac: MAC<G>,
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub unrevealed_messages: BTreeMap<usize, G::ScalarField>,
}

impl<G: AffineRepr> PoKOfBDDT16MAC<G> {
    pub fn new_as_witness<E: Pairing<G1Affine = G>>(
        mac: MAC<G>,
        unrevealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Witness<E> {
        Witness::PoKOfBDDT16MAC(PoKOfBDDT16MAC {
            mac,
            unrevealed_messages,
        })
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
            delegate!([index]self with variant as witness {
                CanonicalSerialize::serialize_with_mode(&index, &mut writer, compress)?;
                CanonicalSerialize::serialize_with_mode(witness, &mut writer, compress)
            })
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            delegate!([index]self with variant as witness {
                index.serialized_size(compress) + CanonicalSerialize::serialized_size(witness, compress)
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
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj, Bls12_381};
    use ark_ec::CurveGroup;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use test_utils::{
        bbs::{bbs_plus_sig_setup, bbs_sig_setup},
        test_serialization,
    };

    #[test]
    fn witness_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0);
        let (msgs, _, _, sig) = bbs_plus_sig_setup(&mut rng, 5);
        let (msgs_23, _, _, sig_23) = bbs_sig_setup(&mut rng, 5);

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

        let wit_5 = PoKBBSSignature23G1::new_as_witness(
            sig_23,
            msgs_23
                .into_iter()
                .enumerate()
                .map(|(i, m)| (i, m))
                .collect::<BTreeMap<usize, Fr>>(),
        );
        test_serialization!(Witness<Bls12_381>, wit_5);

        witnesses.add(wit_5);
        test_serialization!(Witnesses<Bls12_381>, witnesses);
    }
}
