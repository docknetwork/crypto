use crate::impl_collection;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};

pub use serialization::*;

/// Secret data known only to the prover and whose knowledge is to proven
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Witness<E: PairingEngine> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    AccumulatorMembership(Membership<E>),
    AccumulatorNonMembership(NonMembership<E>),
    PedersenCommitment(Vec<E::Fr>),
}

impl_collection!(Witnesses, Witness);

/// Secret data corresponding when proving knowledge of BBS+ sig
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub signature: BBSSignatureG1<E>,
    pub unrevealed_messages: BTreeMap<usize, E::Fr>,
}

/// Secret data corresponding when proving proving accumulator membership
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Membership<E: PairingEngine> {
    pub element: E::Fr,
    pub witness: MembershipWitness<E::G1Affine>,
}

/// Secret data corresponding when proving proving accumulator non-membership
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct NonMembership<E: PairingEngine> {
    pub element: E::Fr,
    pub witness: NonMembershipWitness<E::G1Affine>,
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

    // TODO: Following code contains duplication that can possible be removed using macros

    impl<E: PairingEngine> CanonicalSerialize for Witness<E> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize(&mut writer)?;
                    s.serialize(&mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorMembership(s) => 1u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorNonMembership(s) => {
                    2u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::PedersenCommitment(s) => 3u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl<E: PairingEngine> CanonicalDeserialize for Witness<E> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(Membership::<E>::deserialize(
                    &mut reader,
                )?)),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembership::<E>::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(Vec::<E::Fr>::deserialize(
                    &mut reader,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    Membership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    Vec::<E::Fr>::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    Membership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    Vec::<E::Fr>::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
