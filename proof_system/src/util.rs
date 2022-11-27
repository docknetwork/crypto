#[macro_export]
macro_rules! impl_serialize_witness {
    () => {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    CanonicalSerialize::serialize(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::PedersenCommitment(s) => {
                    CanonicalSerialize::serialize(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::Saver(s) => {
                    CanonicalSerialize::serialize(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    CanonicalSerialize::serialize(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    CanonicalSerialize::serialize(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
                Self::Saver(s) => 4u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16(s) => 5u8.serialized_size() + s.serialized_size(),
                Self::R1CSLegoGroth16(s) => 6u8.serialized_size() + s.serialized_size(),
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
                Self::Saver(s) => {
                    4u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    5u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    6u8.serialize_uncompressed(&mut writer)?;
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
                Self::Saver(s) => {
                    4u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    5u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    6u8.serialize_unchecked(&mut writer)?;
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
                Self::Saver(s) => 4u8.uncompressed_size() + s.uncompressed_size(),
                Self::BoundCheckLegoGroth16(s) => 5u8.uncompressed_size() + s.uncompressed_size(),
                Self::R1CSLegoGroth16(s) => 6u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    };
}

#[macro_export]
macro_rules! impl_deserialize_witness {
    () => {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::PoKBBSSignatureG1(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize(&mut reader)?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize_uncompressed(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize_unchecked(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    };
}

#[macro_export]
macro_rules! impl_serialize_statement_proof {
    () => {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    CanonicalSerialize::serialize(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::PedersenCommitment(s) => {
                    CanonicalSerialize::serialize(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::Saver(s) => {
                    CanonicalSerialize::serialize(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    CanonicalSerialize::serialize(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    CanonicalSerialize::serialize(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverWithAggregation(s) => {
                    CanonicalSerialize::serialize(&7u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    CanonicalSerialize::serialize(&8u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    CanonicalSerialize::serialize(&9u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
                Self::Saver(s) => 4u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16(s) => 5u8.serialized_size() + s.serialized_size(),
                Self::R1CSLegoGroth16(s) => 6u8.serialized_size() + s.serialized_size(),
                Self::SaverWithAggregation(s) => 7u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    8u8.serialized_size() + s.serialized_size()
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    9u8.serialized_size() + s.serialized_size()
                }
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
                Self::Saver(s) => {
                    4u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    5u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    6u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::SaverWithAggregation(s) => {
                    7u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    8u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    9u8.serialize_uncompressed(&mut writer)?;
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
                Self::Saver(s) => {
                    4u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    5u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::R1CSLegoGroth16(s) => {
                    6u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::SaverWithAggregation(s) => {
                    7u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    8u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    9u8.serialize_unchecked(&mut writer)?;
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
                Self::Saver(s) => 4u8.uncompressed_size() + s.uncompressed_size(),
                Self::BoundCheckLegoGroth16(s) => 5u8.uncompressed_size() + s.uncompressed_size(),
                Self::R1CSLegoGroth16(s) => 6u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverWithAggregation(s) => 7u8.uncompressed_size() + s.uncompressed_size(),
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    8u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    9u8.uncompressed_size() + s.uncompressed_size()
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_deserialize_statement_proof {
    () => {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::PoKBBSSignatureG1(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize(&mut reader)?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                7u8 => Ok(Self::SaverWithAggregation(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                8u8 => Ok(Self::BoundCheckLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                9u8 => Ok(Self::R1CSLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize_uncompressed(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                7u8 => Ok(Self::SaverWithAggregation(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                8u8 => Ok(Self::BoundCheckLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                9u8 => Ok(Self::R1CSLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize_unchecked(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                7u8 => Ok(Self::SaverWithAggregation(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                8u8 => Ok(Self::BoundCheckLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                9u8 => Ok(Self::R1CSLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    };
}

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
use legogroth16::{circom::R1CS, Proof as LegoProof, ProvingKey, VerifyingKey};
use saver::saver_groth16::Proof;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

use dock_crypto_utils::impl_for_groth16_struct;

impl_for_groth16_struct!(LegoProvingKeyBytes, ProvingKey, "expected LegoProvingKey");

impl_for_groth16_struct!(
    LegoVerifyingKeyBytes,
    VerifyingKey,
    "expected LegoVerifyingKey"
);

impl_for_groth16_struct!(ProofBytes, Proof, "expected Proof");
impl_for_groth16_struct!(LegoProofBytes, LegoProof, "expected LegoProofBytes");

impl_for_groth16_struct!(R1CSBytes, R1CS, "expected R1CS");
