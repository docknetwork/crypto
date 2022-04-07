use ark_ec::{AffineCurve, PairingEngine};
use ark_std::io::{Read, Write};
use serde::{Deserialize, Serialize};

pub mod bbs_plus;
pub mod bound_check_legogroth16;
pub mod ped_comm;
pub mod saver;
pub mod vb_accumulator;

pub use serialization::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum StatementV2<E: PairingEngine, G: AffineCurve> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(bbs_plus::PoKBBSSignatureG1<E>),
    PedersenCommitment(ped_comm::PedersenCommitment<G>),
    AccumulatorMembership(vb_accumulator::AccumulatorMembership<E>),
    AccumulatorNonMembership(vb_accumulator::AccumulatorNonMembership<E>),
    /// Proving verifiable encryption using SAVER
    SaverProver(saver::SaverProver<E>),
    SaverVerifier(saver::SaverVerifier<E>),
    /// Proving witness satisfies publicly known bounds inclusively (<=, >=).
    BoundCheckLegoGroth16Prover(bound_check_legogroth16::BoundCheckLegoGroth16Prover<E>),
    BoundCheckLegoGroth16Verifier(bound_check_legogroth16::BoundCheckLegoGroth16Verifier<E>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct StatementsV2<E, G>(pub Vec<StatementV2<E, G>>)
where
    E: PairingEngine,
    G: AffineCurve;

impl<E, G> StatementsV2<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: StatementV2<E, G>) -> usize {
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

mod serialization {
    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
    use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for StatementV2<E, G> {
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
                Self::SaverProver(s) => {
                    CanonicalSerialize::serialize(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverVerifier(s) => {
                    CanonicalSerialize::serialize(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    CanonicalSerialize::serialize(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    CanonicalSerialize::serialize(&7u8, &mut writer)?;
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
                Self::SaverProver(s) => 4u8.serialized_size() + s.serialized_size(),
                Self::SaverVerifier(s) => 5u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16Prover(s) => 6u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialized_size() + s.serialized_size()
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
                Self::SaverProver(s) => {
                    4u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::SaverVerifier(s) => {
                    5u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialize_uncompressed(&mut writer)?;
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
                Self::SaverProver(s) => {
                    4u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::SaverVerifier(s) => {
                    5u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialize_unchecked(&mut writer)?;
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
                Self::SaverProver(s) => 4u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverVerifier(s) => 5u8.uncompressed_size() + s.uncompressed_size(),
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.uncompressed_size() + s.uncompressed_size()
                }
            }
        }
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for StatementV2<E, G> {
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
                4u8 => Ok(Self::SaverProver(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::SaverVerifier(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
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
                4u8 => Ok(Self::SaverProver(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                5u8 => Ok(Self::SaverVerifier(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
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
                4u8 => Ok(Self::SaverProver(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                5u8 => Ok(Self::SaverVerifier(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
