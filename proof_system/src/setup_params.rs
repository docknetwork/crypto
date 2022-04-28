//! Represents (public) setup parameters of different protocols. Setup parameters (enum variants here) can
//! be either directly passed to the `Statement` or can be wrapped in this enum `SetupParams` and then a reference
//! to this enum is passed to the `Statement`. This enum is helpful when the same setup parameter needs to
//! be passed to several `Statement`s as it avoids the need of having several copies of the setup param. This
//! becomes more important when interacting with the WASM bindings of this crate as the overhead of repeated
//! serialization and de-serialization can be avoided.

use crate::statement::bound_check_legogroth16::{LegoProvingKeyBytes, LegoVerifyingKeyBytes};
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::vec::Vec;
use bbs_plus::prelude::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};
use legogroth16::data_structures::{
    ProvingKey as LegoSnarkProvingKey, VerifyingKey as LegoSnarkVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey as SaverSnarkProvingKey,
    VerifyingKey as SaverSnarkVerifyingKey,
};
use saver::saver_groth16::Groth16VerifyingKeyBytes;
use vb_accumulator::prelude::{
    MembershipProvingKey, NonMembershipProvingKey, PublicKey as AccumPublicKey,
    SetupParams as AccumParams,
};

use dock_crypto_utils::serde_utils::AffineGroupBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Holds (public) setup parameters of different protocols.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum SetupParams<E: PairingEngine, G: AffineCurve> {
    BBSPlusSignatureParams(BBSSignatureParamsG1<E>),
    BBSPlusPublicKey(BBSPublicKeyG2<E>),
    VbAccumulatorParams(AccumParams<E>),
    VbAccumulatorPublicKey(AccumPublicKey<E::G2Affine>),
    VbAccumulatorMemProvingKey(MembershipProvingKey<E::G1Affine>),
    VbAccumulatorNonMemProvingKey(NonMembershipProvingKey<E::G1Affine>),
    PedersenCommitmentKey(#[serde_as(as = "Vec<AffineGroupBytes>")] Vec<G>),
    SaverEncryptionGens(EncryptionGens<E>),
    SaverCommitmentGens(ChunkedCommitmentGens<E::G1Affine>),
    SaverEncryptionKey(EncryptionKey<E>),
    SaverProvingKey(SaverSnarkProvingKey<E>),
    SaverVerifyingKey(#[serde_as(as = "Groth16VerifyingKeyBytes")] SaverSnarkVerifyingKey<E>),
    LegoSnarkProvingKey(#[serde_as(as = "LegoProvingKeyBytes")] LegoSnarkProvingKey<E>),
    LegoSnarkVerifyingKey(#[serde_as(as = "LegoVerifyingKeyBytes")] LegoSnarkVerifyingKey<E>),
}

macro_rules! extract_param {
    ($setup_params: ident, $param: expr, $param_ref: expr, $param_variant: ident, $error_variant: ident, $statement_index: ident) => {{
        if let Some(sp) = $param {
            return Ok(sp);
        }
        if let Some(idx) = $param_ref {
            if idx < $setup_params.len() {
                match &$setup_params[idx] {
                    SetupParams::$param_variant(p) => Ok(p),
                    _ => Err(ProofSystemError::$error_variant(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven($statement_index))
        }
    }};
}

mod serialization {
    use super::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
    use ark_std::io::{Read, Write};

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for SetupParams<E, G> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::BBSPlusSignatureParams(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BBSPlusPublicKey(s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::VbAccumulatorParams(s) => {
                    CanonicalSerialize::serialize(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::VbAccumulatorPublicKey(s) => {
                    CanonicalSerialize::serialize(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::VbAccumulatorMemProvingKey(s) => {
                    CanonicalSerialize::serialize(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    CanonicalSerialize::serialize(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::PedersenCommitmentKey(s) => {
                    CanonicalSerialize::serialize(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverEncryptionGens(s) => {
                    CanonicalSerialize::serialize(&7u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverCommitmentGens(s) => {
                    CanonicalSerialize::serialize(&8u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverEncryptionKey(s) => {
                    CanonicalSerialize::serialize(&9u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverProvingKey(s) => {
                    CanonicalSerialize::serialize(&10u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverVerifyingKey(s) => {
                    CanonicalSerialize::serialize(&11u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::LegoSnarkProvingKey(s) => {
                    CanonicalSerialize::serialize(&12u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::LegoSnarkVerifyingKey(s) => {
                    CanonicalSerialize::serialize(&13u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::BBSPlusSignatureParams(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::BBSPlusPublicKey(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::VbAccumulatorParams(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::VbAccumulatorPublicKey(s) => 3u8.serialized_size() + s.serialized_size(),
                Self::VbAccumulatorMemProvingKey(s) => 4u8.serialized_size() + s.serialized_size(),
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    5u8.serialized_size() + s.serialized_size()
                }
                Self::PedersenCommitmentKey(s) => 6u8.serialized_size() + s.serialized_size(),
                Self::SaverEncryptionGens(s) => 7u8.serialized_size() + s.serialized_size(),
                Self::SaverCommitmentGens(s) => 8u8.serialized_size() + s.serialized_size(),
                Self::SaverEncryptionKey(s) => 9u8.serialized_size() + s.serialized_size(),
                Self::SaverProvingKey(s) => 10u8.serialized_size() + s.serialized_size(),
                Self::SaverVerifyingKey(s) => 11u8.serialized_size() + s.serialized_size(),
                Self::LegoSnarkProvingKey(s) => 12u8.serialized_size() + s.serialized_size(),
                Self::LegoSnarkVerifyingKey(s) => 13u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::BBSPlusSignatureParams(s) => {
                    CanonicalSerialize::serialize_uncompressed(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::BBSPlusPublicKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::VbAccumulatorParams(s) => {
                    CanonicalSerialize::serialize_uncompressed(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::VbAccumulatorPublicKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::VbAccumulatorMemProvingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::PedersenCommitmentKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::SaverEncryptionGens(s) => {
                    CanonicalSerialize::serialize_uncompressed(&7u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::SaverCommitmentGens(s) => {
                    CanonicalSerialize::serialize_uncompressed(&8u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::SaverEncryptionKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&9u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::SaverProvingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&10u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::SaverVerifyingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&11u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::LegoSnarkProvingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&12u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
                Self::LegoSnarkVerifyingKey(s) => {
                    CanonicalSerialize::serialize_uncompressed(&13u8, &mut writer)?;
                    CanonicalSerialize::serialize_uncompressed(s, &mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::BBSPlusSignatureParams(s) => {
                    CanonicalSerialize::serialize_unchecked(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::BBSPlusPublicKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::VbAccumulatorParams(s) => {
                    CanonicalSerialize::serialize_unchecked(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::VbAccumulatorPublicKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::VbAccumulatorMemProvingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::PedersenCommitmentKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::SaverEncryptionGens(s) => {
                    CanonicalSerialize::serialize_unchecked(&7u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::SaverCommitmentGens(s) => {
                    CanonicalSerialize::serialize_unchecked(&8u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::SaverEncryptionKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&9u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::SaverProvingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&10u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::SaverVerifyingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&11u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::LegoSnarkProvingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&12u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
                Self::LegoSnarkVerifyingKey(s) => {
                    CanonicalSerialize::serialize_unchecked(&13u8, &mut writer)?;
                    CanonicalSerialize::serialize_unchecked(s, &mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::BBSPlusSignatureParams(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
                Self::BBSPlusPublicKey(s) => 1u8.uncompressed_size() + s.uncompressed_size(),
                Self::VbAccumulatorParams(s) => 2u8.uncompressed_size() + s.uncompressed_size(),
                Self::VbAccumulatorPublicKey(s) => 3u8.uncompressed_size() + s.uncompressed_size(),
                Self::VbAccumulatorMemProvingKey(s) => {
                    4u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    5u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::PedersenCommitmentKey(s) => 6u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverEncryptionGens(s) => 7u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverCommitmentGens(s) => 8u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverEncryptionKey(s) => 9u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverProvingKey(s) => 10u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverVerifyingKey(s) => 11u8.uncompressed_size() + s.uncompressed_size(),
                Self::LegoSnarkProvingKey(s) => 12u8.uncompressed_size() + s.uncompressed_size(),
                Self::LegoSnarkVerifyingKey(s) => 13u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for SetupParams<E, G> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::BBSPlusSignatureParams(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                1u8 => Ok(Self::BBSPlusPublicKey(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                2u8 => Ok(Self::VbAccumulatorParams(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::VbAccumulatorPublicKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                4u8 => Ok(Self::VbAccumulatorMemProvingKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                5u8 => Ok(Self::VbAccumulatorNonMemProvingKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                6u8 => Ok(Self::PedersenCommitmentKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                7u8 => Ok(Self::SaverEncryptionGens(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                8u8 => Ok(Self::SaverCommitmentGens(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                9u8 => Ok(Self::SaverEncryptionKey(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                10u8 => Ok(Self::SaverProvingKey(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                11u8 => Ok(Self::SaverVerifyingKey(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                12u8 => Ok(Self::LegoSnarkProvingKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                13u8 => Ok(Self::LegoSnarkVerifyingKey(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::BBSPlusSignatureParams(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::BBSPlusPublicKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::VbAccumulatorParams(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::VbAccumulatorPublicKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                4u8 => Ok(Self::VbAccumulatorMemProvingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                5u8 => Ok(Self::VbAccumulatorNonMemProvingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                6u8 => Ok(Self::PedersenCommitmentKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                7u8 => Ok(Self::SaverEncryptionGens(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                8u8 => Ok(Self::SaverCommitmentGens(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                9u8 => Ok(Self::SaverEncryptionKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                10u8 => Ok(Self::SaverProvingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                11u8 => Ok(Self::SaverVerifyingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                12u8 => Ok(Self::LegoSnarkProvingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                13u8 => Ok(Self::LegoSnarkVerifyingKey(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::BBSPlusSignatureParams(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::BBSPlusPublicKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::VbAccumulatorParams(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::VbAccumulatorPublicKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                4u8 => Ok(Self::VbAccumulatorMemProvingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                5u8 => Ok(Self::VbAccumulatorNonMemProvingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                6u8 => Ok(Self::PedersenCommitmentKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                7u8 => Ok(Self::SaverEncryptionGens(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                8u8 => Ok(Self::SaverCommitmentGens(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                9u8 => Ok(Self::SaverEncryptionKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                10u8 => Ok(Self::SaverProvingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                11u8 => Ok(Self::SaverVerifyingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                12u8 => Ok(Self::LegoSnarkProvingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                13u8 => Ok(Self::LegoSnarkVerifyingKey(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
