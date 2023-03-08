//! Represents (public) setup parameters of different protocols. Setup parameters (enum variants here) can
//! be either directly passed to the `Statement` or can be wrapped in this enum `SetupParams` and then a reference
//! to this enum is passed to the `Statement`. This enum is helpful when the same setup parameter needs to
//! be passed to several `Statement`s as it avoids the need of having several copies of the setup param. This
//! becomes more important when interacting with the WASM bindings of this crate as the overhead of repeated
//! serialization and de-serialization can be avoided.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::vec::Vec;
use bbs_plus::prelude::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};
use legogroth16::circom::R1CS;
use legogroth16::data_structures::{
    ProvingKey as LegoSnarkProvingKey, VerifyingKey as LegoSnarkVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey as SaverSnarkProvingKey,
    VerifyingKey as SaverSnarkVerifyingKey,
};
use vb_accumulator::prelude::{
    MembershipProvingKey, NonMembershipProvingKey, PublicKey as AccumPublicKey,
    SetupParams as AccumParams,
};

use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Holds (public) setup parameters of different protocols.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum SetupParams<E: Pairing, G: AffineRepr> {
    BBSPlusSignatureParams(BBSSignatureParamsG1<E>),
    BBSPlusPublicKey(BBSPublicKeyG2<E>),
    VbAccumulatorParams(AccumParams<E>),
    VbAccumulatorPublicKey(AccumPublicKey<E>),
    VbAccumulatorMemProvingKey(MembershipProvingKey<E::G1Affine>),
    VbAccumulatorNonMemProvingKey(NonMembershipProvingKey<E::G1Affine>),
    PedersenCommitmentKey(#[serde_as(as = "Vec<ArkObjectBytes>")] Vec<G>),
    SaverEncryptionGens(EncryptionGens<E>),
    SaverCommitmentGens(ChunkedCommitmentGens<E::G1Affine>),
    SaverEncryptionKey(EncryptionKey<E>),
    SaverProvingKey(SaverSnarkProvingKey<E>),
    SaverVerifyingKey(#[serde_as(as = "ArkObjectBytes")] SaverSnarkVerifyingKey<E>),
    LegoSnarkProvingKey(#[serde_as(as = "ArkObjectBytes")] LegoSnarkProvingKey<E>),
    LegoSnarkVerifyingKey(#[serde_as(as = "ArkObjectBytes")] LegoSnarkVerifyingKey<E>),
    R1CS(#[serde_as(as = "ArkObjectBytes")] R1CS<E>),
    Bytes(Vec<u8>),
    FieldElemVec(#[serde_as(as = "Vec<ArkObjectBytes>")] Vec<E::ScalarField>),
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
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
    };
    use ark_std::io::{Read, Write};

    impl<E: Pairing, G: AffineRepr> Valid for SetupParams<E, G> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::BBSPlusSignatureParams(s) => s.check(),
                Self::BBSPlusPublicKey(s) => s.check(),
                Self::VbAccumulatorParams(s) => s.check(),
                Self::VbAccumulatorPublicKey(s) => s.check(),
                Self::VbAccumulatorMemProvingKey(s) => s.check(),
                Self::VbAccumulatorNonMemProvingKey(s) => s.check(),
                Self::PedersenCommitmentKey(s) => s.check(),
                Self::SaverEncryptionGens(s) => s.check(),
                Self::SaverCommitmentGens(s) => s.check(),
                Self::SaverEncryptionKey(s) => s.check(),
                Self::SaverProvingKey(s) => s.check(),
                Self::SaverVerifyingKey(s) => s.check(),
                Self::LegoSnarkProvingKey(s) => s.check(),
                Self::LegoSnarkVerifyingKey(s) => s.check(),
                Self::R1CS(s) => s.check(),
                Self::Bytes(s) => s.check(),
                Self::FieldElemVec(s) => s.check(),
            }
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalSerialize for SetupParams<E, G> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::BBSPlusSignatureParams(s) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::BBSPlusPublicKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::VbAccumulatorParams(s) => {
                    CanonicalSerialize::serialize_with_mode(&2u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::VbAccumulatorPublicKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&3u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::VbAccumulatorMemProvingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&4u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&5u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::PedersenCommitmentKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&6u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverEncryptionGens(s) => {
                    CanonicalSerialize::serialize_with_mode(&7u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverCommitmentGens(s) => {
                    CanonicalSerialize::serialize_with_mode(&8u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverEncryptionKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&9u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverProvingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&10u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverVerifyingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&11u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::LegoSnarkProvingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&12u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::LegoSnarkVerifyingKey(s) => {
                    CanonicalSerialize::serialize_with_mode(&13u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::R1CS(s) => {
                    CanonicalSerialize::serialize_with_mode(&14u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::Bytes(s) => {
                    CanonicalSerialize::serialize_with_mode(&15u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::FieldElemVec(s) => {
                    CanonicalSerialize::serialize_with_mode(&16u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::BBSPlusSignatureParams(s) => {
                    0u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::BBSPlusPublicKey(s) => {
                    1u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::VbAccumulatorParams(s) => {
                    2u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::VbAccumulatorPublicKey(s) => {
                    3u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::VbAccumulatorMemProvingKey(s) => {
                    4u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::VbAccumulatorNonMemProvingKey(s) => {
                    5u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::PedersenCommitmentKey(s) => {
                    6u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverEncryptionGens(s) => {
                    7u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverCommitmentGens(s) => {
                    8u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverEncryptionKey(s) => {
                    9u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverProvingKey(s) => {
                    10u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverVerifyingKey(s) => {
                    11u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::LegoSnarkProvingKey(s) => {
                    12u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::LegoSnarkVerifyingKey(s) => {
                    13u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::R1CS(s) => 14u8.serialized_size(compress) + s.serialized_size(compress),
                Self::Bytes(s) => 15u8.serialized_size(compress) + s.serialized_size(compress),
                Self::FieldElemVec(s) => {
                    16u8.serialized_size(compress) + s.serialized_size(compress)
                }
            }
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalDeserialize for SetupParams<E, G> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::BBSPlusSignatureParams(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                1u8 => Ok(Self::BBSPlusPublicKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                2u8 => Ok(Self::VbAccumulatorParams(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                3u8 => Ok(Self::VbAccumulatorPublicKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                4u8 => Ok(Self::VbAccumulatorMemProvingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                5u8 => Ok(Self::VbAccumulatorNonMemProvingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                6u8 => Ok(Self::PedersenCommitmentKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                7u8 => Ok(Self::SaverEncryptionGens(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                8u8 => Ok(Self::SaverCommitmentGens(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                9u8 => Ok(Self::SaverEncryptionKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                10u8 => Ok(Self::SaverProvingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                11u8 => Ok(Self::SaverVerifyingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                12u8 => Ok(Self::LegoSnarkProvingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                13u8 => Ok(Self::LegoSnarkVerifyingKey(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                14u8 => Ok(Self::R1CS(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                15u8 => Ok(Self::Bytes(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                16u8 => Ok(Self::FieldElemVec(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
