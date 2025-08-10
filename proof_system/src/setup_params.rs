//! Represents (public) setup parameters of different protocols. Setup parameters (enum variants here) can
//! be either directly passed to the `Statement` or can be wrapped in this enum `SetupParams` and then a reference
//! to this enum is passed to the `Statement`. This enum is helpful when the same setup parameter needs to
//! be passed to several `Statement`s as it avoids the need of having several copies of the setup param. This
//! becomes more important when interacting with the WASM bindings of this crate as the overhead of repeated
//! serialization and de-serialization can be avoided.

use crate::{
    prelude::bound_check_smc::SmcParamsAndCommitmentKey,
    statement::bound_check_smc_with_kv::{
        SmcParamsKVAndCommitmentKey, SmcParamsKVAndCommitmentKeyAndSecretKey,
    },
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use bbs_plus::prelude::{
    PublicKeyG2 as BBSPublicKeyG2, SignatureParams23G1 as BBSSignatureParams23G1,
    SignatureParamsG1 as BBSSignatureParamsG1,
};
use bulletproofs_plus_plus::setup::SetupParams as BppSetupParams;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use kvac::bbdt_2016::setup::MACParams;
use legogroth16::{
    circom::R1CS,
    data_structures::{ProvingKey as LegoSnarkProvingKey, VerifyingKey as LegoSnarkVerifyingKey},
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey as SaverSnarkProvingKey,
    VerifyingKey as SaverSnarkVerifyingKey,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use short_group_sig::common::ProvingKey;
use vb_accumulator::{
    kb_positive_accumulator::setup::{PublicKey as KBAccumPublicKey, SetupParams as KBAccumParams},
    prelude::{
        MembershipProvingKey, NonMembershipProvingKey, PublicKey as AccumPublicKey,
        SetupParams as AccumParams,
    },
};

/// Holds (public) setup parameters of different protocols.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub enum SetupParams<E: Pairing> {
    BBSPlusSignatureParams(BBSSignatureParamsG1<E>),
    BBSPlusPublicKey(BBSPublicKeyG2<E>),
    VbAccumulatorParams(AccumParams<E>),
    VbAccumulatorPublicKey(AccumPublicKey<E>),
    VbAccumulatorMemProvingKey(MembershipProvingKey<E::G1Affine>),
    VbAccumulatorNonMemProvingKey(NonMembershipProvingKey<E::G1Affine>),
    PedersenCommitmentKey(
        #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] Vec<E::G1Affine>,
    ),
    SaverEncryptionGens(EncryptionGens<E>),
    SaverCommitmentGens(ChunkedCommitmentGens<E::G1Affine>),
    SaverEncryptionKey(EncryptionKey<E>),
    SaverProvingKey(SaverSnarkProvingKey<E>),
    SaverVerifyingKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] SaverSnarkVerifyingKey<E>,
    ),
    LegoSnarkProvingKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] LegoSnarkProvingKey<E>,
    ),
    LegoSnarkVerifyingKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] LegoSnarkVerifyingKey<E>,
    ),
    R1CS(#[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] R1CS<E>),
    Bytes(Vec<u8>),
    FieldElemVec(
        #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] Vec<E::ScalarField>,
    ),
    PSSignatureParams(coconut_crypto::setup::SignatureParams<E>),
    PSSignaturePublicKey(coconut_crypto::setup::PublicKey<E>),
    BBSSignatureParams23(BBSSignatureParams23G1<E>),
    BppSetupParams(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] BppSetupParams<E::G1Affine>,
    ),
    SmcParamsAndCommKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
        SmcParamsAndCommitmentKey<E>,
    ),
    SmcParamsAndCommKeyAndSk(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
        SmcParamsKVAndCommitmentKeyAndSecretKey<E::G1Affine>,
    ),
    CommitmentKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
        PedersenCommitmentKey<E::G1Affine>,
    ),
    BBSigProvingKey(ProvingKey<E::G1Affine>),
    KBPositiveAccumulatorParams(KBAccumParams<E>),
    KBPositiveAccumulatorPublicKey(KBAccumPublicKey<E>),
    BBDT16MACParams(MACParams<E::G1Affine>),
    PedersenCommitmentKeyG2(
        #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] Vec<E::G2Affine>,
    ),
    CommitmentKeyG2(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
        PedersenCommitmentKey<E::G2Affine>,
    ),
    SmcParamsKVAndCommKey(
        #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
        SmcParamsKVAndCommitmentKey<E::G1Affine>,
    ),
    ElgamalEncryption(ElgamalEncryptionParams<E::G1Affine>),
}

macro_rules! delegate {
    ($([$idx: ident])?$self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                BBSPlusSignatureParams,
                BBSPlusPublicKey,
                VbAccumulatorParams,
                VbAccumulatorPublicKey,
                VbAccumulatorMemProvingKey,
                VbAccumulatorNonMemProvingKey,
                PedersenCommitmentKey,
                SaverEncryptionGens,
                SaverCommitmentGens,
                SaverEncryptionKey,
                SaverProvingKey,
                SaverVerifyingKey,
                LegoSnarkProvingKey,
                LegoSnarkVerifyingKey,
                R1CS,
                Bytes,
                FieldElemVec,
                PSSignatureParams,
                PSSignaturePublicKey,
                BBSSignatureParams23,
                BppSetupParams,
                SmcParamsAndCommKey,
                SmcParamsAndCommKeyAndSk,
                CommitmentKey,
                BBSigProvingKey,
                KBPositiveAccumulatorParams,
                KBPositiveAccumulatorPublicKey,
                BBDT16MACParams,
                PedersenCommitmentKeyG2,
                CommitmentKeyG2,
                SmcParamsKVAndCommKey,
                ElgamalEncryption
            : $($tt)+
        }
    }};
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                BBSPlusSignatureParams,
                BBSPlusPublicKey,
                VbAccumulatorParams,
                VbAccumulatorPublicKey,
                VbAccumulatorMemProvingKey,
                VbAccumulatorNonMemProvingKey,
                PedersenCommitmentKey,
                SaverEncryptionGens,
                SaverCommitmentGens,
                SaverEncryptionKey,
                SaverProvingKey,
                SaverVerifyingKey,
                LegoSnarkProvingKey,
                LegoSnarkVerifyingKey,
                R1CS,
                Bytes,
                FieldElemVec,
                PSSignatureParams,
                PSSignaturePublicKey,
                BBSSignatureParams23,
                BppSetupParams,
                SmcParamsAndCommKey,
                SmcParamsAndCommKeyAndSk,
                CommitmentKey,
                BBSigProvingKey,
                KBPositiveAccumulatorParams,
                KBPositiveAccumulatorPublicKey,
                BBDT16MACParams,
                PedersenCommitmentKeyG2,
                CommitmentKeyG2,
                SmcParamsKVAndCommKey,
                ElgamalEncryption
            : $($tt)+
        }

        $err
    }};
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

/// Elgamal encryption parameters generated by the decryptor
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalEncryptionParams<G: AffineRepr> {
    /// Generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub public_key: G,
}

mod serialization {
    use super::*;
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
    };
    use ark_std::io::{Read, Write};

    impl<E: Pairing> Valid for SetupParams<E> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing> CanonicalSerialize for SetupParams<E> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            delegate!([index]self with variant as statement {
                CanonicalSerialize::serialize_with_mode(&index, &mut writer, compress)?;
                CanonicalSerialize::serialize_with_mode(statement, &mut writer, compress)
            })
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            delegate!([index]self with variant as statement {
                index.serialized_size(compress) + CanonicalSerialize::serialized_size(statement, compress)
            })
        }
    }

    impl<E: Pairing> CanonicalDeserialize for SetupParams<E> {
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
