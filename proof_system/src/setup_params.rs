//! Represents (public) setup parameters of different protocols. Setup parameters (enum variants here) can
//! be either directly passed to the `Statement` or can be wrapped in this enum `SetupParams` and then a reference
//! to this enum is passed to the `Statement`. This enum is helpful when the same setup parameter needs to
//! be passed to several `Statement`s as it avoids the need of having several copies of the setup param. This
//! becomes more important when interacting with the WASM bindings of this crate as the overhead of repeated
//! serialization and de-serialization can be avoided.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::vec::Vec;
use bbs_plus::prelude::{
    PublicKeyG2 as BBSPublicKeyG2, SignatureParams23G1 as BBSSignatureParams23G1,
    SignatureParamsG1 as BBSSignatureParamsG1,
};
use legogroth16::{
    circom::R1CS,
    data_structures::{ProvingKey as LegoSnarkProvingKey, VerifyingKey as LegoSnarkVerifyingKey},
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
    PSSignatureParams(coconut_crypto::setup::SignatureParams<E>),
    PSSignaturePublicKey(coconut_crypto::setup::PublicKey<E>),
    BBSSignatureParams23(BBSSignatureParams23G1<E>),
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
                BBSSignatureParams23
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
                BBSSignatureParams23
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

mod serialization {
    use super::*;
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
    };
    use ark_std::io::{Read, Write};

    impl<E: Pairing, G: AffineRepr> Valid for SetupParams<E, G> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalSerialize for SetupParams<E, G> {
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

    impl<E: Pairing, G: AffineRepr> CanonicalDeserialize for SetupParams<E, G> {
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
