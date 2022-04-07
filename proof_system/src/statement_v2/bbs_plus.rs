use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    io::{Read, Write},
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

use crate::error::ProofSystemError;
use crate::setup_params::SetupParams;
use crate::statement_v2::StatementV2;
use bbs_plus::prelude::{PublicKeyG2, SignatureParamsG1};
use dock_crypto_utils::serde_utils::*;

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, FieldBytes>")]
    pub revealed_messages: BTreeMap<usize, E::Fr>,
    pub signature_params: Option<SignatureParamsG1<E>>,
    pub public_key: Option<PublicKeyG2<E>>,
    pub signature_params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
}

impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_statement_from_params<G: AffineCurve>(
        signature_params: SignatureParamsG1<E>,
        public_key: PublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> StatementV2<E, G> {
        StatementV2::PoKBBSSignatureG1(Self {
            revealed_messages,
            signature_params: Some(signature_params),
            public_key: Some(public_key),
            signature_params_ref: None,
            public_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<G: AffineCurve>(
        signature_params_ref: usize,
        public_key_ref: usize,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> StatementV2<E, G> {
        StatementV2::PoKBBSSignatureG1(Self {
            revealed_messages,
            signature_params: None,
            public_key: None,
            signature_params_ref: Some(signature_params_ref),
            public_key_ref: Some(public_key_ref),
        })
    }

    pub fn get_sig_params<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a SignatureParamsG1<E>, ProofSystemError> {
        if let Some(sp) = &self.signature_params {
            return Ok(sp);
        }
        if let Some(idx) = self.signature_params_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::BBSPlusSignatureParams(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleBBSPlusSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_public_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKeyG2<E>, ProofSystemError> {
        if let Some(pk) = &self.public_key {
            return Ok(pk);
        }
        if let Some(idx) = self.public_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::BBSPlusPublicKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleBBSPlusSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}
