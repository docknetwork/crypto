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
use crate::statement::Statement;
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
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParamsG1<E>>,
    /// If the statement was created by passing the public key params directly, then it will not be None
    pub public_key: Option<PublicKeyG2<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
    /// If the statement was created by passing the index of public key in `SetupParams`, then it will not be None
    pub public_key_ref: Option<usize>,
}

impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    /// Create a statement by passing the signature parameters and public key directly.
    pub fn new_statement_from_params<G: AffineCurve>(
        signature_params: SignatureParamsG1<E>,
        public_key: PublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E, G> {
        Statement::PoKBBSSignatureG1(Self {
            revealed_messages,
            signature_params: Some(signature_params),
            public_key: Some(public_key),
            signature_params_ref: None,
            public_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of signature parameters and public key in `SetupParams`.
    pub fn new_statement_from_params_ref<G: AffineCurve>(
        signature_params_ref: usize,
        public_key_ref: usize,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E, G> {
        Statement::PoKBBSSignatureG1(Self {
            revealed_messages,
            signature_params: None,
            public_key: None,
            signature_params_ref: Some(signature_params_ref),
            public_key_ref: Some(public_key_ref),
        })
    }

    /// Get signature params for the statement index `s_idx` either from `self` or from given `setup_params`.
    pub fn get_sig_params<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a SignatureParamsG1<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.signature_params,
            self.signature_params_ref,
            BBSPlusSignatureParams,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }

    /// Get public key for the statement index `s_idx` either from `self` or from given `setup_params`.
    pub fn get_public_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKeyG2<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.public_key,
            self.public_key_ref,
            BBSPlusPublicKey,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }
}
