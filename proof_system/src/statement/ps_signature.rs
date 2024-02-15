use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
use coconut_crypto::{proof::*, setup::*};
use dock_crypto_utils::serde_utils::ArkObjectBytes;

/// Public values like setup params, public key and revealed messages for proving knowledge of PS signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKPSSignatureStatement<E: Pairing> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub revealed_messages: BTreeMap<usize, E::ScalarField>,
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParams<E>>,
    /// If the statement was created by passing the public key params directly, then it will not be None
    pub public_key: Option<PublicKey<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
    /// If the statement was created by passing the index of public key in `SetupParams`, then it will not be None
    pub public_key_ref: Option<usize>,
}

impl<E: Pairing> PoKPSSignatureStatement<E> {
    /// Create a statement by passing the signature parameters and public key directly.
    pub fn new_statement_from_params(
        signature_params: SignatureParams<E>,
        public_key: PublicKey<E>,
        revealed_messages: BTreeMap<usize, E::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKPSSignature(Self {
            revealed_messages,
            signature_params: Some(signature_params),
            public_key: Some(public_key),
            signature_params_ref: None,
            public_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of signature parameters and public key in `SetupParams`.
    pub fn new_statement_from_params_ref(
        signature_params_ref: usize,
        public_key_ref: usize,
        revealed_messages: BTreeMap<usize, E::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKPSSignature(Self {
            revealed_messages,
            signature_params: None,
            public_key: None,
            signature_params_ref: Some(signature_params_ref),
            public_key_ref: Some(public_key_ref),
        })
    }

    /// Get signature params for the statement index `s_idx` either from `self` or from given `setup_params`.
    pub fn get_params<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SignatureParams<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.signature_params,
            self.signature_params_ref,
            PSSignatureParams,
            IncompatiblePSSetupParamAtIndex,
            st_idx
        )
    }

    /// Get public key for the statement index `s_idx` either from `self` or from given `setup_params`.
    pub fn get_public_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a PublicKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.public_key,
            self.public_key_ref,
            PSSignaturePublicKey,
            IncompatiblePSSetupParamAtIndex,
            st_idx
        )
    }
}
