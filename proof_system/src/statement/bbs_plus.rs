use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
use bbs_plus::prelude::{PublicKeyG2, SignatureParamsG1};
use dock_crypto_utils::serde_utils::*;

/// Public values like setup params and revealed messages for proving knowledge of BBS+ signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1Prover<E: Pairing> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub revealed_messages: BTreeMap<usize, E::ScalarField>,
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParamsG1<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
}

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1Verifier<E: Pairing> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub revealed_messages: BTreeMap<usize, E::ScalarField>,
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParamsG1<E>>,
    /// If the statement was created by passing the public key params directly, then it will not be None
    pub public_key: Option<PublicKeyG2<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
    /// If the statement was created by passing the index of public key in `SetupParams`, then it will not be None
    pub public_key_ref: Option<usize>,
}

#[macro_export]
macro_rules! impl_bbs_prover_statement {
    ($params: ident, $stmt: ident, $setup_param_name: ident) => {
        /// Create a statement by passing the signature parameters directly.
        pub fn new_statement_from_params(
            signature_params: $params<E>,
            revealed_messages: BTreeMap<usize, E::ScalarField>,
        ) -> Statement<E> {
            Statement::$stmt(Self {
                revealed_messages,
                signature_params: Some(signature_params),
                signature_params_ref: None,
            })
        }

        /// Create a statement by passing the index of signature parameters in `SetupParams`.
        pub fn new_statement_from_params_ref(
            signature_params_ref: usize,
            revealed_messages: BTreeMap<usize, E::ScalarField>,
        ) -> Statement<E> {
            Statement::$stmt(Self {
                revealed_messages,
                signature_params: None,
                signature_params_ref: Some(signature_params_ref),
            })
        }

        /// Get signature params for the statement index `s_idx` either from `self` or from given `setup_params`.
        pub fn get_params<'a>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
            st_idx: usize,
        ) -> Result<&'a $params<E>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.signature_params,
                self.signature_params_ref,
                $setup_param_name,
                IncompatibleBBSPlusSetupParamAtIndex,
                st_idx
            )
        }
    };
}

#[macro_export]
macro_rules! impl_bbs_verifier_statement {
    ($params: ident, $stmt: ident, $setup_param_name: ident) => {
        /// Create a statement by passing the signature parameters and public key directly.
        pub fn new_statement_from_params(
            signature_params: $params<E>,
            public_key: PublicKeyG2<E>,
            revealed_messages: BTreeMap<usize, E::ScalarField>,
        ) -> Statement<E> {
            Statement::$stmt(Self {
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
            Statement::$stmt(Self {
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
        ) -> Result<&'a $params<E>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.signature_params,
                self.signature_params_ref,
                $setup_param_name,
                IncompatibleBBSPlusSetupParamAtIndex,
                st_idx
            )
        }

        /// Get public key for the statement index `s_idx` either from `self` or from given `setup_params`.
        pub fn get_public_key<'a>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
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
    };
}

impl<E: Pairing> PoKBBSSignatureG1Prover<E> {
    impl_bbs_prover_statement!(
        SignatureParamsG1,
        PoKBBSSignatureG1Prover,
        BBSPlusSignatureParams
    );
}

impl<E: Pairing> PoKBBSSignatureG1Verifier<E> {
    impl_bbs_verifier_statement!(
        SignatureParamsG1,
        PoKBBSSignatureG1Verifier,
        BBSPlusSignatureParams
    );
}
