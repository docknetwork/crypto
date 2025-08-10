use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, Same};

use crate::{
    error::ProofSystemError, impl_bbs_prover_statement, impl_bbs_verifier_statement,
    setup_params::SetupParams, statement::Statement,
};
use bbs_plus::prelude::{PublicKeyG2, SignatureParams23G1};
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::*;

/// Public values like setup params and revealed messages for proving knowledge of BBS signature.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKBBSSignature23G1Prover<E: Pairing> {
    /// Messages being revealed.
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<Same, ArkObjectBytes>"))]
    pub revealed_messages: BTreeMap<usize, E::ScalarField>,
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParams23G1<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
}

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS signature.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKBBSSignature23G1Verifier<E: Pairing> {
    /// Messages being revealed.
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<Same, ArkObjectBytes>"))]
    pub revealed_messages: BTreeMap<usize, E::ScalarField>,
    /// If the statement was created by passing the signature params directly, then it will not be None
    pub signature_params: Option<SignatureParams23G1<E>>,
    /// If the statement was created by passing the public key params directly, then it will not be None
    pub public_key: Option<PublicKeyG2<E>>,
    /// If the statement was created by passing the index of signature params in `SetupParams`, then it will not be None
    pub signature_params_ref: Option<usize>,
    /// If the statement was created by passing the index of public key in `SetupParams`, then it will not be None
    pub public_key_ref: Option<usize>,
}

impl<E: Pairing> PoKBBSSignature23G1Prover<E> {
    impl_bbs_prover_statement!(
        SignatureParams23G1,
        PoKBBSSignature23G1Prover,
        BBSSignatureParams23
    );
}

impl<E: Pairing> PoKBBSSignature23G1Verifier<E> {
    impl_bbs_verifier_statement!(
        SignatureParams23G1,
        PoKBBSSignature23G1Verifier,
        BBSSignatureParams23
    );
}
