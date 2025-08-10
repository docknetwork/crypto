use crate::prelude::{ProofSystemError, SetupParams, Statement};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use kvac::bbdt_2016::setup::{MACParams, SecretKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, Same};

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKOfMAC<G: ark_ec::AffineRepr> {
    /// Messages being revealed.
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<Same, ArkObjectBytes>"))]
    pub revealed_messages: BTreeMap<usize, G::ScalarField>,
    pub mac_params: Option<MACParams<G>>,
    pub mac_params_ref: Option<usize>,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKOfMACFullVerifier<G: ark_ec::AffineRepr> {
    /// Messages being revealed.
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<Same, ArkObjectBytes>"))]
    pub revealed_messages: BTreeMap<usize, G::ScalarField>,
    pub mac_params: Option<MACParams<G>>,
    pub mac_params_ref: Option<usize>,
    pub secret_key: SecretKey<G::ScalarField>,
}

impl<G: ark_ec::AffineRepr> PoKOfMAC<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        params: MACParams<G>,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBBDT16MAC(Self {
            revealed_messages,
            mac_params: Some(params),
            mac_params_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        params_ref: usize,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBBDT16MAC(Self {
            revealed_messages,
            mac_params: None,
            mac_params_ref: Some(params_ref),
        })
    }

    pub fn get_params<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MACParams<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.mac_params,
            self.mac_params_ref,
            BBDT16MACParams,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }
}

impl<G: ark_ec::AffineRepr> PoKOfMACFullVerifier<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        secret_key: SecretKey<G::ScalarField>,
        params: MACParams<G>,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBBDT16MACFullVerifier(Self {
            revealed_messages,
            mac_params: Some(params),
            mac_params_ref: None,
            secret_key,
        })
    }

    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        secret_key: SecretKey<G::ScalarField>,
        params_ref: usize,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBBDT16MACFullVerifier(Self {
            revealed_messages,
            mac_params: None,
            mac_params_ref: Some(params_ref),
            secret_key,
        })
    }

    pub fn get_params<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MACParams<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.mac_params,
            self.mac_params_ref,
            BBDT16MACParams,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }
}
