use crate::{error::ProofSystemError, prelude::Statement, setup_params::SetupParams};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec::Vec};
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use kvac::bddt_2016::setup::{MACParams, SecretKey};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKOfMAC<G: AffineRepr> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub revealed_messages: BTreeMap<usize, G::ScalarField>,
    pub mac_params: Option<MACParams<G>>,
    pub mac_params_ref: Option<usize>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKOfMACFullVerifier<G: AffineRepr> {
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub revealed_messages: BTreeMap<usize, G::ScalarField>,
    pub mac_params: Option<MACParams<G>>,
    pub mac_params_ref: Option<usize>,
    pub secret_key: SecretKey<G::ScalarField>,
}

impl<G: AffineRepr> PoKOfMAC<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        params: MACParams<G>,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBDDT16MAC(Self {
            revealed_messages,
            mac_params: Some(params),
            mac_params_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        params_ref: usize,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBDDT16MAC(Self {
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
            BDDT16MACParams,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }
}

impl<G: AffineRepr> PoKOfMACFullVerifier<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        secret_key: SecretKey<G::ScalarField>,
        params: MACParams<G>,
        revealed_messages: BTreeMap<usize, G::ScalarField>,
    ) -> Statement<E> {
        Statement::PoKBDDT16MACFullVerifier(Self {
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
        Statement::PoKBDDT16MACFullVerifier(Self {
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
            BDDT16MACParams,
            IncompatibleBBSPlusSetupParamAtIndex,
            st_idx
        )
    }
}
