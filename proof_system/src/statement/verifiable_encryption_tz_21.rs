use crate::{
    error::ProofSystemError,
    prelude::{SetupParams, Statement},
    setup_params::ElgamalEncryptionParams,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct VerifiableEncryptionTZ21<G: AffineRepr> {
    pub enc_params: Option<ElgamalEncryptionParams<G>>,
    pub enc_params_ref: Option<usize>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<Vec<ArkObjectBytes>>"))]
    pub comm_key: Option<Vec<G>>,
    pub comm_key_ref: Option<usize>,
}

impl<G: AffineRepr> VerifiableEncryptionTZ21<G> {
    /// Get statement for DKGitH protocol
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        enc_params: ElgamalEncryptionParams<G>,
        comm_key: Vec<G>,
    ) -> Statement<E> {
        Statement::VeTZ21(Self {
            enc_params: Some(enc_params),
            comm_key: Some(comm_key),
            enc_params_ref: None,
            comm_key_ref: None,
        })
    }

    /// Get statement for Robust DKGitH protocol
    pub fn new_statement_from_params_for_robust<E: Pairing<G1Affine = G>>(
        enc_params: ElgamalEncryptionParams<G>,
        comm_key: Vec<G>,
    ) -> Statement<E> {
        Statement::VeTZ21Robust(Self {
            enc_params: Some(enc_params),
            comm_key: Some(comm_key),
            enc_params_ref: None,
            comm_key_ref: None,
        })
    }

    /// Get statement for DKGitH protocol
    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        enc_params: usize,
        comm_key: usize,
    ) -> Statement<E> {
        Statement::VeTZ21(Self {
            enc_params: None,
            comm_key: None,
            enc_params_ref: Some(enc_params),
            comm_key_ref: Some(comm_key),
        })
    }

    /// Get statement for Robust DKGitH protocol
    pub fn new_statement_from_params_ref_for_robust<E: Pairing<G1Affine = G>>(
        enc_params: usize,
        comm_key: usize,
    ) -> Statement<E> {
        Statement::VeTZ21Robust(Self {
            enc_params: None,
            comm_key: None,
            enc_params_ref: Some(enc_params),
            comm_key_ref: Some(comm_key),
        })
    }

    pub fn get_comm_key<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a Vec<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.comm_key,
            self.comm_key_ref,
            PedersenCommitmentKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_enc_params<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a ElgamalEncryptionParams<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.enc_params,
            self.enc_params_ref,
            ElgamalEncryption,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }
}
