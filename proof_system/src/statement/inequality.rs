use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::{commitment::PedersenCommitmentKey, serde_utils::*};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PublicInequality<G: AffineRepr> {
    /// The public value with which the inequalty is being proven
    #[serde_as(as = "ArkObjectBytes")]
    pub inequal_to: G::ScalarField,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub comm_key: Option<PedersenCommitmentKey<G>>,
    pub comm_key_ref: Option<usize>,
}

impl<G: AffineRepr> PublicInequality<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        inequal_to: G::ScalarField,
        comm_key: PedersenCommitmentKey<G>,
    ) -> Statement<E> {
        Statement::PublicInequality(Self {
            inequal_to,
            comm_key: Some(comm_key),
            comm_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        inequal_to: G::ScalarField,
        comm_key_ref: usize,
    ) -> Statement<E> {
        Statement::PublicInequality(Self {
            inequal_to,
            comm_key: None,
            comm_key_ref: Some(comm_key_ref),
        })
    }

    pub fn get_comm_key<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a PedersenCommitmentKey<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.comm_key,
            self.comm_key_ref,
            CommitmentKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }
}
