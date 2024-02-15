use crate::{
    error::ProofSystemError, setup_params::SetupParams, statement::Statement,
    sub_protocols::validate_bounds,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use bulletproofs_plus_plus::setup::SetupParams as BppSetupParams;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Proving knowledge of message that satisfies given bounds, i.e. `min <= message < max` using Bulletproofs++.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckBpp<G: AffineRepr> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub params: Option<BppSetupParams<G>>,
    pub params_ref: Option<usize>,
}

impl<G: AffineRepr> BoundCheckBpp<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        min: u64,
        max: u64,
        params: BppSetupParams<G>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckBpp(Self {
            min,
            max,
            params: Some(params),
            params_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref<E: Pairing<G1Affine = G>>(
        min: u64,
        max: u64,
        params_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::BoundCheckBpp(Self {
            min,
            max,
            params: None,
            params_ref: Some(params_ref),
        }))
    }

    pub fn get_setup_params<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a BppSetupParams<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            BppSetupParams,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }
}
