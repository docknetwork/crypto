use crate::{
    error::ProofSystemError, setup_params::SetupParams, statement::Statement,
    sub_protocols::validate_bounds,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use bulletproofs_plus_plus::setup::SetupParams as BppSetupParams;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::discrete_log::PokDiscreteLog;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;

/// Proving knowledge of message that satisfies given bounds, i.e. `min <= message < max` using Bulletproofs++.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct BoundCheckBpp<G: AffineRepr> {
    pub min: u64,
    pub max: u64,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<ArkObjectBytes>"))]
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

/// Public values for proving knowledge of bound check using Bulletproofs++.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct BoundCheckBppStatement<E: Pairing> {
    /// The commitment to the message whose bounds are being checked
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub commitment: E::G1Affine,
    /// The commitment key used to create the commitment
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub commitment_key: E::G1Affine,
    /// The proof of knowledge of discrete log of commitment wrt commitment key
    pub pok_commitment: PokDiscreteLog<E::G1Affine>,
}
