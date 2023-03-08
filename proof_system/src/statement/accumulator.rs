use crate::error::ProofSystemError;
use crate::setup_params::SetupParams;
use crate::statement::Statement;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::prelude::{
    MembershipProvingKey, NonMembershipProvingKey, PublicKey, SetupParams as AccumParams,
};

/// Public values like setup params, public key, proving key and accumulator for proving membership
/// in positive and universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorMembership<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<MembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

/// Public values like setup params, public key, proving key and accumulator for proving non-membership
/// in universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorNonMembership<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<NonMembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: Pairing> AccumulatorMembership<E> {
    /// Create a statement by passing the accumulator params, public key and proving key directly.
    pub fn new_statement_from_params<G: AffineRepr>(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorMembership(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
    pub fn new_statement_from_params_ref<G: AffineRepr>(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorMembership(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    /// Get accumulator params for the statement index `s_idx` either from `self` or from given `setup_params`
    pub fn get_params<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a AccumParams<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            VbAccumulatorParams,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }

    /// Get publci key for the statement index `s_idx` either from `self` or from given `setup_params`
    pub fn get_public_key<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.public_key,
            self.public_key_ref,
            VbAccumulatorPublicKey,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }

    /// Get membership proving key for the statement index `s_idx` either from `self` or from given `setup_params`
    pub fn get_proving_key<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a MembershipProvingKey<E::G1Affine>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.proving_key,
            self.proving_key_ref,
            VbAccumulatorMemProvingKey,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }
}

impl<E: Pairing> AccumulatorNonMembership<E> {
    pub fn new_statement_from_params<G: AffineRepr>(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorNonMembership(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<G: AffineRepr>(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorNonMembership(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    pub fn get_params<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a AccumParams<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            VbAccumulatorParams,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_public_key<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.public_key,
            self.public_key_ref,
            VbAccumulatorPublicKey,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_proving_key<'a, G: AffineRepr>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a NonMembershipProvingKey<E::G1Affine>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.proving_key,
            self.proving_key_ref,
            VbAccumulatorNonMemProvingKey,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }
}
