use crate::error::ProofSystemError;
use crate::setup_params::SetupParams;
use crate::statement_v2::StatementV2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
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
pub struct AccumulatorMembership<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E::G2Affine>>,
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
pub struct AccumulatorNonMembership<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E::G2Affine>>,
    pub proving_key: Option<NonMembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: PairingEngine> AccumulatorMembership<E> {
    pub fn new_statement_from_params<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: PublicKey<E::G2Affine>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> StatementV2<E, G> {
        StatementV2::AccumulatorMembership(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<G: AffineCurve>(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> StatementV2<E, G> {
        StatementV2::AccumulatorMembership(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    pub fn get_params<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a AccumParams<E>, ProofSystemError> {
        if let Some(p) = &self.params {
            return Ok(p);
        }
        if let Some(idx) = self.params_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorParams(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_public_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKey<E::G2Affine>, ProofSystemError> {
        if let Some(pk) = &self.public_key {
            return Ok(pk);
        }
        if let Some(idx) = self.public_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorPublicKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_proving_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a MembershipProvingKey<E::G1Affine>, ProofSystemError> {
        if let Some(pk) = &self.proving_key {
            return Ok(pk);
        }
        if let Some(idx) = self.proving_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorMemProvingKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}

impl<E: PairingEngine> AccumulatorNonMembership<E> {
    pub fn new_statement_from_params<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: PublicKey<E::G2Affine>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> StatementV2<E, G> {
        StatementV2::AccumulatorNonMembership(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref<G: AffineCurve>(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> StatementV2<E, G> {
        StatementV2::AccumulatorNonMembership(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    pub fn get_params<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a AccumParams<E>, ProofSystemError> {
        if let Some(p) = &self.params {
            return Ok(p);
        }
        if let Some(idx) = self.params_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorParams(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_public_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a PublicKey<E::G2Affine>, ProofSystemError> {
        if let Some(pk) = &self.public_key {
            return Ok(pk);
        }
        if let Some(idx) = self.public_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorPublicKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_proving_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a NonMembershipProvingKey<E::G1Affine>, ProofSystemError> {
        if let Some(pk) = &self.proving_key {
            return Ok(pk);
        }
        if let Some(idx) = self.proving_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::VbAccumulatorNonMemProvingKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleAccumulatorSetupParamAtIndex(
                        idx,
                    )),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}
