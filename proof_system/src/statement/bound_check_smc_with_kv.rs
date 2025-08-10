use crate::{
    error::ProofSystemError, setup_params::SetupParams, statement::Statement,
    sub_protocols::validate_bounds,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use smc_range_proof::{
    ccs_set_membership::setup::SetMembershipCheckParamsKV,
    prelude::{MemberCommitmentKey, SecretKey},
};

/// For ease of use, keeping setup params together, but they could be generated independently
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SmcParamsKVAndCommitmentKey<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub params: SetMembershipCheckParamsKV<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub comm_key: MemberCommitmentKey<G>,
}

/// Used by the verifier as it knows the secret key. Should not be shared with the prover
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SmcParamsKVAndCommitmentKeyAndSecretKey<G: AffineRepr> {
    pub params_and_comm_key: SmcParamsKVAndCommitmentKey<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub sk: SecretKey<G::ScalarField>,
}

impl<G: AffineRepr> SmcParamsKVAndCommitmentKeyAndSecretKey<G> {
    pub fn new<R: RngCore, D: Digest>(rng: &mut R, label: &[u8], base: u16) -> Self {
        let (params_and_comm_key, sk) = SmcParamsKVAndCommitmentKey::new::<R, D>(rng, label, base);
        Self {
            params_and_comm_key,
            sk,
        }
    }

    pub fn get_smc_params(&self) -> &SetMembershipCheckParamsKV<G> {
        &self.params_and_comm_key.params
    }

    pub fn get_comm_key(&self) -> &MemberCommitmentKey<G> {
        &self.params_and_comm_key.comm_key
    }
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct BoundCheckSmcWithKVProver<G: AffineRepr> {
    pub min: u64,
    pub max: u64,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<ArkObjectBytes>"))]
    pub params: Option<SmcParamsKVAndCommitmentKey<G>>,
    pub params_ref: Option<usize>,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct BoundCheckSmcWithKVVerifier<G: AffineRepr> {
    pub min: u64,
    pub max: u64,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<ArkObjectBytes>"))]
    pub params: Option<SmcParamsKVAndCommitmentKeyAndSecretKey<G>>,
    pub params_ref: Option<usize>,
}

impl<G: AffineRepr> BoundCheckSmcWithKVProver<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        min: u64,
        max: u64,
        params: SmcParamsKVAndCommitmentKey<G>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckSmcWithKVProver(Self {
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
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckSmcWithKVProver(Self {
            min,
            max,
            params: None,
            params_ref: Some(params_ref),
        }))
    }

    pub fn get_params_and_comm_key<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SmcParamsKVAndCommitmentKey<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            SmcParamsKVAndCommKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_comm_key<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MemberCommitmentKey<G>, ProofSystemError> {
        Ok(&self.get_params_and_comm_key(setup_params, st_idx)?.comm_key)
    }
}

impl<G: AffineRepr> BoundCheckSmcWithKVVerifier<G> {
    pub fn new_statement_from_params<E: Pairing<G1Affine = G>>(
        min: u64,
        max: u64,
        params: SmcParamsKVAndCommitmentKeyAndSecretKey<G>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckSmcWithKVVerifier(Self {
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
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckSmcWithKVVerifier(Self {
            min,
            max,
            params: None,
            params_ref: Some(params_ref),
        }))
    }

    pub fn get_params_and_comm_key_and_sk<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SmcParamsKVAndCommitmentKeyAndSecretKey<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            SmcParamsAndCommKeyAndSk,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_comm_key<'a, E: Pairing<G1Affine = G>>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MemberCommitmentKey<G>, ProofSystemError> {
        Ok(self
            .get_params_and_comm_key_and_sk(setup_params, st_idx)?
            .get_comm_key())
    }
}

impl<G: AffineRepr> SmcParamsKVAndCommitmentKey<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        base: u16,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let (params, sk) =
            SetMembershipCheckParamsKV::new_for_range_proof::<R, D>(rng, label, base);
        let comm_key = MemberCommitmentKey::new::<D>(label);
        (Self { params, comm_key }, sk)
    }
}
