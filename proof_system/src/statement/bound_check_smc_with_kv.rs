use crate::{
    error::ProofSystemError,
    setup_params::SetupParams,
    statement::{bound_check_smc::SmcParamsAndCommitmentKey, Statement},
    sub_protocols::validate_bounds,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smc_range_proof::prelude::{MemberCommitmentKey, SecretKey, SetMembershipCheckParams};

/// Used by the verifier as it knows the secret key. Should not be shared with the prover
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SmcParamsAndCommitmentKeyAndSecretKey<E: Pairing> {
    pub params_and_comm_key: SmcParamsAndCommitmentKey<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub sk: SecretKey<E::ScalarField>,
}

impl<E: Pairing> SmcParamsAndCommitmentKeyAndSecretKey<E> {
    pub fn new<R: RngCore, D: Digest>(rng: &mut R, label: &[u8], base: u16) -> Self {
        let (params_and_comm_key, sk) = SmcParamsAndCommitmentKey::new::<R, D>(rng, label, base);
        Self {
            params_and_comm_key,
            sk,
        }
    }

    pub fn verify(&self) -> Result<(), ProofSystemError> {
        self.params_and_comm_key.verify()?;
        Ok(())
    }

    pub fn get_smc_params(&self) -> &SetMembershipCheckParams<E> {
        &self.params_and_comm_key.params
    }

    pub fn get_comm_key(&self) -> &MemberCommitmentKey<E::G1Affine> {
        &self.params_and_comm_key.comm_key
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckSmcWithKVProver<E: Pairing> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub params: Option<SmcParamsAndCommitmentKey<E>>,
    pub params_ref: Option<usize>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckSmcWithKVVerifier<E: Pairing> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub params: Option<SmcParamsAndCommitmentKeyAndSecretKey<E>>,
    pub params_ref: Option<usize>,
}

impl<E: Pairing> BoundCheckSmcWithKVProver<E> {
    pub fn new_statement_from_params(
        min: u64,
        max: u64,
        params: SmcParamsAndCommitmentKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckSmcWithKVProver(Self {
            min,
            max,
            params: Some(params),
            params_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
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

    pub fn get_params_and_comm_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SmcParamsAndCommitmentKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            SmcParamsAndCommKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_comm_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MemberCommitmentKey<E::G1Affine>, ProofSystemError> {
        Ok(&self.get_params_and_comm_key(setup_params, st_idx)?.comm_key)
    }
}

impl<E: Pairing> BoundCheckSmcWithKVVerifier<E> {
    pub fn new_statement_from_params(
        min: u64,
        max: u64,
        params: SmcParamsAndCommitmentKeyAndSecretKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckSmcWithKVVerifier(Self {
            min,
            max,
            params: Some(params),
            params_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
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

    pub fn get_params_and_comm_key_and_sk<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SmcParamsAndCommitmentKeyAndSecretKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            SmcParamsAndCommKeyAndSk,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_comm_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a MemberCommitmentKey<E::G1Affine>, ProofSystemError> {
        Ok(self
            .get_params_and_comm_key_and_sk(setup_params, st_idx)?
            .get_comm_key())
    }
}
