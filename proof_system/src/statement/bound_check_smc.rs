use crate::{error::ProofSystemError, statement::Statement, sub_protocols::validate_bounds};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use smc_range_proof::prelude::{
    MemberCommitmentKey, SecretKey, SetMembershipCheckParams, SetMembershipCheckParamsWithPairing,
};

use crate::setup_params::SetupParams;
use dock_crypto_utils::serde_utils::ArkObjectBytes;

/// For ease of use, keeping setup params together but they could be generated independently
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SmcParamsAndCommitmentKey<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub params: SetMembershipCheckParams<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_key: MemberCommitmentKey<E::G1Affine>,
}

#[serde_as]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct SmcParamsWithPairingAndCommitmentKey<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub params: SetMembershipCheckParamsWithPairing<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_key: MemberCommitmentKey<E::G1Affine>,
}

impl<E: Pairing> SmcParamsAndCommitmentKey<E> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        base: u16,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let (params, sk) = SetMembershipCheckParams::new_for_range_proof::<R, D>(rng, label, base);
        let comm_key = MemberCommitmentKey::new::<D>(label);
        (Self { params, comm_key }, sk)
    }

    pub fn verify(&self) -> Result<(), ProofSystemError> {
        self.params.verify()?;
        Ok(())
    }
}

impl<E: Pairing> From<SmcParamsAndCommitmentKey<E>> for SmcParamsWithPairingAndCommitmentKey<E> {
    fn from(params: SmcParamsAndCommitmentKey<E>) -> Self {
        let comm_key = params.comm_key;
        let params = SetMembershipCheckParamsWithPairing::from(params.params);
        Self { comm_key, params }
    }
}

/// Proving knowledge of message that satisfies given bounds, i.e. `min <= message < max` using set-membership based check.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckSmc<E: Pairing> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub params_and_comm_key: Option<SmcParamsAndCommitmentKey<E>>,
    pub params_and_comm_key_ref: Option<usize>,
}

impl<E: Pairing> BoundCheckSmc<E> {
    pub fn new_statement_from_params(
        min: u64,
        max: u64,
        params: SmcParamsAndCommitmentKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckSmc(Self {
            min,
            max,
            params_and_comm_key: Some(params),
            params_and_comm_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        min: u64,
        max: u64,
        params_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckSmc(Self {
            min,
            max,
            params_and_comm_key: None,
            params_and_comm_key_ref: Some(params_ref),
        }))
    }

    pub fn get_params_and_comm_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a SmcParamsAndCommitmentKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params_and_comm_key,
            self.params_and_comm_key_ref,
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
