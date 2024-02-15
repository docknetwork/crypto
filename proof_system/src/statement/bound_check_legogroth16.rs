use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub use legogroth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey};

use crate::{
    error::ProofSystemError,
    setup_params::SetupParams,
    statement::Statement,
    sub_protocols::{bound_check_legogroth16::BoundCheckLegoGrothProtocol, validate_bounds},
};
use dock_crypto_utils::serde_utils::ArkObjectBytes;

/// Proving knowledge of message that satisfies given bounds [min, max), i.e. `min <= message < max` using LegoGroth16.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16Prover<E: Pairing> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub snark_proving_key: Option<ProvingKey<E>>,
    pub snark_proving_key_ref: Option<usize>,
}

/// Proving knowledge of message that satisfies given bounds [min, max), i.e. `min <= message < max` using LegoGroth16
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16Verifier<E: Pairing> {
    pub min: u64,
    pub max: u64,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub snark_verifying_key: Option<VerifyingKey<E>>,
    pub snark_verifying_key_ref: Option<usize>,
}

impl<E: Pairing> BoundCheckLegoGroth16Prover<E> {
    pub fn new_statement_from_params(
        min: u64,
        max: u64,
        snark_proving_key: ProvingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        BoundCheckLegoGrothProtocol::validate_verification_key(&snark_proving_key.vk)?;
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckLegoGroth16Prover(Self {
            min,
            max,
            snark_proving_key: Some(snark_proving_key),
            snark_proving_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        min: u64,
        max: u64,
        snark_proving_key_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckLegoGroth16Prover(Self {
            min,
            max,
            snark_proving_key: None,
            snark_proving_key_ref: Some(snark_proving_key_ref),
        }))
    }

    pub fn get_proving_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a ProvingKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.snark_proving_key,
            self.snark_proving_key_ref,
            LegoSnarkProvingKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }
}

impl<E: Pairing> BoundCheckLegoGroth16Verifier<E> {
    pub fn new_statement_from_params(
        min: u64,
        max: u64,
        snark_verifying_key: VerifyingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        BoundCheckLegoGrothProtocol::validate_verification_key(&snark_verifying_key)?;
        validate_bounds(min, max)?;

        Ok(Statement::BoundCheckLegoGroth16Verifier(Self {
            min,
            max,
            snark_verifying_key: Some(snark_verifying_key),
            snark_verifying_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        min: u64,
        max: u64,
        snark_verifying_key_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        validate_bounds(min, max)?;
        Ok(Statement::BoundCheckLegoGroth16Verifier(Self {
            min,
            max,
            snark_verifying_key: None,
            snark_verifying_key_ref: Some(snark_verifying_key_ref),
        }))
    }

    pub fn get_verifying_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a VerifyingKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.snark_verifying_key,
            self.snark_verifying_key_ref,
            LegoSnarkVerifyingKey,
            IncompatibleBoundCheckSetupParamAtIndex,
            st_idx
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn bound_check_statement_validity() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();
        assert!(
            BoundCheckLegoGroth16Prover::new_statement_from_params(5, 5, snark_pk.clone()).is_err()
        );
        assert!(BoundCheckLegoGroth16Verifier::new_statement_from_params(
            5,
            5,
            snark_pk.vk.clone()
        )
        .is_err());
        assert!(
            BoundCheckLegoGroth16Prover::new_statement_from_params(5, 4, snark_pk.clone()).is_err()
        );
        assert!(BoundCheckLegoGroth16Verifier::new_statement_from_params(
            5,
            4,
            snark_pk.vk.clone()
        )
        .is_err());
        assert!(
            BoundCheckLegoGroth16Prover::new_statement_from_params(5, 6, snark_pk.clone()).is_ok()
        );
        assert!(
            BoundCheckLegoGroth16Verifier::new_statement_from_params(5, 6, snark_pk.vk).is_ok()
        );
    }
}
