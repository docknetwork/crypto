use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
pub use legogroth16::{circom::R1CS, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSCircomProver<E: Pairing> {
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub r1cs: Option<R1CS<E>>,
    pub r1cs_ref: Option<usize>,
    pub wasm_bytes: Option<Vec<u8>>,
    pub wasm_bytes_ref: Option<usize>,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub snark_proving_key: Option<ProvingKey<E>>,
    pub snark_proving_key_ref: Option<usize>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSCircomVerifier<E: Pairing> {
    #[serde_as(as = "Option<Vec<ArkObjectBytes>>")]
    pub public_inputs: Option<Vec<E::ScalarField>>,
    pub public_inputs_ref: Option<usize>,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub snark_verifying_key: Option<VerifyingKey<E>>,
    pub snark_verifying_key_ref: Option<usize>,
}

impl<E: Pairing> R1CSCircomProver<E> {
    pub fn new_statement_from_params(
        r1cs: R1CS<E>,
        wasm_bytes: Vec<u8>,
        snark_proving_key: ProvingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomProver(Self {
            r1cs: Some(r1cs),
            r1cs_ref: None,
            wasm_bytes: Some(wasm_bytes),
            wasm_bytes_ref: None,
            snark_proving_key: Some(snark_proving_key),
            snark_proving_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        r1cs_ref: usize,
        wasm_bytes_ref: usize,
        snark_proving_key_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomProver(Self {
            r1cs: None,
            r1cs_ref: Some(r1cs_ref),
            wasm_bytes: None,
            wasm_bytes_ref: Some(wasm_bytes_ref),
            snark_proving_key: None,
            snark_proving_key_ref: Some(snark_proving_key_ref),
        }))
    }

    pub fn new_statement_from_params_when_reusing_proof(
        snark_proving_key: ProvingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomProver(Self {
            r1cs: None,
            r1cs_ref: None,
            wasm_bytes: None,
            wasm_bytes_ref: None,
            snark_proving_key: Some(snark_proving_key),
            snark_proving_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref_when_reusing_proof(
        snark_proving_key_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomProver(Self {
            r1cs: None,
            r1cs_ref: None,
            wasm_bytes: None,
            wasm_bytes_ref: None,
            snark_proving_key: None,
            snark_proving_key_ref: Some(snark_proving_key_ref),
        }))
    }

    pub fn get_r1cs<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a R1CS<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.r1cs,
            self.r1cs_ref,
            R1CS,
            IncompatibleR1CSSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_wasm_bytes<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a Vec<u8>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.wasm_bytes,
            self.wasm_bytes_ref,
            Bytes,
            IncompatibleR1CSSetupParamAtIndex,
            st_idx
        )
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
            IncompatibleR1CSSetupParamAtIndex,
            st_idx
        )
    }
}

impl<E: Pairing> R1CSCircomVerifier<E> {
    pub fn new_statement_from_params(
        public_inputs: Vec<E::ScalarField>,
        snark_verifying_key: VerifyingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomVerifier(Self {
            public_inputs: Some(public_inputs),
            public_inputs_ref: None,
            snark_verifying_key: Some(snark_verifying_key),
            snark_verifying_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        public_inputs_ref: usize,
        snark_verifying_key_ref: usize,
    ) -> Result<Statement<E>, ProofSystemError> {
        Ok(Statement::R1CSCircomVerifier(Self {
            public_inputs: None,
            public_inputs_ref: Some(public_inputs_ref),
            snark_verifying_key: None,
            snark_verifying_key_ref: Some(snark_verifying_key_ref),
        }))
    }

    pub fn get_public_inputs<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a Vec<E::ScalarField>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.public_inputs,
            self.public_inputs_ref,
            FieldElemVec,
            IncompatibleR1CSSetupParamAtIndex,
            st_idx
        )
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
            IncompatibleR1CSSetupParamAtIndex,
            st_idx
        )
    }
}
