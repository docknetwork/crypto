use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    error::ProofSystemError, setup_params::SetupParams, statement::Statement,
    sub_protocols::saver::SaverProtocol,
};
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey, VerifyingKey,
};

/// Proving knowledge of correctly encrypted message
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProver<E: Pairing> {
    pub chunk_bit_size: u8,
    pub encryption_gens: Option<EncryptionGens<E>>,
    pub chunked_commitment_gens: Option<ChunkedCommitmentGens<E::G1Affine>>,
    pub encryption_key: Option<EncryptionKey<E>>,
    pub snark_proving_key: Option<ProvingKey<E>>,
    pub encryption_gens_ref: Option<usize>,
    pub chunked_commitment_gens_ref: Option<usize>,
    pub encryption_key_ref: Option<usize>,
    pub snark_proving_key_ref: Option<usize>,
}

/// Verifying knowledge of correctly encrypted message
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverVerifier<E: Pairing> {
    pub chunk_bit_size: u8,
    pub encryption_gens: Option<EncryptionGens<E>>,
    pub chunked_commitment_gens: Option<ChunkedCommitmentGens<E::G1Affine>>,
    pub encryption_key: Option<EncryptionKey<E>>,
    #[serde_as(as = "Option<ArkObjectBytes>")]
    pub snark_verifying_key: Option<VerifyingKey<E>>,
    pub encryption_gens_ref: Option<usize>,
    pub chunked_commitment_gens_ref: Option<usize>,
    pub encryption_key_ref: Option<usize>,
    pub snark_verifying_key_ref: Option<usize>,
}

impl<E: Pairing> SaverProver<E> {
    pub fn new_statement_from_params(
        chunk_bit_size: u8,
        encryption_gens: EncryptionGens<E>,
        chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: EncryptionKey<E>,
        snark_proving_key: ProvingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        SaverProtocol::validate_encryption_key(chunk_bit_size, &encryption_key)?;
        Ok(Statement::SaverProver(Self {
            chunk_bit_size,
            encryption_gens: Some(encryption_gens),
            chunked_commitment_gens: Some(chunked_commitment_gens),
            encryption_key: Some(encryption_key),
            snark_proving_key: Some(snark_proving_key),
            encryption_gens_ref: None,
            chunked_commitment_gens_ref: None,
            encryption_key_ref: None,
            snark_proving_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        chunk_bit_size: u8,
        encryption_gens: usize,
        chunked_commitment_gens: usize,
        encryption_key: usize,
        snark_proving_key: usize,
    ) -> Statement<E> {
        Statement::SaverProver(Self {
            chunk_bit_size,
            encryption_gens: None,
            chunked_commitment_gens: None,
            encryption_key: None,
            snark_proving_key: None,
            encryption_gens_ref: Some(encryption_gens),
            chunked_commitment_gens_ref: Some(chunked_commitment_gens),
            encryption_key_ref: Some(encryption_key),
            snark_proving_key_ref: Some(snark_proving_key),
        })
    }

    pub fn get_encryption_gens<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a EncryptionGens<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.encryption_gens,
            self.encryption_gens_ref,
            SaverEncryptionGens,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_chunked_commitment_gens<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a ChunkedCommitmentGens<E::G1Affine>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.chunked_commitment_gens,
            self.chunked_commitment_gens_ref,
            SaverCommitmentGens,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_encryption_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a EncryptionKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.encryption_key,
            self.encryption_key_ref,
            SaverEncryptionKey,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_snark_proving_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a ProvingKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.snark_proving_key,
            self.snark_proving_key_ref,
            SaverProvingKey,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }
}

impl<E: Pairing> SaverVerifier<E> {
    pub fn new_statement_from_params(
        chunk_bit_size: u8,
        encryption_gens: EncryptionGens<E>,
        chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: EncryptionKey<E>,
        snark_verifying_key: VerifyingKey<E>,
    ) -> Result<Statement<E>, ProofSystemError> {
        SaverProtocol::validate_encryption_key(chunk_bit_size, &encryption_key)?;
        Ok(Statement::SaverVerifier(Self {
            chunk_bit_size,
            encryption_gens: Some(encryption_gens),
            chunked_commitment_gens: Some(chunked_commitment_gens),
            encryption_key: Some(encryption_key),
            snark_verifying_key: Some(snark_verifying_key),
            encryption_gens_ref: None,
            chunked_commitment_gens_ref: None,
            encryption_key_ref: None,
            snark_verifying_key_ref: None,
        }))
    }

    pub fn new_statement_from_params_ref(
        chunk_bit_size: u8,
        encryption_gens: usize,
        chunked_commitment_gens: usize,
        encryption_key: usize,
        snark_verifying_key: usize,
    ) -> Statement<E> {
        Statement::SaverVerifier(Self {
            chunk_bit_size,
            encryption_gens: None,
            chunked_commitment_gens: None,
            encryption_key: None,
            snark_verifying_key: None,
            encryption_gens_ref: Some(encryption_gens),
            chunked_commitment_gens_ref: Some(chunked_commitment_gens),
            encryption_key_ref: Some(encryption_key),
            snark_verifying_key_ref: Some(snark_verifying_key),
        })
    }

    pub fn get_encryption_gens<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a EncryptionGens<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.encryption_gens,
            self.encryption_gens_ref,
            SaverEncryptionGens,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_chunked_commitment_gens<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a ChunkedCommitmentGens<E::G1Affine>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.chunked_commitment_gens,
            self.chunked_commitment_gens_ref,
            SaverCommitmentGens,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_encryption_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a EncryptionKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.encryption_key,
            self.encryption_key_ref,
            SaverEncryptionKey,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }

    pub fn get_snark_verifying_key<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a VerifyingKey<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.snark_verifying_key,
            self.snark_verifying_key_ref,
            SaverVerifyingKey,
            IncompatibleSaverSetupParamAtIndex,
            st_idx
        )
    }
}
