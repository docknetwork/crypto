use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::ProofSystemError;
use crate::prelude::saver::SaverProtocol;
use crate::setup_params::SetupParams;
use crate::statement_v2::StatementV2;
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey, VerifyingKey,
};
use saver::saver_groth16::Groth16VerifyingKeyBytes;

/// Proving knowledge of correctly encrypted message
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProver<E: PairingEngine> {
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
pub struct SaverVerifier<E: PairingEngine> {
    pub chunk_bit_size: u8,
    pub encryption_gens: Option<EncryptionGens<E>>,
    pub chunked_commitment_gens: Option<ChunkedCommitmentGens<E::G1Affine>>,
    pub encryption_key: Option<EncryptionKey<E>>,
    #[serde_as(as = "Option<Groth16VerifyingKeyBytes>")]
    pub snark_verifying_key: Option<VerifyingKey<E>>,
    pub encryption_gens_ref: Option<usize>,
    pub chunked_commitment_gens_ref: Option<usize>,
    pub encryption_key_ref: Option<usize>,
    pub snark_verifying_key_ref: Option<usize>,
}

impl<E: PairingEngine> SaverProver<E> {
    pub fn new_statement_from_params<G: AffineCurve>(
        chunk_bit_size: u8,
        encryption_gens: EncryptionGens<E>,
        chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: EncryptionKey<E>,
        snark_proving_key: ProvingKey<E>,
    ) -> Result<StatementV2<E, G>, ProofSystemError> {
        SaverProtocol::validate_encryption_key(chunk_bit_size, &encryption_key)?;
        Ok(StatementV2::SaverProver(Self {
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

    pub fn new_statement_from_params_ref<G: AffineCurve>(
        chunk_bit_size: u8,
        encryption_gens: usize,
        chunked_commitment_gens: usize,
        encryption_key: usize,
        snark_proving_key: usize,
    ) -> Result<StatementV2<E, G>, ProofSystemError> {
        Ok(StatementV2::SaverProver(Self {
            chunk_bit_size,
            encryption_gens: None,
            chunked_commitment_gens: None,
            encryption_key: None,
            snark_proving_key: None,
            encryption_gens_ref: Some(encryption_gens),
            chunked_commitment_gens_ref: Some(chunked_commitment_gens),
            encryption_key_ref: Some(encryption_key),
            snark_proving_key_ref: Some(snark_proving_key),
        }))
    }

    pub fn get_encryption_gens<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a EncryptionGens<E>, ProofSystemError> {
        if let Some(g) = &self.encryption_gens {
            return Ok(g);
        }
        if let Some(idx) = self.encryption_gens_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverEncryptionGens(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_chunked_commitment_gens<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a ChunkedCommitmentGens<E::G1Affine>, ProofSystemError> {
        if let Some(g) = &self.chunked_commitment_gens {
            return Ok(g);
        }
        if let Some(idx) = self.chunked_commitment_gens_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverCommitmentGens(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_encryption_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a EncryptionKey<E>, ProofSystemError> {
        if let Some(k) = &self.encryption_key {
            return Ok(k);
        }
        if let Some(idx) = self.encryption_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverEncryptionKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_snark_proving_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a ProvingKey<E>, ProofSystemError> {
        if let Some(k) = &self.snark_proving_key {
            return Ok(k);
        }
        if let Some(idx) = self.snark_proving_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverProvingKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}

impl<E: PairingEngine> SaverVerifier<E> {
    pub fn new_statement_from_params<G: AffineCurve>(
        chunk_bit_size: u8,
        encryption_gens: EncryptionGens<E>,
        chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: EncryptionKey<E>,
        snark_verifying_key: VerifyingKey<E>,
    ) -> Result<StatementV2<E, G>, ProofSystemError> {
        SaverProtocol::validate_encryption_key(chunk_bit_size, &encryption_key)?;
        Ok(StatementV2::SaverVerifier(Self {
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

    pub fn new_statement_from_params_ref<G: AffineCurve>(
        chunk_bit_size: u8,
        encryption_gens: usize,
        chunked_commitment_gens: usize,
        encryption_key: usize,
        snark_verifying_key: usize,
    ) -> Result<StatementV2<E, G>, ProofSystemError> {
        Ok(StatementV2::SaverVerifier(Self {
            chunk_bit_size,
            encryption_gens: None,
            chunked_commitment_gens: None,
            encryption_key: None,
            snark_verifying_key: None,
            encryption_gens_ref: Some(encryption_gens),
            chunked_commitment_gens_ref: Some(chunked_commitment_gens),
            encryption_key_ref: Some(encryption_key),
            snark_verifying_key_ref: Some(snark_verifying_key),
        }))
    }

    pub fn get_encryption_gens<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a EncryptionGens<E>, ProofSystemError> {
        if let Some(g) = &self.encryption_gens {
            return Ok(g);
        }
        if let Some(idx) = self.encryption_gens_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverEncryptionGens(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_chunked_commitment_gens<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a ChunkedCommitmentGens<E::G1Affine>, ProofSystemError> {
        if let Some(g) = &self.chunked_commitment_gens {
            return Ok(g);
        }
        if let Some(idx) = self.chunked_commitment_gens_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverCommitmentGens(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_encryption_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a EncryptionKey<E>, ProofSystemError> {
        if let Some(k) = &self.encryption_key {
            return Ok(k);
        }
        if let Some(idx) = self.encryption_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverEncryptionKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }

    pub fn get_snark_verifying_key<'a, G: AffineCurve>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a VerifyingKey<E>, ProofSystemError> {
        if let Some(k) = &self.snark_verifying_key {
            return Ok(k);
        }
        if let Some(idx) = self.snark_verifying_key_ref {
            if idx < setup_params.len() {
                match &setup_params[idx] {
                    SetupParams::SaverVerifyingKey(p) => Ok(p),
                    _ => Err(ProofSystemError::IncompatibleSaverSetupParamAtIndex(idx)),
                }
            } else {
                Err(ProofSystemError::InvalidSetupParamsIndex(idx))
            }
        } else {
            Err(ProofSystemError::NeitherParamsNorRefGiven(st_idx))
        }
    }
}
