use crate::derived_params::{DerivedParamsTracker, StatementDerivedParams};
use crate::error::ProofSystemError;
use crate::meta_statement::{MetaStatement, MetaStatements};
use crate::setup_params::SetupParams;
use crate::statement::{Statement, Statements};
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    io::{Read, Write},
    vec::Vec,
};
use legogroth16::{
    PreparedVerifyingKey as LegoPreparedVerifyingKey, VerifyingKey as LegoVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, PreparedEncryptionGens,
    PreparedEncryptionKey, PreparedVerifyingKey as SaverPreparedVerifyingKey,
    VerifyingKey as SaverVerifyingKey,
};
use serde::{Deserialize, Serialize};

/// Describes the relations that need to proven. This is created independently by the prover and verifier and must
/// be agreed upon and be same before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s.
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct ProofSpec<E: PairingEngine, G: AffineCurve> {
    pub statements: Statements<E, G>,
    pub meta_statements: MetaStatements,
    pub setup_params: Vec<SetupParams<E, G>>,
    /// `context` is any arbitrary data that needs to be hashed into the proof and it must be kept
    /// same while creating and verifying the proof. Eg of `context` are the purpose of
    /// the proof or the verifier's identity or some verifier-specific identity of the holder
    /// or all of the above combined.
    pub context: Option<Vec<u8>>,
}

impl<E, G> ProofSpec<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new(
        statements: Statements<E, G>,
        meta_statements: MetaStatements,
        setup_params: Vec<SetupParams<E, G>>,
        context: Option<Vec<u8>>,
    ) -> Self {
        Self {
            statements,
            meta_statements,
            setup_params,
            context,
        }
    }

    pub fn add_statement(&mut self, statement: Statement<E, G>) -> usize {
        self.statements.add(statement)
    }

    pub fn add_meta_statement(&mut self, meta_statement: MetaStatement) -> usize {
        self.meta_statements.add(meta_statement)
    }

    /// Sanity check to ensure the proof spec is valid. This should never be false as these are used
    /// by same entity creating them.
    pub fn is_valid(&self) -> bool {
        for mt in &self.meta_statements.0 {
            match mt {
                // All witness equalities should be valid
                MetaStatement::WitnessEquality(w) => {
                    if !w.is_valid() {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Derive commitment keys for Schnorr protocol from public params. This is done to avoid
    /// creating them if the same public params are used in multiple statements and is effectively a
    /// pre-processing step done for optimization.
    pub fn derive_commitment_keys(
        &self,
    ) -> Result<
        (
            StatementDerivedParams<Vec<E::G1Affine>>,
            StatementDerivedParams<Vec<E::G1Affine>>,
            StatementDerivedParams<(Vec<E::G1Affine>, Vec<E::G1Affine>)>,
        ),
        ProofSystemError,
    > {
        let mut derived_bound_check_comm =
            DerivedParamsTracker::<LegoVerifyingKey<E>, Vec<E::G1Affine>, E>::new();
        let mut derived_ek_comm =
            DerivedParamsTracker::<EncryptionKey<E>, Vec<E::G1Affine>, E>::new();
        let mut derived_chunked_comm = DerivedParamsTracker::<
            (&ChunkedCommitmentGens<E::G1Affine>, u8),
            (Vec<E::G1Affine>, Vec<E::G1Affine>),
            E,
        >::new();

        // To avoid creating variable with short lifetime
        let mut tuple_map = BTreeMap::new();
        for (s_idx, statement) in self.statements.0.iter().enumerate() {
            match statement {
                Statement::SaverProver(_) | Statement::SaverVerifier(_) => {
                    let (comm_gens, chunk_bit_size) = match statement {
                        Statement::SaverProver(s) => (
                            s.get_chunked_commitment_gens(&self.setup_params, s_idx)?,
                            s.chunk_bit_size,
                        ),
                        Statement::SaverVerifier(s) => (
                            s.get_chunked_commitment_gens(&self.setup_params, s_idx)?,
                            s.chunk_bit_size,
                        ),
                        _ => panic!("This should never happen"),
                    };
                    tuple_map.insert(s_idx, (comm_gens, chunk_bit_size));
                }
                _ => (),
            }
        }
        for (s_idx, statement) in self.statements.0.iter().enumerate() {
            match statement {
                Statement::SaverProver(_) | Statement::SaverVerifier(_) => {
                    let enc_key = match statement {
                        Statement::SaverProver(s) => {
                            s.get_encryption_key(&self.setup_params, s_idx)?
                        }
                        Statement::SaverVerifier(s) => {
                            s.get_encryption_key(&self.setup_params, s_idx)?
                        }
                        _ => panic!("This should never happen"),
                    };

                    derived_ek_comm.on_new_statement_idx(enc_key, s_idx);
                    derived_chunked_comm
                        .on_new_statement_idx(tuple_map.get(&s_idx).unwrap(), s_idx);
                }
                Statement::BoundCheckLegoGroth16Prover(_)
                | Statement::BoundCheckLegoGroth16Verifier(_) => {
                    let verifying_key = match statement {
                        Statement::BoundCheckLegoGroth16Prover(s) => {
                            &s.get_proving_key(&self.setup_params, s_idx)?.vk
                        }
                        Statement::BoundCheckLegoGroth16Verifier(s) => {
                            s.get_verifying_key(&self.setup_params, s_idx)?
                        }
                        _ => panic!("This should never happen"),
                    };
                    derived_bound_check_comm.on_new_statement_idx(verifying_key, s_idx);
                }
                _ => (),
            }
        }
        Ok((
            derived_bound_check_comm.finish(),
            derived_ek_comm.finish(),
            derived_chunked_comm.finish(),
        ))
    }

    /// Derive prepared keys for performing pairings. This is done to avoid preparing the same
    /// parameters again and is effectively a pre-processing step done for optimization.
    pub fn derive_prepared_parameters(
        &self,
    ) -> Result<
        (
            StatementDerivedParams<LegoPreparedVerifyingKey<E>>,
            StatementDerivedParams<PreparedEncryptionGens<E>>,
            StatementDerivedParams<PreparedEncryptionKey<E>>,
            StatementDerivedParams<SaverPreparedVerifyingKey<E>>,
        ),
        ProofSystemError,
    > {
        let mut derived_lego_vk =
            DerivedParamsTracker::<LegoVerifyingKey<E>, LegoPreparedVerifyingKey<E>, E>::new();
        let mut derived_gens =
            DerivedParamsTracker::<EncryptionGens<E>, PreparedEncryptionGens<E>, E>::new();
        let mut derived_ek =
            DerivedParamsTracker::<EncryptionKey<E>, PreparedEncryptionKey<E>, E>::new();
        let mut derived_saver_vk =
            DerivedParamsTracker::<SaverVerifyingKey<E>, SaverPreparedVerifyingKey<E>, E>::new();

        for (s_idx, statement) in self.statements.0.iter().enumerate() {
            match statement {
                Statement::SaverVerifier(s) => {
                    let gens = s.get_encryption_gens(&self.setup_params, s_idx)?;
                    derived_gens.on_new_statement_idx(gens, s_idx);

                    let enc_key = s.get_encryption_key(&self.setup_params, s_idx)?;
                    derived_ek.on_new_statement_idx(enc_key, s_idx);

                    let verifying_key = s.get_snark_verifying_key(&self.setup_params, s_idx)?;
                    derived_saver_vk.on_new_statement_idx(verifying_key, s_idx);
                }
                Statement::BoundCheckLegoGroth16Verifier(s) => {
                    let verifying_key = s.get_verifying_key(&self.setup_params, s_idx)?;
                    derived_lego_vk.on_new_statement_idx(verifying_key, s_idx);
                }
                _ => (),
            }
        }
        Ok((
            derived_lego_vk.finish(),
            derived_gens.finish(),
            derived_ek.finish(),
            derived_saver_vk.finish(),
        ))
    }
}

impl<E, G> Default for ProofSpec<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    fn default() -> Self {
        Self {
            statements: Statements::new(),
            meta_statements: MetaStatements::new(),
            setup_params: Vec::new(),
            context: None,
        }
    }
}
