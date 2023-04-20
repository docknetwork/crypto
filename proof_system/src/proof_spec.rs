use crate::{
    derived_params::{DerivedParamsTracker, StatementDerivedParams},
    error::ProofSystemError,
    meta_statement::{MetaStatement, MetaStatements},
    setup_params::SetupParams,
    statement::{Statement, Statements},
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::setup::{
    PreparedPublicKeyG2 as PreparedBBSPlusPk,
    PreparedSignatureParams23G1 as PreparedBBSSigParams23,
    PreparedSignatureParamsG1 as PreparedBBSPlusSigParams, PublicKeyG2 as BBSPlusPk,
    SignatureParams23G1 as BBSSigParams23, SignatureParamsG1 as BBSPlusSigParams,
};
use coconut_crypto::setup::{
    PreparedPublicKey as PreparedPSPk, PreparedSignatureParams as PreparedPSSigParams,
    PublicKey as PSPk, SignatureParams as PSSigParams,
};
use legogroth16::{
    aggregation::srs::{ProverSRS, VerifierSRS},
    PreparedVerifyingKey as LegoPreparedVerifyingKey, VerifyingKey as LegoVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, PreparedEncryptionGens,
    PreparedEncryptionKey, PreparedVerifyingKey as SaverPreparedVerifyingKey,
    VerifyingKey as SaverVerifyingKey,
};
use serde::{Deserialize, Serialize};
use vb_accumulator::setup::{
    PreparedPublicKey as PreparedAccumPk, PreparedSetupParams as PreparedAccumParams,
    PublicKey as AccumPk, SetupParams as AccumParams,
};

// TODO: Serialize snarkpack params
/// SRS used for Groth16 and LegoGroth16 proof aggregation using SnarkPack.
#[derive(Clone, Debug, PartialEq)]
pub enum SnarkpackSRS<E: Pairing> {
    /// SRS used by prover
    ProverSrs(ProverSRS<E>),
    /// SRS used by verifier
    VerifierSrs(VerifierSRS<E>),
}

/// Describes the relations that need to proven. This is created independently by the prover and verifier and must
/// be agreed upon and be same before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s.
/// Also contains other instructions like which proofs to aggregate.
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct ProofSpec<E: Pairing, G: AffineRepr> {
    pub statements: Statements<E, G>,
    pub meta_statements: MetaStatements,
    pub setup_params: Vec<SetupParams<E, G>>,
    /// `context` is any arbitrary data that needs to be hashed into the proof and it must be kept
    /// same while creating and verifying the proof. Eg of `context` are the purpose of
    /// the proof or the verifier's identity or some verifier-specific identity of the holder
    /// or all of the above combined.
    pub context: Option<Vec<u8>>,
    /// Statement indices for which Groth16 proof should be aggregated. Each BTreeSet represents one
    /// group of statements whose proof will be aggregated into 1 aggregate proof. The number of aggregate
    /// proofs is the length of the vector
    pub aggregate_groth16: Option<Vec<BTreeSet<usize>>>,
    /// Same as `aggregate_groth16` above but aggregates LegoGroth16 proof instead of Groth16.
    pub aggregate_legogroth16: Option<Vec<BTreeSet<usize>>>,
    // TODO: Remove this skip
    #[serde(skip)]
    pub snark_aggregation_srs: Option<SnarkpackSRS<E>>,
}

impl<E, G> ProofSpec<E, G>
where
    E: Pairing,
    G: AffineRepr,
{
    /// Create a new `ProofSpec`
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
            aggregate_groth16: None,
            aggregate_legogroth16: None,
            snark_aggregation_srs: None,
        }
    }

    /// Same as `Self::new` but specifies which proofs should be aggregated.
    pub fn new_with_aggregation(
        statements: Statements<E, G>,
        meta_statements: MetaStatements,
        setup_params: Vec<SetupParams<E, G>>,
        context: Option<Vec<u8>>,
        aggregate_groth16: Option<Vec<BTreeSet<usize>>>,
        aggregate_legogroth16: Option<Vec<BTreeSet<usize>>>,
        snark_aggregation_srs: Option<SnarkpackSRS<E>>,
    ) -> Self {
        Self {
            statements,
            meta_statements,
            setup_params,
            context,
            aggregate_groth16,
            aggregate_legogroth16,
            snark_aggregation_srs,
        }
    }

    pub fn add_statement(&mut self, statement: Statement<E, G>) -> usize {
        self.statements.add(statement)
    }

    pub fn add_meta_statement(&mut self, meta_statement: MetaStatement) -> usize {
        self.meta_statements.add(meta_statement)
    }

    /// Sanity check to ensure the proof spec is valid. This should never error as these are used
    /// by same entity creating them.
    pub fn validate(&self) -> Result<(), ProofSystemError> {
        // Ensure that messages(s) being revealed are not used in a witness equality.
        let mut revealed_wit_refs = BTreeSet::new();

        if (self.aggregate_groth16.is_some() || self.aggregate_legogroth16.is_some())
            && self.snark_aggregation_srs.is_none()
        {
            return Err(ProofSystemError::SnarckpackSrsNotProvided);
        }

        // Check that the same statement id does not occur in self.aggregate_groth16 and self.aggregate_legogroth16
        fn check_disjoint_in_same_list(
            st_ids: &Vec<BTreeSet<usize>>,
        ) -> Result<(), ProofSystemError> {
            let len_st_ids = st_ids.len();
            for (i, s_ids) in st_ids.iter().enumerate() {
                if i < (len_st_ids - 1) {
                    for j in (i + 1)..len_st_ids {
                        if !s_ids.is_disjoint(&st_ids[j]) {
                            return Err(
                                ProofSystemError::SameStatementIdsFoundInMultipleAggregations(
                                    s_ids.intersection(&st_ids[j]).cloned().collect(),
                                ),
                            );
                        }
                    }
                }
            }
            Ok(())
        }

        if let Some(g16) = &self.aggregate_groth16 {
            check_disjoint_in_same_list(g16)?
        }
        if let Some(lg16) = &self.aggregate_legogroth16 {
            check_disjoint_in_same_list(lg16)?
        }
        if let (Some(g16), Some(lg16)) = (&self.aggregate_groth16, &self.aggregate_legogroth16) {
            let len_lg16 = lg16.len();
            for s_ids in g16 {
                for j in 0..len_lg16 {
                    if !s_ids.is_disjoint(&lg16[j]) {
                        return Err(
                            ProofSystemError::SameStatementIdsFoundInMultipleAggregations(
                                s_ids.intersection(&lg16[j]).cloned().collect(),
                            ),
                        );
                    }
                }
            }
        }

        // Check that a message signed with BBS+ being revealed does not occur as a witness in any zero
        // knowledge proof
        for (i, st) in self.statements.0.iter().enumerate() {
            match st {
                Statement::PoKBBSSignatureG1(s) => {
                    for k in s.revealed_messages.keys() {
                        revealed_wit_refs.insert((i, *k));
                    }
                }
                Statement::PoKPSSignature(s) => {
                    for k in s.revealed_messages.keys() {
                        revealed_wit_refs.insert((i, *k));
                    }
                }
                _ => continue,
            }
        }
        for mt in &self.meta_statements.0 {
            match mt {
                // All witness equalities should be valid
                MetaStatement::WitnessEquality(w) => {
                    if !w.is_valid() {
                        return Err(ProofSystemError::InvalidWitnessEquality);
                    }
                    for r in w.0.iter() {
                        if revealed_wit_refs.contains(r) {
                            return Err(ProofSystemError::WitnessAlreadyBeingRevealed(r.0, r.1));
                        }
                    }
                }
            }
        }
        Ok(())
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
            StatementDerivedParams<Vec<E::G1Affine>>,
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
        let mut derived_r1cs_comm =
            DerivedParamsTracker::<LegoVerifyingKey<E>, Vec<E::G1Affine>, E>::new();

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

                Statement::R1CSCircomProver(_) | Statement::R1CSCircomVerifier(_) => {
                    let verifying_key = match statement {
                        Statement::R1CSCircomProver(s) => {
                            &s.get_proving_key(&self.setup_params, s_idx)?.vk
                        }
                        Statement::R1CSCircomVerifier(s) => {
                            s.get_verifying_key(&self.setup_params, s_idx)?
                        }
                        _ => panic!("This should never happen"),
                    };
                    derived_r1cs_comm.on_new_statement_idx(verifying_key, s_idx);
                }
                _ => (),
            }
        }
        Ok((
            derived_bound_check_comm.finish(),
            derived_ek_comm.finish(),
            derived_chunked_comm.finish(),
            derived_r1cs_comm.finish(),
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
            StatementDerivedParams<PreparedBBSPlusSigParams<E>>,
            StatementDerivedParams<PreparedBBSPlusPk<E>>,
            StatementDerivedParams<PreparedAccumParams<E>>,
            StatementDerivedParams<PreparedAccumPk<E>>,
            StatementDerivedParams<PreparedPSSigParams<E>>,
            StatementDerivedParams<PreparedPSPk<E>>,
            StatementDerivedParams<PreparedBBSSigParams23<E>>,
        ),
        ProofSystemError,
    > {
        let mut derived_lego_vk =
            DerivedParamsTracker::<LegoVerifyingKey<E>, LegoPreparedVerifyingKey<E>, E>::new();
        let mut derived_enc_gens =
            DerivedParamsTracker::<EncryptionGens<E>, PreparedEncryptionGens<E>, E>::new();
        let mut derived_ek =
            DerivedParamsTracker::<EncryptionKey<E>, PreparedEncryptionKey<E>, E>::new();
        let mut derived_saver_vk =
            DerivedParamsTracker::<SaverVerifyingKey<E>, SaverPreparedVerifyingKey<E>, E>::new();
        let mut derived_bbs_p =
            DerivedParamsTracker::<BBSPlusSigParams<E>, PreparedBBSPlusSigParams<E>, E>::new();
        let mut derived_bbs =
            DerivedParamsTracker::<BBSSigParams23<E>, PreparedBBSSigParams23<E>, E>::new();
        let mut derived_bbs_pk =
            DerivedParamsTracker::<BBSPlusPk<E>, PreparedBBSPlusPk<E>, E>::new();
        let mut derived_accum_p =
            DerivedParamsTracker::<AccumParams<E>, PreparedAccumParams<E>, E>::new();
        let mut derived_accum_pk = DerivedParamsTracker::<AccumPk<E>, PreparedAccumPk<E>, E>::new();
        let mut derived_ps_p =
            DerivedParamsTracker::<PSSigParams<E>, PreparedPSSigParams<E>, E>::new();
        let mut derived_ps_pk = DerivedParamsTracker::<PSPk<E>, PreparedPSPk<E>, E>::new();

        for (s_idx, statement) in self.statements.0.iter().enumerate() {
            match statement {
                Statement::PoKBBSSignatureG1(s) => {
                    let params = s.get_sig_params(&self.setup_params, s_idx)?;
                    derived_bbs_p.on_new_statement_idx(params, s_idx);

                    let pk = s.get_public_key(&self.setup_params, s_idx)?;
                    derived_bbs_pk.on_new_statement_idx(pk, s_idx);
                }
                Statement::PoKBBSSignature23G1(s) => {
                    let params = s.get_sig_params(&self.setup_params, s_idx)?;
                    derived_bbs.on_new_statement_idx(params, s_idx);

                    let pk = s.get_public_key(&self.setup_params, s_idx)?;
                    derived_bbs_pk.on_new_statement_idx(pk, s_idx);
                }
                Statement::AccumulatorMembership(s) => {
                    let params = s.get_params(&self.setup_params, s_idx)?;
                    derived_accum_p.on_new_statement_idx(params, s_idx);

                    let pk = s.get_public_key(&self.setup_params, s_idx)?;
                    derived_accum_pk.on_new_statement_idx(pk, s_idx);
                }
                Statement::AccumulatorNonMembership(s) => {
                    let params = s.get_params(&self.setup_params, s_idx)?;
                    derived_accum_p.on_new_statement_idx(params, s_idx);

                    let pk = s.get_public_key(&self.setup_params, s_idx)?;
                    derived_accum_pk.on_new_statement_idx(pk, s_idx);
                }
                Statement::SaverVerifier(s) => {
                    let gens = s.get_encryption_gens(&self.setup_params, s_idx)?;
                    derived_enc_gens.on_new_statement_idx(gens, s_idx);

                    let enc_key = s.get_encryption_key(&self.setup_params, s_idx)?;
                    derived_ek.on_new_statement_idx(enc_key, s_idx);

                    let verifying_key = s.get_snark_verifying_key(&self.setup_params, s_idx)?;
                    derived_saver_vk.on_new_statement_idx(verifying_key, s_idx);
                }
                Statement::BoundCheckLegoGroth16Verifier(s) => {
                    let verifying_key = s.get_verifying_key(&self.setup_params, s_idx)?;
                    derived_lego_vk.on_new_statement_idx(verifying_key, s_idx);
                }
                Statement::R1CSCircomVerifier(s) => {
                    let verifying_key = s.get_verifying_key(&self.setup_params, s_idx)?;
                    derived_lego_vk.on_new_statement_idx(verifying_key, s_idx);
                }
                Statement::PoKPSSignature(s) => {
                    let params = s.get_sig_params(&self.setup_params, s_idx)?;
                    derived_ps_p.on_new_statement_idx(params, s_idx);

                    let pk = s.get_public_key(&self.setup_params, s_idx)?;
                    derived_ps_pk.on_new_statement_idx(pk, s_idx);
                }
                _ => (),
            }
        }
        Ok((
            derived_lego_vk.finish(),
            derived_enc_gens.finish(),
            derived_ek.finish(),
            derived_saver_vk.finish(),
            derived_bbs_p.finish(),
            derived_bbs_pk.finish(),
            derived_accum_p.finish(),
            derived_accum_pk.finish(),
            derived_ps_p.finish(),
            derived_ps_pk.finish(),
            derived_bbs.finish(),
        ))
    }
}

impl<E, G> Default for ProofSpec<E, G>
where
    E: Pairing,
    G: AffineRepr,
{
    fn default() -> Self {
        Self {
            statements: Statements::new(),
            meta_statements: MetaStatements::new(),
            setup_params: Vec::new(),
            context: None,
            aggregate_groth16: None,
            aggregate_legogroth16: None,
            snark_aggregation_srs: None,
        }
    }
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, Valid, Validate};

    impl<E: Pairing> Valid for SnarkpackSRS<E> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::ProverSrs(s) => s.check(),
                Self::VerifierSrs(s) => s.check(),
            }
        }
    }

    impl<E: Pairing> CanonicalSerialize for SnarkpackSRS<E> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::ProverSrs(s) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::VerifierSrs(s) => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::ProverSrs(s) => 0u8.serialized_size(compress) + s.serialized_size(compress),
                Self::VerifierSrs(s) => 1u8.serialized_size(compress) + s.serialized_size(compress),
            }
        }
    }

    impl<E: Pairing> CanonicalDeserialize for SnarkpackSRS<E> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::ProverSrs(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                1u8 => Ok(Self::VerifierSrs(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
