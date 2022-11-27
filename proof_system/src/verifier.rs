use crate::error::ProofSystemError;
use crate::proof::Proof;
use crate::proof_spec::ProofSpec;
use crate::statement::Statement;
use crate::statement_proof::StatementProof;
use crate::sub_protocols::accumulator::{
    AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol,
};
use crate::sub_protocols::bbs_plus::PoKBBSSigG1SubProtocol;
use crate::sub_protocols::bound_check_legogroth16::BoundCheckProtocol;
use crate::sub_protocols::r1cs_legogorth16::R1CSLegogroth16Protocol;
use crate::sub_protocols::saver::SaverProtocol;
use crate::sub_protocols::schnorr::SchnorrProtocol;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::rand::RngCore;
use digest::Digest;
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

#[derive(Default)]
pub struct VerifierConfig {
    pub use_randomized_pairing_checks: bool,
}

impl<E, G, D> Proof<E, G, D>
where
    E: PairingEngine,
    G: AffineCurve<ScalarField = E::Fr>,
    D: Digest,
{
    /// Verify the `Proof` given the `ProofSpec` and `nonce`
    pub fn verify(
        self,
        proof_spec: ProofSpec<E, G>,
        nonce: Option<Vec<u8>>,
        config: VerifierConfig,
    ) -> Result<(), ProofSystemError> {
        self._verify(proof_spec, nonce, config, None)
    }

    pub fn verify_using_randomized_pairing_check<R: RngCore>(
        self,
        rng: &mut R,
        proof_spec: ProofSpec<E, G>,
        nonce: Option<Vec<u8>>,
        config: VerifierConfig,
    ) -> Result<(), ProofSystemError> {
        let checker = RandomizedPairingChecker::new(rng);
        self._verify(proof_spec, nonce, config, Some(checker))
    }

    fn _verify(
        self,
        proof_spec: ProofSpec<E, G>,
        nonce: Option<Vec<u8>>,
        config: VerifierConfig,
        mut pairing_checker: Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        proof_spec.validate()?;

        // Number of statement proofs is less than number of statements which means some statements
        // are not satisfied.
        if proof_spec.statements.len() > self.statement_proofs.len() {
            return Err(ProofSystemError::UnsatisfiedStatements(
                proof_spec.statements.len(),
                self.statement_proofs.len(),
            ));
        }

        // Prepare commitment keys for running Schnorr protocols of all statements.
        let (bound_check_comm, ek_comm, chunked_comm, r1cs_comm_keys) =
            proof_spec.derive_commitment_keys()?;

        // Prepared required parameters for pairings
        let (derived_lego_vk, derived_gens, derived_ek, derived_saver_vk) =
            proof_spec.derive_prepared_parameters()?;

        // All the distinct equalities in `ProofSpec`
        let mut witness_equalities = vec![];

        if !proof_spec.meta_statements.is_empty() {
            let disjoint_equalities = proof_spec.meta_statements.disjoint_witness_equalities();
            for eq_wits in disjoint_equalities {
                witness_equalities.push(eq_wits.0);
            }
        }

        // This will hold the response for each witness equality. If there is no response for some witness
        // equality, it will contain `None` corresponding to that.
        let mut responses_for_equalities: Vec<Option<&E::Fr>> =
            vec![None; witness_equalities.len()];

        // Get nonce's and context's challenge contribution
        let mut challenge_bytes = vec![];
        if let Some(n) = nonce.as_ref() {
            challenge_bytes.extend_from_slice(n)
        }
        if let Some(ctx) = &proof_spec.context {
            challenge_bytes.extend_from_slice(ctx);
        }

        // Get challenge contribution for each statement and check if response is equal for all witnesses.
        for (s_idx, (statement, proof)) in proof_spec
            .statements
            .0
            .iter()
            .zip(self.statement_proofs.iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1(s) => match proof {
                    StatementProof::PoKBBSSignatureG1(p) => {
                        let revealed_msg_ids = s.revealed_messages.keys().map(|k| *k).collect();
                        let sig_params = s.get_sig_params(&proof_spec.setup_params, s_idx)?;
                        // Check witness equalities for this statement.
                        for i in 0..sig_params.supported_message_count() {
                            let w_ref = (s_idx, i);
                            for j in 0..witness_equalities.len() {
                                if witness_equalities[j].contains(&w_ref) {
                                    let resp = p.get_resp_for_message(i, &revealed_msg_ids)?;
                                    Self::check_response_for_equality(
                                        s_idx,
                                        i,
                                        j,
                                        &mut responses_for_equalities,
                                        resp,
                                    )?;
                                }
                            }
                        }
                        p.challenge_contribution(
                            &s.revealed_messages,
                            sig_params,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorMembership(s) => match proof {
                    StatementProof::AccumulatorMembership(p) => {
                        for i in 0..witness_equalities.len() {
                            // Check witness equalities for this statement. As there is only 1 witness
                            // of interest, i.e. the accumulator member, its index is always 0
                            if witness_equalities[i].contains(&(s_idx, 0)) {
                                let resp = p.get_schnorr_response_for_element();
                                Self::check_response_for_equality(
                                    s_idx,
                                    0,
                                    i,
                                    &mut responses_for_equalities,
                                    resp,
                                )?;
                            }
                        }
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorNonMembership(s) => match proof {
                    StatementProof::AccumulatorNonMembership(p) => {
                        // Check witness equalities for this statement. As there is only 1 witness
                        // of interest, i.e. the accumulator non-member, its index is always 0
                        for i in 0..witness_equalities.len() {
                            if witness_equalities[i].contains(&(s_idx, 0)) {
                                let resp = p.get_schnorr_response_for_element();
                                Self::check_response_for_equality(
                                    s_idx,
                                    0,
                                    i,
                                    &mut responses_for_equalities,
                                    resp,
                                )?;
                            }
                        }
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::PedersenCommitment(s) => match proof {
                    StatementProof::PedersenCommitment(p) => {
                        let comm_key = s.get_commitment_key(&proof_spec.setup_params, s_idx)?;
                        for i in 0..comm_key.len() {
                            // Check witness equalities for this statement.
                            for j in 0..witness_equalities.len() {
                                if witness_equalities[j].contains(&(s_idx, i)) {
                                    let r = p.response.get_response(i)?;
                                    Self::check_response_for_equality(
                                        s_idx,
                                        i,
                                        j,
                                        &mut responses_for_equalities,
                                        r,
                                    )?;
                                }
                            }
                        }

                        SchnorrProtocol::compute_challenge_contribution(
                            comm_key,
                            &s.commitment,
                            &p.t,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::SaverVerifier(s) => match proof {
                    StatementProof::Saver(p) => {
                        for i in 0..witness_equalities.len() {
                            if witness_equalities[i].contains(&(s_idx, 0)) {
                                let resp = p.get_schnorr_response_for_combined_message()?;
                                Self::check_response_for_equality(
                                    s_idx,
                                    0,
                                    i,
                                    &mut responses_for_equalities,
                                    resp,
                                )?;
                            }
                        }
                        let ek_comm_key = ek_comm.get(s_idx).unwrap();
                        let cc_keys = chunked_comm.get(s_idx).unwrap();
                        SaverProtocol::compute_challenge_contribution(
                            ek_comm_key,
                            &cc_keys.0,
                            &cc_keys.1,
                            p,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::BoundCheckLegoGroth16Verifier(s) => match proof {
                    StatementProof::BoundCheckLegoGroth16(p) => {
                        for i in 0..witness_equalities.len() {
                            if witness_equalities[i].contains(&(s_idx, 0)) {
                                let resp = p.get_schnorr_response_for_message()?;
                                Self::check_response_for_equality(
                                    s_idx,
                                    0,
                                    i,
                                    &mut responses_for_equalities,
                                    resp,
                                )?;
                            }
                        }

                        let comm_key = bound_check_comm.get(s_idx).unwrap();
                        BoundCheckProtocol::compute_challenge_contribution(
                            comm_key,
                            &p,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::R1CSCircomVerifier(s) => match proof {
                    StatementProof::R1CSLegoGroth16(p) => {
                        let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                        for i in 0..witness_equalities.len() {
                            for j in 0..verifying_key.commit_witness_count {
                                if witness_equalities[i].contains(&(s_idx, j)) {
                                    let resp = p.get_schnorr_response_for_message(j)?;
                                    Self::check_response_for_equality(
                                        s_idx,
                                        j,
                                        i,
                                        &mut responses_for_equalities,
                                        resp,
                                    )?;
                                }
                            }
                        }

                        R1CSLegogroth16Protocol::compute_challenge_contribution(
                            r1cs_comm_keys.get(s_idx).unwrap(),
                            &p,
                            &mut challenge_bytes,
                        )?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                _ => return Err(ProofSystemError::InvalidStatement),
            }
        }

        // If even one of witness equality had no corresponding response, it means that wasn't satisfied
        // and proof should not verify
        if responses_for_equalities.iter().any(|r| r.is_none()) {
            return Err(ProofSystemError::UnsatisfiedWitnessEqualities(
                responses_for_equalities
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| match r {
                        None => Some(witness_equalities[i].clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ));
        }

        // Verifier independently generates challenge
        let challenge = Self::generate_challenge_from_bytes(&challenge_bytes);

        // Verify the proof for each statement
        for (s_idx, (statement, proof)) in proof_spec
            .statements
            .0
            .iter()
            .zip(self.statement_proofs.into_iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1(s) => match proof {
                    StatementProof::PoKBBSSignatureG1(ref p) => {
                        let sig_params = s.get_sig_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp = PoKBBSSigG1SubProtocol::new(
                            s_idx,
                            &s.revealed_messages,
                            sig_params,
                            pk,
                        );
                        sp.verify_proof_contribution(&challenge, &p, &mut pairing_checker)?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorMembership(s) => match proof {
                    StatementProof::AccumulatorMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = AccumulatorMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(&challenge, &p, &mut pairing_checker)?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorNonMembership(s) => match proof {
                    StatementProof::AccumulatorNonMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = AccumulatorNonMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(&challenge, &p, &mut pairing_checker)?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::PedersenCommitment(s) => match proof {
                    StatementProof::PedersenCommitment(ref _p) => {
                        let comm_key = s.get_commitment_key(&proof_spec.setup_params, s_idx)?;
                        let sp = SchnorrProtocol::new(s_idx, comm_key, s.commitment);
                        sp.verify_proof_contribution(&challenge, &proof)?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::SaverVerifier(s) => match proof {
                    StatementProof::Saver(ref saver_proof) => {
                        let enc_gens = s.get_encryption_gens(&proof_spec.setup_params, s_idx)?;
                        let comm_gens =
                            s.get_chunked_commitment_gens(&proof_spec.setup_params, s_idx)?;
                        let enc_key = s.get_encryption_key(&proof_spec.setup_params, s_idx)?;
                        let vk = s.get_snark_verifying_key(&proof_spec.setup_params, s_idx)?;
                        let sp = SaverProtocol::new_for_verifier(
                            s_idx,
                            s.chunk_bit_size,
                            enc_gens,
                            comm_gens,
                            enc_key,
                            vk,
                        );
                        let ek_comm_key = ek_comm.get(s_idx).unwrap();
                        let cc_keys = chunked_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution_using_prepared(
                            &challenge,
                            saver_proof,
                            ek_comm_key,
                            &cc_keys.0,
                            &cc_keys.1,
                            derived_saver_vk.get(s_idx).unwrap(),
                            derived_gens.get(s_idx).unwrap(),
                            derived_ek.get(s_idx).unwrap(),
                            &mut pairing_checker
                        )?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::BoundCheckLegoGroth16Verifier(s) => match proof {
                    StatementProof::BoundCheckLegoGroth16(ref bc_proof) => {
                        let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                        let sp = BoundCheckProtocol::new_for_verifier(
                            s_idx,
                            s.min,
                            s.max,
                            verifying_key,
                        );
                        let comm_key = bound_check_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution_using_prepared(
                            &challenge,
                            bc_proof,
                            &comm_key,
                            derived_lego_vk.get(s_idx).unwrap(),
                            &mut pairing_checker
                        )?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::R1CSCircomVerifier(s) => match proof {
                    StatementProof::R1CSLegoGroth16(ref r1cs_proof) => {
                        let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                        let sp = R1CSLegogroth16Protocol::new_for_verifier(s_idx, verifying_key);
                        sp.verify_proof_contribution_using_prepared(
                            &challenge,
                            s.get_public_inputs(&proof_spec.setup_params, s_idx)?,
                            r1cs_proof,
                            r1cs_comm_keys.get(s_idx).unwrap(),
                            derived_lego_vk.get(s_idx).unwrap(),
                            &mut pairing_checker
                        )?
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
                _ => return Err(ProofSystemError::InvalidStatement),
            }
        }

        if let Some(c) = pairing_checker {
            if !c.verify() {
                return Err(ProofSystemError::RandomizedPairingCheckFailed);
            }
        }
        Ok(())
    }

    /// Used to check if response (from Schnorr protocol) for a witness is equal to other witnesses that
    /// it must be equal to. This is required when the `ProofSpec` demands certain witnesses to be equal.
    fn check_response_for_equality<'a>(
        stmt_id: usize,
        wit_id: usize,
        equality_id: usize,
        responses_for_equalities: &mut [Option<&'a E::Fr>],
        resp: &'a E::Fr,
    ) -> Result<(), ProofSystemError> {
        if responses_for_equalities[equality_id].is_none() {
            // First response encountered for the witness
            responses_for_equalities[equality_id] = Some(resp);
        } else if responses_for_equalities[equality_id] != Some(resp) {
            return Err(ProofSystemError::WitnessResponseNotEqual(stmt_id, wit_id));
        }
        Ok(())
    }
}
