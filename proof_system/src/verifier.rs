use crate::{
    constants::{
        BBS_23_LABEL, BBS_PLUS_LABEL, BDDT16_KVAC_LABEL, COMPOSITE_PROOF_CHALLENGE_LABEL,
        COMPOSITE_PROOF_LABEL, CONTEXT_LABEL, KB_POS_ACCUM_CDH_MEM_LABEL, KB_POS_ACCUM_MEM_LABEL,
        KB_UNI_ACCUM_CDH_MEM_LABEL, KB_UNI_ACCUM_CDH_NON_MEM_LABEL, KB_UNI_ACCUM_MEM_LABEL,
        KB_UNI_ACCUM_NON_MEM_LABEL, NONCE_LABEL, PS_LABEL, VB_ACCUM_CDH_MEM_LABEL,
        VB_ACCUM_CDH_NON_MEM_LABEL, VB_ACCUM_MEM_LABEL, VB_ACCUM_NON_MEM_LABEL,
    },
    error::ProofSystemError,
    proof::Proof,
    proof_spec::{ProofSpec, SnarkpackSRS},
    statement::Statement,
    statement_proof::StatementProof,
    sub_protocols::{
        accumulator::{
            cdh::{
                KBPositiveAccumulatorMembershipCDHSubProtocol,
                KBUniversalAccumulatorMembershipCDHSubProtocol,
                KBUniversalAccumulatorNonMembershipCDHSubProtocol,
                VBAccumulatorMembershipCDHSubProtocol, VBAccumulatorNonMembershipCDHSubProtocol,
            },
            keyed_verification::{
                KBUniversalAccumulatorMembershipKVSubProtocol,
                KBUniversalAccumulatorNonMembershipKVSubProtocol,
                VBAccumulatorMembershipKVSubProtocol,
            },
            KBPositiveAccumulatorMembershipSubProtocol,
            KBUniversalAccumulatorMembershipSubProtocol,
            KBUniversalAccumulatorNonMembershipSubProtocol, VBAccumulatorMembershipSubProtocol,
            VBAccumulatorNonMembershipSubProtocol,
        },
        bbs_23::PoKBBSSigG1SubProtocol as PoKBBSSig23G1SubProtocol,
        bbs_23_ietf::PoKBBSSigIETFG1SubProtocol as PoKBBSSig23IETFG1SubProtocol,
        bbs_plus::PoKBBSSigG1SubProtocol,
        bddt16_kvac::PoKOfMACSubProtocol,
        bound_check_bpp::BoundCheckBppProtocol,
        bound_check_legogroth16::BoundCheckLegoGrothProtocol,
        bound_check_smc::BoundCheckSmcProtocol,
        bound_check_smc_with_kv::BoundCheckSmcWithKVProtocol,
        inequality::InequalityProtocol,
        ps_signature::PSSignaturePoK,
        r1cs_legogorth16::R1CSLegogroth16Protocol,
        saver::SaverProtocol,
        schnorr::SchnorrProtocol,
    },
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, format, rand::RngCore, vec, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    expect_equality,
    randomized_pairing_check::RandomizedPairingChecker,
    signature::MultiMessageSignatureParams,
    transcript::{MerlinTranscript, Transcript},
};
use saver::encryption::Ciphertext;

/// Passed to the verifier during proof verification
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct VerifierConfig {
    /// Uses `RandomizedPairingChecker` to speed up pairing checks.
    /// If true, uses lazy `RandomizedPairingChecker` that trades-off memory for compute time
    pub use_lazy_randomized_pairing_checks: Option<bool>,
}

macro_rules! err_incompat_proof {
    ($s_idx:ident, $s: ident, $proof: ident) => {
        return Err(ProofSystemError::ProofIncompatibleWithStatement(
            $s_idx,
            format!("{:?}", $proof),
            format!("{:?}", $s),
        ))
    };
}

macro_rules! check_resp_for_equalities {
    ($witness_equalities:ident, $s_idx: ident, $p: expr, $func_name: ident, $self: ident, $responses_for_equalities: ident) => {
        for i in 0..$witness_equalities.len() {
            // Check witness equalities for this statement. As there is only 1 witness
            // of interest, its index is always 0
            if $witness_equalities[i].contains(&($s_idx, 0)) {
                let resp = $p.$func_name();
                $self::check_response_for_equality(
                    $s_idx,
                    0,
                    i,
                    &mut $responses_for_equalities,
                    resp,
                )?;
            }
        }
    };
}

macro_rules! check_resp_for_equalities_with_err {
    ($witness_equalities:ident, $s_idx: ident, $p: expr, $func_name: ident, $self: ident, $responses_for_equalities: ident) => {
        for i in 0..$witness_equalities.len() {
            // Check witness equalities for this statement. As there is only 1 witness
            // of interest, its index is always 0
            if $witness_equalities[i].contains(&($s_idx, 0)) {
                let resp = $p.$func_name()?;
                $self::check_response_for_equality(
                    $s_idx,
                    0,
                    i,
                    &mut $responses_for_equalities,
                    resp,
                )?;
            }
        }
    };
}

impl<E: Pairing> Proof<E> {
    /// Verify the `Proof` given the `ProofSpec`, `nonce` and `config`
    pub fn verify<R: RngCore, D: Digest>(
        self,
        rng: &mut R,
        proof_spec: ProofSpec<E>,
        nonce: Option<Vec<u8>>,
        config: VerifierConfig,
    ) -> Result<(), ProofSystemError> {
        match config.use_lazy_randomized_pairing_checks {
            Some(b) => {
                let pairing_checker = RandomizedPairingChecker::new_using_rng(rng, b);
                self._verify::<R, D>(rng, proof_spec, nonce, Some(pairing_checker))
            }
            None => self._verify::<R, D>(rng, proof_spec, nonce, None),
        }
    }

    fn _verify<R: RngCore, D: Digest>(
        self,
        rng: &mut R,
        proof_spec: ProofSpec<E>,
        nonce: Option<Vec<u8>>,
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

        let mut transcript = MerlinTranscript::new(COMPOSITE_PROOF_LABEL);

        // TODO: Check SNARK SRSs compatible when aggregating and statement proof compatible with proof spec when aggregating

        let aggregate_snarks =
            proof_spec.aggregate_groth16.is_some() || proof_spec.aggregate_legogroth16.is_some();
        let mut agg_saver = Vec::<Vec<Ciphertext<E>>>::new();
        let mut agg_lego = Vec::<(Vec<E::G1Affine>, Vec<Vec<E::ScalarField>>)>::new();

        let mut agg_saver_stmts = BTreeMap::new();
        let mut agg_lego_stmts = BTreeMap::new();

        if aggregate_snarks {
            if let Some(a) = &proof_spec.aggregate_groth16 {
                for (i, s) in a.iter().enumerate() {
                    for j in s {
                        agg_saver_stmts.insert(*j, i);
                    }
                    agg_saver.push(vec![]);
                }
            }

            if let Some(a) = &proof_spec.aggregate_legogroth16 {
                for (i, s) in a.iter().enumerate() {
                    for j in s {
                        agg_lego_stmts.insert(*j, i);
                    }
                    agg_lego.push((vec![], vec![]));
                }
            }
        }

        // Prepare commitment keys for running Schnorr protocols of all statements.
        let (
            bound_check_comm,
            ek_comm,
            chunked_comm,
            r1cs_comm_keys,
            bound_check_bpp_comm,
            bound_check_smc_comm,
            ineq_comm,
        ) = proof_spec.derive_commitment_keys()?;

        // Prepare required parameters for pairings
        let (
            derived_lego_vk,
            derived_gens,
            derived_ek,
            derived_saver_vk,
            derived_bbs_plus_param,
            derived_bbs_pk,
            derived_accum_param,
            derived_accum_pk,
            derived_kb_accum_param,
            derived_kb_accum_pk,
            derived_ps_param,
            derived_ps_pk,
            derived_bbs_param,
            derived_smc_param,
        ) = proof_spec.derive_prepared_parameters()?;

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
        let mut responses_for_equalities: Vec<Option<&E::ScalarField>> =
            vec![None; witness_equalities.len()];

        // Get nonce's and context's challenge contribution
        if let Some(n) = nonce.as_ref() {
            transcript.append_message(NONCE_LABEL, n);
        }
        if let Some(ctx) = &proof_spec.context {
            transcript.append_message(CONTEXT_LABEL, ctx);
        }

        macro_rules! sig_protocol_chal_gen {
            ($s: ident, $s_idx: ident, $p: ident, $label: ident) => {{
                let revealed_msg_ids = $s.revealed_messages.keys().copied().collect();
                let params = $s.get_params(&proof_spec.setup_params, $s_idx)?;
                // Check witness equalities for this statement.
                for i in 0..params.supported_message_count() {
                    let w_ref = ($s_idx, i);
                    for j in 0..witness_equalities.len() {
                        if witness_equalities[j].contains(&w_ref) {
                            let resp = $p.get_resp_for_message(i, &revealed_msg_ids)?;
                            Self::check_response_for_equality(
                                $s_idx,
                                i,
                                j,
                                &mut responses_for_equalities,
                                resp,
                            )?;
                        }
                    }
                }
                transcript.set_label($label);
                $p.challenge_contribution(&$s.revealed_messages, params, &mut transcript)?;
            }};
        }

        macro_rules! ped_comm_protocol_chal_gen {
            ($s: ident, $s_idx: ident, $p: ident, $com_key_func: ident) => {{
                let comm_key = $s.$com_key_func(&proof_spec.setup_params, $s_idx)?;
                for i in 0..comm_key.len() {
                    // Check witness equalities for this statement.
                    for j in 0..witness_equalities.len() {
                        if witness_equalities[j].contains(&($s_idx, i)) {
                            let r = $p.response.get_response(i)?;
                            Self::check_response_for_equality(
                                $s_idx,
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
                    &$s.commitment,
                    &$p.t,
                    &mut transcript,
                )?;
            }};
        }

        macro_rules! accum_cdh_protocol_chal_gen {
            ($s: ident, $s_idx: ident, $p: ident, $label: ident) => {{
                check_resp_for_equalities!(
                    witness_equalities,
                    $s_idx,
                    $p,
                    get_schnorr_response_for_element,
                    Self,
                    responses_for_equalities
                );
                transcript.set_label($label);
                $p.challenge_contribution(&$s.accumulator_value, &mut transcript)?;
            }};
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
                Statement::PoKBBSSignatureG1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignatureG1(p) => {
                        sig_protocol_chal_gen!(s, s_idx, p, BBS_PLUS_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBBSSignature23G1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignature23G1(p) => {
                        sig_protocol_chal_gen!(s, s_idx, p, BBS_23_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBBSSignature23IETFG1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignature23IETFG1(p) => {
                        sig_protocol_chal_gen!(s, s_idx, p, BBS_23_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembership(s) => match proof {
                    StatementProof::VBAccumulatorMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(VB_ACCUM_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorNonMembership(s) => match proof {
                    StatementProof::VBAccumulatorNonMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(VB_ACCUM_NON_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembership(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(KB_UNI_ACCUM_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembership(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(KB_UNI_ACCUM_NON_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipCDHVerifier(s) => match proof {
                    StatementProof::VBAccumulatorMembershipCDH(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, VB_ACCUM_CDH_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorNonMembershipCDHVerifier(s) => match proof {
                    StatementProof::VBAccumulatorNonMembershipCDH(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(VB_ACCUM_CDH_NON_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            params,
                            &s.Q,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipCDHVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipCDH(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_CDH_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipCDHVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipCDH(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_CDH_NON_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBPositiveAccumulatorMembership(s) => match proof {
                    StatementProof::KBPositiveAccumulatorMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(KB_POS_ACCUM_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBPositiveAccumulatorMembershipCDH(s) => match proof {
                    StatementProof::KBPositiveAccumulatorMembershipCDH(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(KB_POS_ACCUM_CDH_MEM_LABEL);
                        p.challenge_contribution(
                            &s.accumulator_value,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PedersenCommitment(s) => match proof {
                    StatementProof::PedersenCommitment(p) => {
                        ped_comm_protocol_chal_gen!(s, s_idx, p, get_commitment_key);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PedersenCommitmentG2(s) => match proof {
                    StatementProof::PedersenCommitmentG2(p) => {
                        ped_comm_protocol_chal_gen!(s, s_idx, p, get_commitment_key_g2);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::SaverVerifier(s) => match proof {
                    StatementProof::Saver(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_combined_message,
                            Self,
                            responses_for_equalities
                        );
                        let ek_comm_key = ek_comm.get(s_idx).unwrap();
                        let cc_keys = chunked_comm.get(s_idx).unwrap();
                        SaverProtocol::compute_challenge_contribution(
                            ek_comm_key,
                            &cc_keys.0,
                            &cc_keys.1,
                            p,
                            &mut transcript,
                        )?;
                    }
                    StatementProof::SaverWithAggregation(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_combined_message,
                            Self,
                            responses_for_equalities
                        );
                        let ek_comm_key = ek_comm.get(s_idx).unwrap();
                        let cc_keys = chunked_comm.get(s_idx).unwrap();
                        SaverProtocol::compute_challenge_contribution_when_aggregating_snark(
                            ek_comm_key,
                            &cc_keys.0,
                            &cc_keys.1,
                            p,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckLegoGroth16Verifier(s) => match proof {
                    StatementProof::BoundCheckLegoGroth16(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key = bound_check_comm.get(s_idx).unwrap();
                        BoundCheckLegoGrothProtocol::compute_challenge_contribution(
                            comm_key,
                            p,
                            &mut transcript,
                        )?;
                    }
                    StatementProof::BoundCheckLegoGroth16WithAggregation(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key = bound_check_comm.get(s_idx).unwrap();
                        BoundCheckLegoGrothProtocol::compute_challenge_contribution_when_aggregating_snark(
                            comm_key,
                            p,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::R1CSCircomVerifier(s) => {
                    let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                    match proof {
                        StatementProof::R1CSLegoGroth16(p) => {
                            for i in 0..witness_equalities.len() {
                                for j in 0..verifying_key.commit_witness_count as usize {
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
                                p,
                                &mut transcript,
                            )?;
                        }
                        StatementProof::R1CSLegoGroth16WithAggregation(p) => {
                            for i in 0..witness_equalities.len() {
                                for j in 0..verifying_key.commit_witness_count as usize {
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

                            R1CSLegogroth16Protocol::compute_challenge_contribution_when_aggregating_snark(
                                r1cs_comm_keys.get(s_idx).unwrap(),
                                p,
                                &mut transcript,
                            )?;
                        }
                        _ => err_incompat_proof!(s_idx, s, proof),
                    }
                }
                Statement::PoKPSSignature(s) => match proof {
                    StatementProof::PoKPSSignature(p) => {
                        let revealed_msg_ids: Vec<_> =
                            s.revealed_messages.keys().copied().collect();
                        let sig_params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        // Check witness equalities for this statement.
                        for i in 0..sig_params.supported_message_count() {
                            let w_ref = (s_idx, i);
                            for j in 0..witness_equalities.len() {
                                if witness_equalities[j].contains(&w_ref) {
                                    let resp = p.response_for_message(
                                        i,
                                        revealed_msg_ids.iter().copied(),
                                    )?;
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
                        transcript.set_label(PS_LABEL);
                        p.challenge_contribution(&mut transcript, pk, sig_params)?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckBpp(s) => match proof {
                    StatementProof::BoundCheckBpp(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key = bound_check_bpp_comm.get(s_idx).unwrap();
                        BoundCheckBppProtocol::<E::G1Affine>::compute_challenge_contribution(
                            s.min,
                            s.max,
                            comm_key.as_slice(),
                            p,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckSmc(s) => match proof {
                    StatementProof::BoundCheckSmc(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        BoundCheckSmcProtocol::compute_challenge_contribution(
                            comm_key_slice.as_slice(),
                            p,
                            s.get_params_and_comm_key(&proof_spec.setup_params, s_idx)
                                .unwrap(),
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckSmcWithKVVerifier(s) => match proof {
                    StatementProof::BoundCheckSmcWithKV(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        BoundCheckSmcWithKVProtocol::compute_challenge_contribution(
                            comm_key_slice.as_slice(),
                            p,
                            s.get_params_and_comm_key_and_sk(&proof_spec.setup_params, s_idx)?,
                            &mut transcript,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PublicInequality(s) => match proof {
                    StatementProof::Inequality(p) => {
                        check_resp_for_equalities_with_err!(
                            witness_equalities,
                            s_idx,
                            p,
                            get_schnorr_response_for_message,
                            Self,
                            responses_for_equalities
                        );

                        let comm_key_slice = ineq_comm.get(s_idx).unwrap();
                        InequalityProtocol::compute_challenge_contribution(
                            comm_key_slice.as_slice(),
                            p,
                            &s.inequal_to,
                            s.get_comm_key(&proof_spec.setup_params, s_idx)?,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::DetachedAccumulatorMembershipVerifier(s) => match proof {
                    StatementProof::DetachedAccumulatorMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p.accum_proof,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(VB_ACCUM_MEM_LABEL);
                        p.accum_proof.challenge_contribution(
                            &p.accumulator,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::DetachedAccumulatorNonMembershipVerifier(s) => match proof {
                    StatementProof::DetachedAccumulatorNonMembership(p) => {
                        check_resp_for_equalities!(
                            witness_equalities,
                            s_idx,
                            p.accum_proof,
                            get_schnorr_response_for_element,
                            Self,
                            responses_for_equalities
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        transcript.set_label(VB_ACCUM_NON_MEM_LABEL);
                        p.accum_proof.challenge_contribution(
                            &p.accumulator,
                            pk,
                            params,
                            prk,
                            &mut transcript,
                        )?;
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBDDT16MAC(s) => match proof {
                    StatementProof::PoKOfBDDT16MAC(p) => {
                        sig_protocol_chal_gen!(s, s_idx, p, BDDT16_KVAC_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBDDT16MACFullVerifier(s) => match proof {
                    StatementProof::PoKOfBDDT16MAC(p) => {
                        sig_protocol_chal_gen!(s, s_idx, p, BDDT16_KVAC_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipKV(s) => match proof {
                    StatementProof::VBAccumulatorMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, VB_ACCUM_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipKVFullVerifier(s) => match proof {
                    StatementProof::VBAccumulatorMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, VB_ACCUM_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipKV(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipKVFullVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipKV(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_NON_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipKVFullVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipKV(p) => {
                        accum_cdh_protocol_chal_gen!(s, s_idx, p, KB_UNI_ACCUM_NON_MEM_LABEL);
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
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
        let challenge = transcript.challenge_scalar(COMPOSITE_PROOF_CHALLENGE_LABEL);

        macro_rules! sig_protocol_verify {
            ($s: ident, $s_idx: ident, $protocol: ident, $func_name: ident, $p: ident, $derived_pk: ident, $derived_param: ident, $error_variant: ident) => {{
                let params = $s.get_params(&proof_spec.setup_params, $s_idx)?;
                let pk = $s.get_public_key(&proof_spec.setup_params, $s_idx)?;
                let sp = $protocol::$func_name($s_idx, &$s.revealed_messages, params, pk);
                sp.verify_proof_contribution(
                    &challenge,
                    $p,
                    $derived_pk.get($s_idx).unwrap().clone(),
                    $derived_param.get($s_idx).unwrap().clone(),
                    &mut pairing_checker,
                )
                .map_err(|e| ProofSystemError::$error_variant($s_idx as u32, e))?
            }};
        }

        // Verify the proof for each statement
        for (s_idx, (statement, proof)) in proof_spec
            .statements
            .0
            .iter()
            .zip(self.statement_proofs.into_iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignatureG1(ref p) => {
                        sig_protocol_verify!(
                            s,
                            s_idx,
                            PoKBBSSigG1SubProtocol,
                            new_for_verifier,
                            p,
                            derived_bbs_pk,
                            derived_bbs_plus_param,
                            BBSPlusProofContributionFailed
                        );
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBBSSignature23G1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignature23G1(ref p) => {
                        sig_protocol_verify!(
                            s,
                            s_idx,
                            PoKBBSSig23G1SubProtocol,
                            new_for_verifier,
                            p,
                            derived_bbs_pk,
                            derived_bbs_param,
                            BBSProofContributionFailed
                        );
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBBSSignature23IETFG1Verifier(s) => match proof {
                    StatementProof::PoKBBSSignature23IETFG1(ref p) => {
                        sig_protocol_verify!(
                            s,
                            s_idx,
                            PoKBBSSig23IETFG1SubProtocol,
                            new_for_verifier,
                            p,
                            derived_bbs_pk,
                            derived_bbs_param,
                            BBSProofContributionFailed
                        );
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembership(s) => match proof {
                    StatementProof::VBAccumulatorMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = VBAccumulatorMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorNonMembership(s) => match proof {
                    StatementProof::VBAccumulatorNonMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = VBAccumulatorNonMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembership(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = KBUniversalAccumulatorMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembership(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = KBUniversalAccumulatorNonMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipCDHVerifier(s) => match proof {
                    StatementProof::VBAccumulatorMembershipCDH(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp = VBAccumulatorMembershipCDHSubProtocol::new_for_verifier(
                            s_idx,
                            s.accumulator_value,
                            params,
                            pk,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorNonMembershipCDHVerifier(s) => match proof {
                    StatementProof::VBAccumulatorNonMembershipCDH(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp = VBAccumulatorNonMembershipCDHSubProtocol::new_for_verifier(
                            s_idx,
                            s.accumulator_value,
                            s.Q,
                            params,
                            pk,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipCDHVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipCDH(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp = KBUniversalAccumulatorMembershipCDHSubProtocol::new_for_verifier(
                            s_idx,
                            s.accumulator_value,
                            params,
                            pk,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipCDHVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipCDH(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp =
                            KBUniversalAccumulatorNonMembershipCDHSubProtocol::new_for_verifier(
                                s_idx,
                                s.accumulator_value,
                                params,
                                pk,
                            );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_accum_pk.get(s_idx).unwrap().clone(),
                            derived_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBPositiveAccumulatorMembership(s) => match proof {
                    StatementProof::KBPositiveAccumulatorMembership(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = KBPositiveAccumulatorMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_kb_accum_pk.get(s_idx).unwrap().clone(),
                            derived_kb_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBPositiveAccumulatorMembershipCDH(s) => match proof {
                    StatementProof::KBPositiveAccumulatorMembershipCDH(ref p) => {
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let sp = KBPositiveAccumulatorMembershipCDHSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(
                            &challenge,
                            p,
                            derived_kb_accum_pk.get(s_idx).unwrap().clone(),
                            derived_kb_accum_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PedersenCommitment(s) => match proof {
                    StatementProof::PedersenCommitment(ref p) => {
                        let comm_key = s.get_commitment_key(&proof_spec.setup_params, s_idx)?;
                        let sp = SchnorrProtocol::new(s_idx, comm_key, s.commitment);
                        sp.verify_proof_contribution(&challenge, p).map_err(|e| {
                            ProofSystemError::SchnorrProofContributionFailed(s_idx as u32, e)
                        })?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PedersenCommitmentG2(s) => match proof {
                    StatementProof::PedersenCommitmentG2(ref p) => {
                        let comm_key = s.get_commitment_key_g2(&proof_spec.setup_params, s_idx)?;
                        let sp = SchnorrProtocol::new(s_idx, comm_key, s.commitment);
                        sp.verify_proof_contribution(&challenge, p).map_err(|e| {
                            ProofSystemError::SchnorrProofContributionFailed(s_idx as u32, e)
                        })?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::SaverVerifier(s) => {
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

                    match proof {
                        StatementProof::Saver(ref saver_proof) => sp.verify_proof_contribution(
                            &challenge,
                            saver_proof,
                            ek_comm_key,
                            &cc_keys.0,
                            &cc_keys.1,
                            derived_saver_vk.get(s_idx).unwrap(),
                            derived_gens.get(s_idx).unwrap().clone(),
                            derived_ek.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?,
                        StatementProof::SaverWithAggregation(ref saver_proof) => {
                            let agg_idx = agg_saver_stmts.get(&s_idx).ok_or_else(|| {
                                ProofSystemError::InvalidStatementProofIndex(s_idx)
                            })?;
                            agg_saver[*agg_idx].push(saver_proof.ciphertext.clone());
                            sp.verify_ciphertext_and_commitment(
                                &challenge,
                                &saver_proof.ciphertext,
                                saver_proof.comm_combined.clone(),
                                saver_proof.comm_chunks.clone(),
                                &saver_proof.sp_ciphertext,
                                &saver_proof.sp_chunks,
                                &saver_proof.sp_combined,
                                ek_comm_key,
                                &cc_keys.0,
                                &cc_keys.1,
                            )?
                        }
                        _ => {
                            return Err(ProofSystemError::ProofIncompatibleWithStatement(
                                s_idx,
                                format!("{:?}", proof),
                                format!("{:?}", s),
                            ))
                        }
                    }
                }
                Statement::BoundCheckLegoGroth16Verifier(s) => {
                    let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                    let sp = BoundCheckLegoGrothProtocol::new_for_verifier(
                        s_idx,
                        s.min,
                        s.max,
                        verifying_key,
                    );
                    let comm_key = bound_check_comm.get(s_idx).unwrap();
                    match proof {
                        StatementProof::BoundCheckLegoGroth16(ref bc_proof) => sp
                            .verify_proof_contribution(
                                &challenge,
                                bc_proof,
                                comm_key,
                                derived_lego_vk.get(s_idx).unwrap(),
                                &mut pairing_checker,
                            )?,
                        StatementProof::BoundCheckLegoGroth16WithAggregation(ref bc_proof) => {
                            let pub_inp =
                                vec![E::ScalarField::from(sp.min), E::ScalarField::from(sp.max)];
                            let agg_idx = agg_lego_stmts.get(&s_idx).ok_or_else(|| {
                                ProofSystemError::InvalidStatementProofIndex(s_idx)
                            })?;
                            agg_lego[*agg_idx].0.push(bc_proof.commitment);
                            agg_lego[*agg_idx].1.push(pub_inp);
                            sp.verify_proof_contribution_using_prepared_when_aggregating_snark(
                                &challenge, bc_proof, comm_key,
                            )?
                        }
                        _ => {
                            return Err(ProofSystemError::ProofIncompatibleWithStatement(
                                s_idx,
                                format!("{:?}", proof),
                                format!("{:?}", s),
                            ))
                        }
                    }
                }
                Statement::R1CSCircomVerifier(s) => {
                    let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                    let sp = R1CSLegogroth16Protocol::new_for_verifier(s_idx, verifying_key);
                    let pub_inp = s
                        .get_public_inputs(&proof_spec.setup_params, s_idx)?
                        .to_vec();

                    match proof {
                        StatementProof::R1CSLegoGroth16(ref r1cs_proof) => sp
                            .verify_proof_contribution(
                                &challenge,
                                &pub_inp,
                                r1cs_proof,
                                r1cs_comm_keys.get(s_idx).unwrap(),
                                derived_lego_vk.get(s_idx).unwrap(),
                                &mut pairing_checker,
                            )?,
                        StatementProof::R1CSLegoGroth16WithAggregation(ref r1cs_proof) => {
                            let agg_idx = agg_lego_stmts.get(&s_idx).ok_or_else(|| {
                                ProofSystemError::InvalidStatementProofIndex(s_idx)
                            })?;
                            agg_lego[*agg_idx].0.push(r1cs_proof.commitment);
                            agg_lego[*agg_idx].1.push(pub_inp);

                            sp.verify_proof_contribution_using_prepared_when_aggregating_snark(
                                &challenge,
                                r1cs_proof,
                                r1cs_comm_keys.get(s_idx).unwrap(),
                            )?
                        }
                        _ => {
                            return Err(ProofSystemError::ProofIncompatibleWithStatement(
                                s_idx,
                                format!("{:?}", proof),
                                format!("{:?}", s),
                            ))
                        }
                    }
                }
                Statement::PoKPSSignature(s) => match proof {
                    StatementProof::PoKPSSignature(ref p) => {
                        sig_protocol_verify!(
                            s,
                            s_idx,
                            PSSignaturePoK,
                            new,
                            p,
                            derived_ps_pk,
                            derived_ps_param,
                            PSProofContributionFailed
                        );
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckBpp(s) => match proof {
                    StatementProof::BoundCheckBpp(ref bc_proof) => {
                        let setup_params = s.get_setup_params(&proof_spec.setup_params, s_idx)?;
                        let sp = BoundCheckBppProtocol::new(s_idx, s.min, s.max, setup_params);
                        let comm_key = bound_check_bpp_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution(
                            &challenge,
                            bc_proof,
                            comm_key.as_slice(),
                            &mut transcript,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckSmc(s) => match proof {
                    StatementProof::BoundCheckSmc(ref bc_proof) => {
                        let setup_params =
                            s.get_params_and_comm_key(&proof_spec.setup_params, s_idx)?;
                        let sp = BoundCheckSmcProtocol::new(s_idx, s.min, s.max, setup_params);
                        let comm_key_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution(
                            &challenge,
                            bc_proof,
                            comm_key_slice.as_slice(),
                            derived_smc_param.get(s_idx).unwrap().clone(),
                            &mut pairing_checker,
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::BoundCheckSmcWithKVVerifier(s) => match proof {
                    StatementProof::BoundCheckSmcWithKV(ref bc_proof) => {
                        let setup_params =
                            s.get_params_and_comm_key_and_sk(&proof_spec.setup_params, s_idx)?;
                        let sp = BoundCheckSmcWithKVProtocol::new_for_verifier(
                            s_idx,
                            s.min,
                            s.max,
                            setup_params,
                        );
                        let comm_key_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution(
                            &challenge,
                            bc_proof,
                            comm_key_slice.as_slice(),
                        )?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PublicInequality(s) => match proof {
                    StatementProof::Inequality(ref iq_proof) => {
                        let comm_key = s.get_comm_key(&proof_spec.setup_params, s_idx)?;
                        let sp = InequalityProtocol::new(s_idx, s.inequal_to, comm_key);
                        let comm_key = ineq_comm.get(s_idx).unwrap();
                        sp.verify_proof_contribution(&challenge, iq_proof, comm_key.as_slice())?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::DetachedAccumulatorMembershipVerifier(_s) => (),
                Statement::DetachedAccumulatorNonMembershipVerifier(_s) => (),
                Statement::PoKBDDT16MAC(s) => match proof {
                    StatementProof::PoKOfBDDT16MAC(ref p) => {
                        let mac_params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let sp = PoKOfMACSubProtocol::new(s_idx, &s.revealed_messages, mac_params);
                        sp.verify_proof_contribution(&challenge, p).map_err(|e| {
                            ProofSystemError::BDDT16KVACProofContributionFailed(s_idx as u32, e)
                        })?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::PoKBDDT16MACFullVerifier(s) => match proof {
                    StatementProof::PoKOfBDDT16MAC(ref p) => {
                        let mac_params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let sp = PoKOfMACSubProtocol::new(s_idx, &s.revealed_messages, mac_params);
                        sp.verify_full_proof_contribution(&challenge, p, &s.secret_key)
                            .map_err(|e| {
                                ProofSystemError::BDDT16KVACProofContributionFailed(s_idx as u32, e)
                            })?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipKV(s) => match proof {
                    StatementProof::VBAccumulatorMembershipKV(ref p) => {
                        let sp =
                            VBAccumulatorMembershipKVSubProtocol::new(s_idx, s.accumulator_value);
                        sp.verify_proof_contribution(&challenge, p)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::VBAccumulatorMembershipKVFullVerifier(s) => match proof {
                    StatementProof::VBAccumulatorMembershipKV(ref p) => {
                        let sp =
                            VBAccumulatorMembershipKVSubProtocol::new(s_idx, s.accumulator_value);
                        sp.verify_full_proof_contribution(&challenge, p, &s.secret_key)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipKV(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipKV(ref p) => {
                        let sp = KBUniversalAccumulatorMembershipKVSubProtocol::new(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(&challenge, p)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorMembershipKVFullVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorMembershipKV(ref p) => {
                        let sp = KBUniversalAccumulatorMembershipKVSubProtocol::new(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.verify_full_proof_contribution(&challenge, p, &s.secret_key)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipKV(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipKV(ref p) => {
                        let sp = KBUniversalAccumulatorNonMembershipKVSubProtocol::new(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.verify_proof_contribution(&challenge, p)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                Statement::KBUniversalAccumulatorNonMembershipKVFullVerifier(s) => match proof {
                    StatementProof::KBUniversalAccumulatorNonMembershipKV(ref p) => {
                        let sp = KBUniversalAccumulatorNonMembershipKVSubProtocol::new(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.verify_full_proof_contribution(&challenge, p, &s.secret_key)?
                    }
                    _ => err_incompat_proof!(s_idx, s, proof),
                },
                _ => return Err(ProofSystemError::InvalidStatement),
            }
        }

        if aggregate_snarks {
            // The validity of `ProofSpec` ensures that statements are not being repeated

            let srs = match proof_spec.snark_aggregation_srs {
                Some(SnarkpackSRS::VerifierSrs(srs)) => srs,
                _ => return Err(ProofSystemError::SnarckpackSrsNotProvided),
            };

            if let Some(to_aggregate) = proof_spec.aggregate_groth16 {
                if let Some(aggr_proofs) = self.aggregated_groth16 {
                    expect_equality!(
                        to_aggregate.len(),
                        aggr_proofs.len(),
                        ProofSystemError::InvalidNumberOfAggregateGroth16Proofs
                    );
                    for (i, a) in aggr_proofs.into_iter().enumerate() {
                        if to_aggregate[i] != a.statements {
                            return Err(
                                ProofSystemError::NotFoundAggregateGroth16ProofForRequiredStatements(
                                    i,
                                    to_aggregate[i].clone(),
                                ),
                            );
                        }
                        let s_id = a.statements.into_iter().next().unwrap();
                        let pvk = derived_saver_vk.get(s_id).unwrap();
                        let ciphertexts = &agg_saver[i];
                        SaverProtocol::verify_ciphertext_commitments_in_batch(
                            rng,
                            ciphertexts,
                            derived_gens.get(s_id).unwrap().clone(),
                            derived_ek.get(s_id).unwrap().clone(),
                            &mut pairing_checker,
                        )?;
                        saver::saver_groth16::verify_aggregate_proof(
                            &srs,
                            pvk,
                            &a.proof,
                            ciphertexts,
                            rng,
                            &mut transcript,
                            pairing_checker.as_mut(),
                        )?;
                    }
                } else {
                    return Err(ProofSystemError::NoAggregateGroth16ProofFound);
                }
            }

            if let Some(to_aggregate) = proof_spec.aggregate_legogroth16 {
                if let Some(aggr_proofs) = self.aggregated_legogroth16 {
                    expect_equality!(
                        to_aggregate.len(),
                        aggr_proofs.len(),
                        ProofSystemError::InvalidNumberOfAggregateLegoGroth16Proofs
                    );
                    for (i, a) in aggr_proofs.into_iter().enumerate() {
                        if to_aggregate[i] != a.statements {
                            return Err(ProofSystemError::NotFoundAggregateLegoGroth16ProofForRequiredStatements(i, to_aggregate[i].clone()));
                        }
                        let s_id = a.statements.into_iter().next().unwrap();
                        let pvk = derived_lego_vk.get(s_id).unwrap();
                        legogroth16::aggregation::legogroth16::using_groth16::verify_aggregate_proof(
                            &srs,
                            pvk,
                            &agg_lego[i].1,
                            &a.proof,
                            &agg_lego[i].0,
                            rng,
                            &mut transcript,
                            pairing_checker.as_mut(),
                        )
                            .map_err(|e| ProofSystemError::LegoGroth16Error(e.into()))?
                    }
                } else {
                    return Err(ProofSystemError::NoAggregateLegoGroth16ProofFound);
                }
            }
        }

        // If randomized pairing checker was used, verify all its pairing checks
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
        responses_for_equalities: &mut [Option<&'a E::ScalarField>],
        resp: &'a E::ScalarField,
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
