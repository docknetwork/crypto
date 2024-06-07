//! Code for the prover to generate a `Proof`

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, format, rand::RngCore, vec, vec::Vec, UniformRand};

use crate::{
    error::ProofSystemError,
    statement::Statement,
    sub_protocols::{ps_signature::PSSignaturePoK, SubProtocol},
    witness::{Witness, Witnesses},
};
use digest::Digest;
use legogroth16::aggregation::srs::PreparedProverSRS;

use crate::{
    constants::{
        BBS_23_LABEL, BBS_PLUS_LABEL, BDDT16_KVAC_LABEL, COMPOSITE_PROOF_CHALLENGE_LABEL,
        COMPOSITE_PROOF_LABEL, CONTEXT_LABEL, KB_POS_ACCUM_CDH_MEM_LABEL, KB_POS_ACCUM_MEM_LABEL,
        KB_UNI_ACCUM_CDH_MEM_LABEL, KB_UNI_ACCUM_CDH_NON_MEM_LABEL, KB_UNI_ACCUM_MEM_LABEL,
        KB_UNI_ACCUM_NON_MEM_LABEL, NONCE_LABEL, PS_LABEL, VB_ACCUM_CDH_MEM_LABEL,
        VB_ACCUM_CDH_NON_MEM_LABEL, VB_ACCUM_MEM_LABEL, VB_ACCUM_NON_MEM_LABEL,
    },
    meta_statement::WitnessRef,
    prelude::SnarkpackSRS,
    proof::{AggregatedGroth16, Proof},
    proof_spec::ProofSpec,
    statement_proof::StatementProof,
    sub_protocols::{
        accumulator::{
            cdh::{
                KBPositiveAccumulatorMembershipCDHSubProtocol,
                KBUniversalAccumulatorMembershipCDHSubProtocol,
                KBUniversalAccumulatorNonMembershipCDHSubProtocol,
                VBAccumulatorMembershipCDHSubProtocol, VBAccumulatorNonMembershipCDHSubProtocol,
            },
            detached::{
                DetachedAccumulatorMembershipSubProtocol,
                DetachedAccumulatorNonMembershipSubProtocol,
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
        bbs_23::PoKBBSSigG1SubProtocol,
        bbs_23_ietf::PoKBBSSigIETFG1SubProtocol,
        bbs_plus::PoKBBSSigG1SubProtocol as PoKBBSPlusSigG1SubProtocol,
        bddt16_kvac::PoKOfMACSubProtocol,
        bound_check_bpp::BoundCheckBppProtocol,
        bound_check_legogroth16::BoundCheckLegoGrothProtocol,
        bound_check_smc::BoundCheckSmcProtocol,
        bound_check_smc_with_kv::BoundCheckSmcWithKVProtocol,
        inequality::InequalityProtocol,
        r1cs_legogorth16::R1CSLegogroth16Protocol,
        saver::SaverProtocol,
        schnorr::SchnorrProtocol,
    },
};
use dock_crypto_utils::{
    expect_equality,
    hashing_utils::field_elem_from_try_and_incr,
    transcript::{MerlinTranscript, Transcript},
};
use saver::encryption::Ciphertext;

/// The SAVER randomness, ciphertext and proof to reuse when creating the composite proof. This is more
/// efficient than generating a new ciphertext and proof.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct OldSaverProof<E: Pairing>(
    pub E::ScalarField,
    pub Ciphertext<E>,
    pub ark_groth16::Proof<E>,
);
/// The LegoGroth16 randomness and proof to reuse when creating the composite proof. This is more
/// efficient than generating a new proof.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct OldLegoGroth16Proof<E: Pairing>(pub E::ScalarField, pub legogroth16::Proof<E>);

/// Passed to the prover during proof creation
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverConfig<E: Pairing> {
    pub reuse_saver_proofs: Option<BTreeMap<usize, OldSaverProof<E>>>,
    pub reuse_legogroth16_proofs: Option<BTreeMap<usize, OldLegoGroth16Proof<E>>>,
}

impl<E: Pairing> Default for ProverConfig<E> {
    fn default() -> Self {
        Self {
            reuse_saver_proofs: None,
            reuse_legogroth16_proofs: None,
        }
    }
}

impl<E: Pairing> ProverConfig<E> {
    /// Get SAVER randomness, ciphertext and proof to reuse for the given statement id
    fn get_saver_proof(&mut self, statement_id: &usize) -> Option<OldSaverProof<E>> {
        self.reuse_saver_proofs
            .as_mut()
            .and_then(|p| p.remove(statement_id))
    }

    /// Get LegoGroth16 randomness and proof to reuse for the given statement id
    fn get_legogroth16_proof(&mut self, statement_id: &usize) -> Option<OldLegoGroth16Proof<E>> {
        self.reuse_legogroth16_proofs
            .as_mut()
            .and_then(|p| p.remove(statement_id))
    }
}

macro_rules! err_incompat_witness {
    ($s_idx:ident, $s: ident, $witness: ident) => {
        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
            $s_idx,
            format!("{:?}", $witness),
            format!("{:?}", $s),
        ))
    };
}

impl<E: Pairing> Proof<E> {
    /// Create a new proof. `nonce` is random data that needs to be hashed into the proof and
    /// it must be kept same while creating and verifying the proof. One use of `nonce` is for replay
    /// protection, here the prover might have chosen its nonce to prevent the verifier from reusing
    /// the proof as its own or the verifier might want to require the user to create fresh proof.
    /// Also returns the randomness used by statements using SAVER and LegoGroth16 proofs which can
    /// then be used as helpers in subsequent proof creations where these proofs are reused than
    /// creating fresh proofs.
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        proof_spec: ProofSpec<E>,
        witnesses: Witnesses<E>,
        nonce: Option<Vec<u8>>,
        mut config: ProverConfig<E>,
    ) -> Result<(Self, BTreeMap<usize, E::ScalarField>), ProofSystemError> {
        proof_spec.validate()?;

        // There should be a witness for each statement
        expect_equality!(
            proof_spec.statements.len(),
            witnesses.len(),
            ProofSystemError::UnequalWitnessAndStatementCount
        );

        // Keep blinding for each witness reference that is part of an equality. This means that for
        // any 2 witnesses that are equal, same blinding will be stored. This will be drained during
        // proof creation and should be empty by the end.
        let mut blindings = BTreeMap::<WitnessRef, E::ScalarField>::new();

        // Prepare blindings for any witnesses that need to be proven equal.
        if !proof_spec.meta_statements.is_empty() {
            let disjoint_equalities = proof_spec.meta_statements.disjoint_witness_equalities();
            for eq_wits in disjoint_equalities {
                let blinding = E::ScalarField::rand(rng);
                for wr in eq_wits.0 {
                    // Duplicating the same blinding for faster search
                    blindings.insert(wr, blinding);
                }
            }
        }

        // Prepare commitment keys for running Schnorr protocols of all statements.
        let (
            bound_check_lego_comm,
            ek_comm,
            chunked_comm,
            r1cs_comm_keys,
            bound_check_bpp_comm,
            bound_check_smc_comm,
            ineq_comm,
        ) = proof_spec.derive_commitment_keys()?;

        let mut sub_protocols = Vec::<SubProtocol<E>>::with_capacity(proof_spec.statements.0.len());

        // Randomness used by SAVER and LegoGroth16 proofs. This is tracked and returned so subsequent proofs for
        // the same public params and witness can reuse this randomness
        let mut commitment_randomness = BTreeMap::<usize, E::ScalarField>::new();

        let mut transcript = MerlinTranscript::new(COMPOSITE_PROOF_LABEL);
        if let Some(n) = nonce.as_ref() {
            transcript.append_message(NONCE_LABEL, n);
        }
        if let Some(ctx) = &proof_spec.context {
            transcript.append_message(CONTEXT_LABEL, ctx);
        }

        macro_rules! accum_protocol_init {
            ($s: ident, $s_idx: ident, $w: ident, $protocol: ident, $protocol_variant: ident, $label: ident) => {{
                let blinding = blindings.remove(&($s_idx, 0));
                let params = $s.get_params(&proof_spec.setup_params, $s_idx)?;
                let pk = $s.get_public_key(&proof_spec.setup_params, $s_idx)?;
                let prk = $s.get_proving_key(&proof_spec.setup_params, $s_idx)?;
                let mut sp = $protocol::new($s_idx, params, pk, prk, $s.accumulator_value);
                sp.init(rng, blinding, $w)?;
                transcript.set_label($label);
                sp.challenge_contribution(&mut transcript)?;
                sub_protocols.push(SubProtocol::$protocol_variant(sp));
            }};
        }

        macro_rules! sig_protocol_init {
            ($s: ident, $s_idx: ident, $w: ident, $protocol: ident, $func_name: ident, $protocol_variant: ident, $label: ident) => {{
                // Prepare blindings for this signature proof
                let blindings_map = build_blindings_map::<E>(
                    &mut blindings,
                    $s_idx,
                    $w.unrevealed_messages.keys().cloned(),
                );
                let sig_params = $s.get_params(&proof_spec.setup_params, $s_idx)?;
                let mut sp = $protocol::$func_name($s_idx, &$s.revealed_messages, sig_params);
                sp.init(rng, blindings_map, $w)?;
                transcript.set_label($label);
                sp.challenge_contribution(&mut transcript)?;
                sub_protocols.push(SubProtocol::$protocol_variant(sp));
            }};
        }

        macro_rules! ped_comm_protocol_init {
            ($s: ident, $s_idx: ident, $w: ident, $cm_key_func: ident, $protocol_variant: ident) => {{
                let blindings_map = build_blindings_map::<E>(&mut blindings, $s_idx, 0..$w.len());
                let comm_key = $s.$cm_key_func(&proof_spec.setup_params, $s_idx)?;
                let mut sp = SchnorrProtocol::new($s_idx, comm_key, $s.commitment);
                sp.init(rng, blindings_map, $w)?;
                sp.challenge_contribution(&mut transcript)?;
                sub_protocols.push(SubProtocol::$protocol_variant(sp));
            }};
        }

        macro_rules! accum_kv_protocol_init {
            ($s: ident, $s_idx: ident, $w: ident, $protocol: ident, $protocol_variant: ident, $label: ident) => {{
                let blinding = blindings.remove(&($s_idx, 0));
                let mut sp = $protocol::new($s_idx, $s.accumulator_value);
                sp.init(rng, blinding, $w)?;
                transcript.set_label($label);
                sp.challenge_contribution(&mut transcript)?;
                sub_protocols.push(SubProtocol::$protocol_variant(sp));
            }};
        }

        fn build_blindings_map<E: Pairing>(
            blindings: &mut BTreeMap<WitnessRef, E::ScalarField>,
            s_idx: usize,
            wit_idx: impl Iterator<Item = usize>,
        ) -> BTreeMap<usize, E::ScalarField> {
            let mut blindings_map = BTreeMap::new();
            for k in wit_idx {
                match blindings.remove(&(s_idx, k)) {
                    Some(b) => blindings_map.insert(k, b),
                    None => None,
                };
            }
            blindings_map
        }

        // Initialize sub-protocols for each statement
        for (s_idx, (statement, witness)) in proof_spec
            .statements
            .0
            .iter()
            .zip(witnesses.0.into_iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1Prover(s) => match witness {
                    Witness::PoKBBSSignatureG1(w) => {
                        sig_protocol_init!(
                            s,
                            s_idx,
                            w,
                            PoKBBSPlusSigG1SubProtocol,
                            new_for_prover,
                            PoKBBSSignatureG1,
                            BBS_PLUS_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PoKBBSSignature23G1Prover(s) => match witness {
                    Witness::PoKBBSSignature23G1(w) => {
                        sig_protocol_init!(
                            s,
                            s_idx,
                            w,
                            PoKBBSSigG1SubProtocol,
                            new_for_prover,
                            PoKBBSSignature23G1,
                            BBS_23_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PoKBBSSignature23IETFG1Prover(s) => match witness {
                    Witness::PoKBBSSignature23G1(w) => {
                        sig_protocol_init!(
                            s,
                            s_idx,
                            w,
                            PoKBBSSigIETFG1SubProtocol,
                            new_for_prover,
                            PoKBBSSignature23IETFG1,
                            BBS_23_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::VBAccumulatorMembership(s) => match witness {
                    Witness::VBAccumulatorMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            VBAccumulatorMembershipSubProtocol,
                            VBAccumulatorMembership,
                            VB_ACCUM_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::VBAccumulatorNonMembership(s) => match witness {
                    Witness::VBAccumulatorNonMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            VBAccumulatorNonMembershipSubProtocol,
                            VBAccumulatorNonMembership,
                            VB_ACCUM_NON_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorMembership(s) => match witness {
                    Witness::KBUniAccumulatorMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBUniversalAccumulatorMembershipSubProtocol,
                            KBUniversalAccumulatorMembership,
                            KB_UNI_ACCUM_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorNonMembership(s) => match witness {
                    Witness::KBUniAccumulatorNonMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBUniversalAccumulatorNonMembershipSubProtocol,
                            KBUniversalAccumulatorNonMembership,
                            KB_UNI_ACCUM_NON_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::VBAccumulatorMembershipCDHProver(s) => match witness {
                    Witness::VBAccumulatorMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let mut sp = VBAccumulatorMembershipCDHSubProtocol::new_for_prover(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.init(rng, blinding, w)?;
                        transcript.set_label(VB_ACCUM_CDH_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::VBAccumulatorMembershipCDH(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::VBAccumulatorNonMembershipCDHProver(s) => match witness {
                    Witness::VBAccumulatorNonMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let mut sp = VBAccumulatorNonMembershipCDHSubProtocol::new_for_prover(
                            s_idx,
                            s.accumulator_value,
                            s.Q,
                            params,
                        );
                        sp.init(rng, blinding, w)?;
                        transcript.set_label(VB_ACCUM_CDH_NON_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::VBAccumulatorNonMembershipCDH(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorMembershipCDHProver(s) => match witness {
                    Witness::KBUniAccumulatorMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let mut sp = KBUniversalAccumulatorMembershipCDHSubProtocol::new_for_prover(
                            s_idx,
                            s.accumulator_value,
                        );
                        sp.init(rng, blinding, w)?;
                        transcript.set_label(KB_UNI_ACCUM_CDH_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::KBUniversalAccumulatorMembershipCDH(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorNonMembershipCDHProver(s) => match witness {
                    Witness::KBUniAccumulatorNonMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let mut sp =
                            KBUniversalAccumulatorNonMembershipCDHSubProtocol::new_for_prover(
                                s_idx,
                                s.accumulator_value,
                            );
                        sp.init(rng, blinding, w)?;
                        transcript.set_label(KB_UNI_ACCUM_CDH_NON_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::KBUniversalAccumulatorNonMembershipCDH(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBPositiveAccumulatorMembership(s) => match witness {
                    Witness::KBPosAccumulatorMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBPositiveAccumulatorMembershipSubProtocol,
                            KBPositiveAccumulatorMembership,
                            KB_POS_ACCUM_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBPositiveAccumulatorMembershipCDH(s) => match witness {
                    Witness::KBPosAccumulatorMembership(w) => {
                        accum_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBPositiveAccumulatorMembershipCDHSubProtocol,
                            KBPositiveAccumulatorMembershipCDH,
                            KB_POS_ACCUM_CDH_MEM_LABEL
                        )
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PedersenCommitment(s) => match witness {
                    Witness::PedersenCommitment(w) => {
                        ped_comm_protocol_init!(s, s_idx, w, get_commitment_key, PoKDiscreteLogs);
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PedersenCommitmentG2(s) => match witness {
                    Witness::PedersenCommitment(w) => {
                        ped_comm_protocol_init!(
                            s,
                            s_idx,
                            w,
                            get_commitment_key_g2,
                            PoKDiscreteLogsG2
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::SaverProver(s) => match witness {
                    Witness::Saver(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let enc_gens = s.get_encryption_gens(&proof_spec.setup_params, s_idx)?;
                        let comm_gens =
                            s.get_chunked_commitment_gens(&proof_spec.setup_params, s_idx)?;
                        let enc_key = s.get_encryption_key(&proof_spec.setup_params, s_idx)?;
                        let cc_keys = chunked_comm.get(s_idx).unwrap();
                        let ck_comm_ct = ek_comm.get(s_idx).unwrap();
                        let pk = s.get_snark_proving_key(&proof_spec.setup_params, s_idx)?;

                        let mut sp = SaverProtocol::new_for_prover(
                            s_idx,
                            s.chunk_bit_size,
                            enc_gens,
                            comm_gens,
                            enc_key,
                            pk,
                        );

                        match config.get_saver_proof(&s_idx) {
                            // Found a proof to reuse.
                            Some(OldSaverProof(v, ct, proof)) => {
                                sp.init_with_ciphertext_and_proof(
                                    rng, ck_comm_ct, &cc_keys.0, &cc_keys.1, w, blinding, v, ct,
                                    proof,
                                )?;
                            }
                            None => {
                                sp.init(rng, ck_comm_ct, &cc_keys.0, &cc_keys.1, w, blinding)?;
                            }
                        }
                        commitment_randomness.insert(
                            s_idx,
                            *sp.sp_ciphertext
                                .as_ref()
                                .unwrap()
                                .witnesses
                                .as_ref()
                                .unwrap()
                                .last()
                                .unwrap(),
                        );

                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::Saver(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::BoundCheckLegoGroth16Prover(s) => match witness {
                    Witness::BoundCheckLegoGroth16(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let proving_key = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let comm_key = bound_check_lego_comm.get(s_idx).unwrap();

                        let mut sp = BoundCheckLegoGrothProtocol::new_for_prover(
                            s_idx,
                            s.min,
                            s.max,
                            proving_key,
                        );

                        match config.get_legogroth16_proof(&s_idx) {
                            // Found a proof to reuse.
                            Some(OldLegoGroth16Proof(v, proof)) => sp
                                .init_with_old_randomness_and_proof(
                                    rng, comm_key, w, blinding, v, proof,
                                )?,
                            None => sp.init(rng, comm_key, w, blinding)?,
                        }

                        commitment_randomness.insert(
                            s_idx,
                            *sp.sp
                                .as_ref()
                                .unwrap()
                                .witnesses
                                .as_ref()
                                .unwrap()
                                .last()
                                .unwrap(),
                        );

                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::BoundCheckLegoGroth16(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::R1CSCircomProver(s) => match witness {
                    Witness::R1CSLegoGroth16(w) => {
                        let proving_key = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut blindings_map = BTreeMap::new();
                        for i in 0..proving_key.vk.commit_witness_count as usize {
                            match blindings.remove(&(s_idx, i)) {
                                Some(b) => blindings_map.insert(i, b),
                                None => None,
                            };
                        }
                        let comm_key = r1cs_comm_keys.get(s_idx).unwrap();
                        let mut sp = R1CSLegogroth16Protocol::new_for_prover(s_idx, proving_key);

                        match config.get_legogroth16_proof(&s_idx) {
                            Some(OldLegoGroth16Proof(v, proof)) => sp
                                .init_with_old_randomness_and_proof(
                                    rng,
                                    comm_key,
                                    w,
                                    blindings_map,
                                    v,
                                    proof,
                                )?,
                            None => {
                                let r1cs = s.get_r1cs(&proof_spec.setup_params, s_idx)?;
                                let wasm_bytes =
                                    s.get_wasm_bytes(&proof_spec.setup_params, s_idx)?;
                                sp.init(rng, r1cs.clone(), wasm_bytes, comm_key, w, blindings_map)?
                            }
                        }

                        commitment_randomness.insert(
                            s_idx,
                            *sp.sp
                                .as_ref()
                                .unwrap()
                                .witnesses
                                .as_ref()
                                .unwrap()
                                .last()
                                .unwrap(),
                        );

                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::R1CSLegogroth16Protocol(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PoKPSSignature(s) => match witness {
                    Witness::PoKPSSignature(w) => {
                        // Prepare blindings for this PS sig proof
                        let blindings_map = build_blindings_map::<E>(
                            &mut blindings,
                            s_idx,
                            w.unrevealed_messages.keys().cloned(),
                        );
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = PSSignaturePoK::new(s_idx, &s.revealed_messages, params, pk);
                        sp.init::<R>(rng, blindings_map, w)?;
                        transcript.set_label(PS_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::PSSignaturePoK(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::BoundCheckBpp(s) => match witness {
                    Witness::BoundCheckBpp(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let bpp_setup_params =
                            s.get_setup_params(&proof_spec.setup_params, s_idx)?;
                        let comm_key = bound_check_bpp_comm.get(s_idx).unwrap();
                        let mut sp =
                            BoundCheckBppProtocol::new(s_idx, s.min, s.max, bpp_setup_params);
                        sp.init(rng, comm_key.as_slice(), w, blinding)?;
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::BoundCheckBpp(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::BoundCheckSmc(s) => match witness {
                    Witness::BoundCheckSmc(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params_comm_key =
                            s.get_params_and_comm_key(&proof_spec.setup_params, s_idx)?;
                        let comm_key_as_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        let mut sp =
                            BoundCheckSmcProtocol::new(s_idx, s.min, s.max, params_comm_key);
                        sp.init(rng, comm_key_as_slice, w, blinding)?;
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::BoundCheckSmc(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::BoundCheckSmcWithKVProver(s) => match witness {
                    Witness::BoundCheckSmcWithKV(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params_comm_key =
                            s.get_params_and_comm_key(&proof_spec.setup_params, s_idx)?;
                        let comm_key_as_slice = bound_check_smc_comm.get(s_idx).unwrap();
                        let mut sp = BoundCheckSmcWithKVProtocol::new_for_prover(
                            s_idx,
                            s.min,
                            s.max,
                            params_comm_key,
                        );
                        sp.init(rng, comm_key_as_slice, w, blinding)?;
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::BoundCheckSmcWithKV(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PublicInequality(s) => match witness {
                    Witness::PublicInequality(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let comm_key = s.get_comm_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp =
                            InequalityProtocol::new(s_idx, s.inequal_to.clone(), &comm_key);
                        sp.init(rng, ineq_comm.get(s_idx).unwrap().as_slice(), w, blinding)?;
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::Inequality(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::DetachedAccumulatorMembershipProver(s) => match witness {
                    Witness::VBAccumulatorMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp =
                            DetachedAccumulatorMembershipSubProtocol::new(s_idx, params, pk, prk);
                        sp.init(rng, s.accumulator_value, blinding, w)?;
                        transcript.set_label(VB_ACCUM_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::DetachedAccumulatorMembership(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::DetachedAccumulatorNonMembershipProver(s) => match witness {
                    Witness::VBAccumulatorNonMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = DetachedAccumulatorNonMembershipSubProtocol::new(
                            s_idx, params, pk, prk,
                        );
                        sp.init(rng, s.accumulator_value, blinding, w)?;
                        transcript.set_label(VB_ACCUM_NON_MEM_LABEL);
                        sp.challenge_contribution(&mut transcript)?;
                        sub_protocols.push(SubProtocol::DetachedAccumulatorNonMembership(sp));
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::PoKBDDT16MAC(s) => match witness {
                    Witness::PoKOfBDDT16MAC(w) => {
                        sig_protocol_init!(
                            s,
                            s_idx,
                            w,
                            PoKOfMACSubProtocol,
                            new,
                            PoKOfBDDT16MAC,
                            BDDT16_KVAC_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::VBAccumulatorMembershipKV(s) => match witness {
                    Witness::VBAccumulatorMembership(w) => {
                        accum_kv_protocol_init!(
                            s,
                            s_idx,
                            w,
                            VBAccumulatorMembershipKVSubProtocol,
                            VBAccumulatorMembershipKV,
                            VB_ACCUM_MEM_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorMembershipKV(s) => match witness {
                    Witness::KBUniAccumulatorMembership(w) => {
                        accum_kv_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBUniversalAccumulatorMembershipKVSubProtocol,
                            KBUniversalAccumulatorMembershipKV,
                            KB_UNI_ACCUM_MEM_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                Statement::KBUniversalAccumulatorNonMembershipKV(s) => match witness {
                    Witness::KBUniAccumulatorNonMembership(w) => {
                        accum_kv_protocol_init!(
                            s,
                            s_idx,
                            w,
                            KBUniversalAccumulatorNonMembershipKVSubProtocol,
                            KBUniversalAccumulatorNonMembershipKV,
                            KB_UNI_ACCUM_NON_MEM_LABEL
                        );
                    }
                    _ => err_incompat_witness!(s_idx, s, witness),
                },
                _ => return Err(ProofSystemError::InvalidStatement),
            }
        }

        // If all blindings are not consumed, it means that there was some witness equality which was
        // incorrect like either statement index was wrong or witness index for certain statement was wrong.
        if !blindings.is_empty() {
            return Err(ProofSystemError::InvalidWitnessEqualities(
                blindings.keys().cloned().collect::<Vec<_>>(),
            ));
        }

        // Generate the challenge
        let challenge = transcript.challenge_scalar(COMPOSITE_PROOF_CHALLENGE_LABEL);

        // Get each sub-protocol's proof
        let mut statement_proofs = Vec::with_capacity(sub_protocols.len());
        for p in sub_protocols {
            statement_proofs.push(match p {
                SubProtocol::PoKBBSSignatureG1(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::VBAccumulatorMembership(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::VBAccumulatorNonMembership(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::PoKDiscreteLogs(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::PoKDiscreteLogsG2(mut sp) => {
                    sp.gen_proof_contribution_g2(&challenge)?
                }
                SubProtocol::Saver(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::BoundCheckLegoGroth16(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::R1CSLegogroth16Protocol(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::PSSignaturePoK(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::PoKBBSSignature23G1(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::PoKBBSSignature23IETFG1(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::BoundCheckBpp(mut sp) => {
                    sp.gen_proof_contribution(rng, &challenge, &mut transcript)?
                }
                SubProtocol::BoundCheckSmc(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::BoundCheckSmcWithKV(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::Inequality(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::DetachedAccumulatorMembership(mut sp) => {
                    sp.gen_proof_contribution(rng, &challenge)?
                }
                SubProtocol::DetachedAccumulatorNonMembership(mut sp) => {
                    sp.gen_proof_contribution(rng, &challenge)?
                }
                SubProtocol::KBUniversalAccumulatorMembership(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBUniversalAccumulatorNonMembership(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::VBAccumulatorMembershipCDH(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::VBAccumulatorNonMembershipCDH(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBUniversalAccumulatorMembershipCDH(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBUniversalAccumulatorNonMembershipCDH(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBPositiveAccumulatorMembership(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBPositiveAccumulatorMembershipCDH(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::PoKOfBDDT16MAC(mut sp) => sp.gen_proof_contribution(&challenge)?,
                SubProtocol::VBAccumulatorMembershipKV(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBUniversalAccumulatorMembershipKV(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
                SubProtocol::KBUniversalAccumulatorNonMembershipKV(mut sp) => {
                    sp.gen_proof_contribution(&challenge)?
                }
            });
        }

        // TODO: Revisit - aggregating after challenge generation, is this correct?

        let mut aggregated_groth16 = vec![];
        let mut aggregated_legogroth16 = vec![];

        let aggregate_snarks =
            proof_spec.aggregate_groth16.is_some() || proof_spec.aggregate_legogroth16.is_some();
        if !aggregate_snarks {
            // TODO: Check no of groth16 and legogroth16
        }
        if aggregate_snarks {
            // The validity of `ProofSpec` ensures that statements are not being repeated

            let srs = match proof_spec.snark_aggregation_srs {
                Some(SnarkpackSRS::ProverSrs(srs)) => srs,
                _ => return Err(ProofSystemError::SnarckpackSrsNotProvided),
            };
            let prepared_srs = PreparedProverSRS::from(srs);

            if proof_spec.aggregate_groth16.is_some() {
                let to_aggr = proof_spec.aggregate_groth16.unwrap();
                let mut proofs = vec![];
                for a in to_aggr {
                    for i in &a {
                        let p = match statement_proofs.get(*i).unwrap() {
                            StatementProof::Saver(s) => &s.snark_proof,
                            _ => return Err(ProofSystemError::NotASaverStatementProof),
                        };
                        proofs.push(p.clone());
                    }
                    let ag_proof = legogroth16::aggregation::groth16::aggregate_proofs(
                        prepared_srs.clone(),
                        &mut transcript,
                        &proofs,
                    )
                    .map_err(|e| ProofSystemError::LegoGroth16Error(e.into()))?;
                    aggregated_groth16.push(AggregatedGroth16 {
                        proof: ag_proof,
                        statements: a,
                    });
                }
            }

            if proof_spec.aggregate_legogroth16.is_some() {
                let to_aggr = proof_spec.aggregate_legogroth16.unwrap();
                let mut proofs = vec![];
                for a in to_aggr {
                    for i in &a {
                        let p = match statement_proofs.get(*i).unwrap() {
                            StatementProof::BoundCheckLegoGroth16(s) => &s.snark_proof,
                            StatementProof::R1CSLegoGroth16(s) => &s.snark_proof,
                            _ => return Err(ProofSystemError::NotASaverStatementProof),
                        };
                        proofs.push(p.clone());
                    }
                    let (ag_proof, _) =
                        legogroth16::aggregation::legogroth16::using_groth16::aggregate_proofs(
                            prepared_srs.clone(),
                            &mut transcript,
                            &proofs,
                        )
                        .map_err(|e| ProofSystemError::LegoGroth16Error(e.into()))?;
                    aggregated_legogroth16.push(AggregatedGroth16 {
                        proof: ag_proof,
                        statements: a,
                    });
                }
            }
        }

        Ok((
            Self {
                statement_proofs,
                aggregated_groth16: if !aggregated_groth16.is_empty() {
                    Some(aggregated_groth16)
                } else {
                    None
                },
                aggregated_legogroth16: if !aggregated_legogroth16.is_empty() {
                    Some(aggregated_legogroth16)
                } else {
                    None
                },
            },
            commitment_randomness,
        ))
    }

    pub fn statement_proof(&self, index: usize) -> Result<&StatementProof<E>, ProofSystemError> {
        self.statement_proofs()
            .get(index)
            .ok_or(ProofSystemError::InvalidStatementProofIndex(index))
    }

    pub fn statement_proofs(&self) -> &[StatementProof<E>] {
        &self.statement_proofs
    }

    /// Hash bytes to a field element. This is vulnerable to timing attack and is only used when input
    /// is public anyway like when generating setup parameters or challenge
    pub fn generate_challenge_from_bytes<D: Digest>(bytes: &[u8]) -> E::ScalarField {
        field_elem_from_try_and_incr::<E::ScalarField, D>(bytes)
    }

    pub fn get_saver_ciphertext_and_proof(
        &self,
        index: usize,
    ) -> Result<(&Ciphertext<E>, &ark_groth16::Proof<E>), ProofSystemError> {
        let st = self.statement_proof(index)?;
        if let StatementProof::Saver(s) = st {
            Ok((&s.ciphertext, &s.snark_proof))
        } else {
            Err(ProofSystemError::NotASaverStatementProof)
        }
    }

    pub fn get_legogroth16_proof(
        &self,
        index: usize,
    ) -> Result<&legogroth16::Proof<E>, ProofSystemError> {
        let st = self.statement_proof(index)?;
        match st {
            StatementProof::BoundCheckLegoGroth16(s) => Ok(&s.snark_proof),
            StatementProof::R1CSLegoGroth16(s) => Ok(&s.snark_proof),
            _ => Err(ProofSystemError::NotASaverStatementProof),
        }
    }

    pub fn for_aggregate(&self) -> Self {
        let mut statement_proofs = vec![];
        for sp in self.statement_proofs() {
            match sp {
                StatementProof::Saver(sp) => statement_proofs
                    .push(StatementProof::SaverWithAggregation(sp.for_aggregation())),
                StatementProof::BoundCheckLegoGroth16(b) => statement_proofs.push(
                    StatementProof::BoundCheckLegoGroth16WithAggregation(b.for_aggregation()),
                ),
                StatementProof::R1CSLegoGroth16(b) => statement_proofs.push(
                    StatementProof::R1CSLegoGroth16WithAggregation(b.for_aggregation()),
                ),
                _ => statement_proofs.push(sp.clone()),
            }
        }
        Self {
            statement_proofs,
            aggregated_groth16: self.aggregated_groth16.clone(),
            aggregated_legogroth16: self.aggregated_legogroth16.clone(),
        }
    }
}
