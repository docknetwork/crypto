use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    format,
    io::{Read, Write},
    marker::PhantomData,
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};

use crate::statement::Statement;
use crate::sub_protocols::SubProtocol;
use crate::witness::Witness;
use crate::{error::ProofSystemError, witness::Witnesses};
use digest::Digest;

use crate::meta_statement::WitnessRef;
use crate::proof::Proof;
use crate::proof_spec::ProofSpec;
use crate::statement_proof::StatementProof;
use crate::sub_protocols::accumulator::{
    AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol,
};
use crate::sub_protocols::bbs_plus::PoKBBSSigG1SubProtocol;
use crate::sub_protocols::bound_check_legogroth16::BoundCheckProtocol;
use crate::sub_protocols::r1cs_legogorth16::R1CSLegogroth16Protocol;
use crate::sub_protocols::saver::SaverProtocol;
use crate::sub_protocols::schnorr::SchnorrProtocol;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;
use saver::encryption::Ciphertext;

pub struct ProverConfig<E: PairingEngine> {
    pub reuse_groth16_proofs:
        Option<BTreeMap<usize, (E::Fr, Ciphertext<E>, ark_groth16::Proof<E>)>>,
    pub reuse_legogroth16_proofs: Option<BTreeMap<usize, (E::Fr, legogroth16::Proof<E>)>>,
}

impl<E: PairingEngine> Default for ProverConfig<E> {
    fn default() -> Self {
        Self {
            reuse_groth16_proofs: None,
            reuse_legogroth16_proofs: None,
        }
    }
}

impl<E: PairingEngine> ProverConfig<E> {
    fn get_groth16_proof(
        &mut self,
        s_id: &usize,
    ) -> Option<(E::Fr, Ciphertext<E>, ark_groth16::Proof<E>)> {
        self.reuse_groth16_proofs
            .as_mut()
            .and_then(|p| p.remove(s_id))
    }

    fn get_legogroth16_proof(&mut self, s_id: &usize) -> Option<(E::Fr, legogroth16::Proof<E>)> {
        self.reuse_legogroth16_proofs
            .as_mut()
            .and_then(|p| p.remove(s_id))
    }
}

impl<E, G, D> Proof<E, G, D>
where
    E: PairingEngine,
    G: AffineCurve<ScalarField = E::Fr>,
    D: Digest,
{
    /// Create a new proof. `nonce` is random data that needs to be hashed into the proof and
    /// it must be kept same while creating and verifying the proof. One use of `nonce` is for replay
    /// protection, here the prover might have chosen its nonce to prevent the verifier from reusing
    /// the proof as its own or the verifier might want to require the user to create fresh proof.
    pub fn new<R: RngCore>(
        rng: &mut R,
        proof_spec: ProofSpec<E, G>,
        witnesses: Witnesses<E>,
        nonce: Option<Vec<u8>>,
        mut config: ProverConfig<E>,
    ) -> Result<(Self, BTreeMap<usize, E::Fr>), ProofSystemError> {
        proof_spec.validate()?;

        // There should be a witness for each statement
        if proof_spec.statements.len() != witnesses.len() {
            return Err(ProofSystemError::UnequalWitnessAndStatementCount(
                proof_spec.statements.len(),
                witnesses.len(),
            ));
        }

        let mut aggregate_snarks =
            proof_spec.aggregate_groth16.is_some() || proof_spec.aggregate_legogroth16.is_some();
        if !aggregate_snarks {
            // TODO: Check no of groth16 and legogroth16
        }

        // Keep blinding for each witness reference that is part of an equality. This means that for
        // any 2 witnesses that are equal, same blinding will be stored. This will be drained during
        // proof creation and should be empty by the end.
        let mut blindings = BTreeMap::<WitnessRef, E::Fr>::new();

        // Prepare blindings for any witnesses that need to be proven equal.
        if !proof_spec.meta_statements.is_empty() {
            let disjoint_equalities = proof_spec.meta_statements.disjoint_witness_equalities();
            for eq_wits in disjoint_equalities {
                let blinding = E::Fr::rand(rng);
                for wr in eq_wits.0 {
                    // Duplicating the same blinding for faster search
                    blindings.insert(wr, blinding);
                }
            }
        }

        // Prepare commitment keys for running Schnorr protocols of all statements.
        let (bound_check_comm, ek_comm, chunked_comm, r1cs_comm_keys) =
            proof_spec.derive_commitment_keys()?;

        let mut sub_protocols =
            Vec::<SubProtocol<E, G>>::with_capacity(proof_spec.statements.0.len());

        let mut commitment_randomness = BTreeMap::<usize, E::Fr>::new();

        // Initialize sub-protocols for each statement
        for (s_idx, (statement, witness)) in proof_spec
            .statements
            .0
            .iter()
            .zip(witnesses.0.into_iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1(s) => match witness {
                    Witness::PoKBBSSignatureG1(w) => {
                        // Prepare blindings for this BBS+ signature proof
                        let mut blindings_map = BTreeMap::new();
                        for k in w.unrevealed_messages.keys() {
                            match blindings.remove(&(s_idx, *k)) {
                                Some(b) => blindings_map.insert(*k, b),
                                None => None,
                            };
                        }
                        let sig_params = s.get_sig_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = PoKBBSSigG1SubProtocol::new(
                            s_idx,
                            &s.revealed_messages,
                            sig_params,
                            pk,
                        );
                        sp.init(rng, blindings_map, w)?;
                        sub_protocols.push(SubProtocol::PoKBBSSignatureG1(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorMembership(s) => match witness {
                    Witness::AccumulatorMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = AccumulatorMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.init(rng, blinding, w)?;
                        sub_protocols.push(SubProtocol::AccumulatorMembership(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::AccumulatorNonMembership(s) => match witness {
                    Witness::AccumulatorNonMembership(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let params = s.get_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let prk = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = AccumulatorNonMembershipSubProtocol::new(
                            s_idx,
                            params,
                            pk,
                            prk,
                            s.accumulator_value,
                        );
                        sp.init(rng, blinding, w)?;
                        sub_protocols.push(SubProtocol::AccumulatorNonMembership(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::PedersenCommitment(s) => match witness {
                    Witness::PedersenCommitment(w) => {
                        let mut blindings_map = BTreeMap::new();
                        for i in 0..w.len() {
                            match blindings.remove(&(s_idx, i)) {
                                Some(b) => blindings_map.insert(i, b),
                                None => None,
                            };
                        }
                        let comm_key = s.get_commitment_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = SchnorrProtocol::new(s_idx, comm_key, s.commitment);
                        sp.init(rng, blindings_map, w)?;
                        sub_protocols.push(SubProtocol::PoKDiscreteLogs(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
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

                        match config.get_groth16_proof(&s_idx) {
                            Some((v, ct, proof)) => {
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

                        sub_protocols.push(SubProtocol::Saver(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::BoundCheckLegoGroth16Prover(s) => match witness {
                    Witness::BoundCheckLegoGroth16(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let proving_key = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let comm_key = bound_check_comm.get(s_idx).unwrap();

                        let mut sp =
                            BoundCheckProtocol::new_for_prover(s_idx, s.min, s.max, proving_key);

                        match config.get_legogroth16_proof(&s_idx) {
                            Some((v, proof)) => sp.init_with_old_randomness_and_proof(
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

                        sub_protocols.push(SubProtocol::BoundCheckProtocol(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
                },
                Statement::R1CSCircomProver(s) => match witness {
                    Witness::R1CSLegoGroth16(w) => {
                        let proving_key = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut blindings_map = BTreeMap::new();
                        for i in 0..proving_key.vk.commit_witness_count {
                            match blindings.remove(&(s_idx, i)) {
                                Some(b) => blindings_map.insert(i, b),
                                None => None,
                            };
                        }
                        let comm_key = r1cs_comm_keys.get(s_idx).unwrap();
                        let mut sp = R1CSLegogroth16Protocol::new_for_prover(s_idx, proving_key);

                        match config.get_legogroth16_proof(&s_idx) {
                            Some((v, proof)) => sp.init_with_old_randomness_and_proof(
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
                        sub_protocols.push(SubProtocol::R1CSLegogroth16Protocol(sp));
                    }
                    _ => {
                        return Err(ProofSystemError::WitnessIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", witness),
                            format!("{:?}", s),
                        ))
                    }
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

        // Get nonce's and context's challenge contribution
        let mut challenge_bytes = vec![];
        if let Some(n) = nonce.as_ref() {
            challenge_bytes.extend_from_slice(n)
        }
        if let Some(ctx) = &proof_spec.context {
            challenge_bytes.extend_from_slice(ctx);
        }

        // Get each sub-protocol's challenge contribution
        for p in sub_protocols.iter() {
            p.challenge_contribution(&mut challenge_bytes)?;
        }

        // Generate the challenge
        let challenge = Self::generate_challenge_from_bytes(&challenge_bytes);

        // Get each sub-protocol's proof
        let mut statement_proofs = Vec::with_capacity(sub_protocols.len());
        for mut p in sub_protocols {
            statement_proofs.push(p.gen_proof_contribution(&challenge)?);
        }
        Ok((
            Self {
                statement_proofs,
                nonce,
                aggregated_groth16: None,
                aggregated_legogroth16: None,
                _phantom: PhantomData,
            },
            commitment_randomness,
        ))
    }

    pub fn statement_proof(&self, index: usize) -> Result<&StatementProof<E, G>, ProofSystemError> {
        self.statement_proofs()
            .get(index)
            .ok_or(ProofSystemError::InvalidStatementProofIndex(index))
    }

    pub fn statement_proofs(&self) -> &[StatementProof<E, G>] {
        &self.statement_proofs
    }

    pub fn nonce(&self) -> &Option<Vec<u8>> {
        &self.nonce
    }

    /// Hash bytes to a field element. This is vulnerable to timing attack and is only used input
    /// is public anyway like when generating setup parameters or challenge
    pub fn generate_challenge_from_bytes(bytes: &[u8]) -> E::Fr {
        field_elem_from_try_and_incr::<E::Fr, D>(bytes)
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
}
