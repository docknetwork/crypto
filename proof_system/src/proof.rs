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
use crate::proof_spec::ProofSpec;
use crate::statement_proof::StatementProof;
use crate::sub_protocols::accumulator::{
    AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol,
};
use crate::sub_protocols::bbs_plus::PoKBBSSigG1SubProtocol;
use crate::sub_protocols::bound_check::BoundCheckProtocol;
use crate::sub_protocols::saver::SaverProtocol;
use crate::sub_protocols::schnorr::SchnorrProtocol;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;
use saver::keygen::EncryptionKey;
use saver::setup::ChunkedCommitmentGens;
use serde::{Deserialize, Serialize};

/// Created by the prover and verified by the verifier
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<E: PairingEngine, G: AffineCurve, D: Digest>(
    pub Vec<StatementProof<E, G>>,
    pub Option<Vec<u8>>,
    PhantomData<D>,
);

impl<E: PairingEngine, G: AffineCurve, D: Digest> PartialEq for Proof<E, G, D> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
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
    ) -> Result<Self, ProofSystemError> {
        if !proof_spec.is_valid() {
            return Err(ProofSystemError::InvalidProofSpec);
        }

        // There should be a witness for each statement
        if proof_spec.statements.len() != witnesses.len() {
            return Err(ProofSystemError::UnequalWitnessAndStatementCount(
                proof_spec.statements.len(),
                witnesses.len(),
            ));
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

        // Prepare commitment keys for running Schnorr protocol
        let mut bound_check_vks = Vec::new();
        let mut bound_check_comm_keys = BTreeMap::new();
        let mut bound_check_statement_comm_key = BTreeMap::new();

        let mut saver_eks = Vec::new();
        let mut saver_ek_comm_keys = BTreeMap::new();
        let mut saver_statement_ek_comm_key = BTreeMap::new();

        let mut saver_chunked_comms = Vec::new();
        let mut saver_chunked_comm_keys = BTreeMap::new();
        let mut saver_statement_chunked_comm_key = BTreeMap::new();

        for (s_idx, statement) in proof_spec.statements.0.iter().enumerate() {
            match statement {
                Statement::BoundCheckLegoGroth16Prover(s) => {
                    let proving_key = s.get_proving_key(&proof_spec.setup_params, s_idx)?;
                    let k_idx = bound_check_vks
                        .iter()
                        .position(|v: &&legogroth16::VerifyingKey<E>| **v == proving_key.vk);
                    if let Some(k) = k_idx {
                        bound_check_statement_comm_key.insert(s_idx, k);
                    } else {
                        let comm_key = BoundCheckProtocol::schnorr_comm_key(&proving_key.vk);
                        bound_check_comm_keys.insert(bound_check_vks.len(), comm_key);
                        bound_check_statement_comm_key.insert(s_idx, bound_check_vks.len());
                        bound_check_vks.push(&proving_key.vk);
                    }
                }
                Statement::SaverProver(s) => {
                    let enc_key = s.get_encryption_key(&proof_spec.setup_params, s_idx)?;
                    let ek_idx = saver_eks
                        .iter()
                        .position(|e: &&EncryptionKey<E>| **e == *enc_key);
                    if let Some(k) = ek_idx {
                        saver_statement_ek_comm_key.insert(s_idx, k);
                    } else {
                        let comm_key = SaverProtocol::encryption_comm_key(enc_key);
                        saver_ek_comm_keys.insert(saver_eks.len(), comm_key);
                        saver_statement_ek_comm_key.insert(s_idx, saver_eks.len());
                        saver_eks.push(enc_key);
                    }

                    let comm_gens =
                        s.get_chunked_commitment_gens(&proof_spec.setup_params, s_idx)?;
                    let g_idx = saver_chunked_comms.iter().position(
                        |(b, g): &(u8, &ChunkedCommitmentGens<E::G1Affine>)| {
                            *b == s.chunk_bit_size && **g == *comm_gens
                        },
                    );
                    if let Some(k) = g_idx {
                        saver_statement_chunked_comm_key.insert(s_idx, k);
                    } else {
                        let comm_keys =
                            SaverProtocol::<E>::chunked_comm_keys(comm_gens, s.chunk_bit_size);
                        saver_chunked_comm_keys.insert(saver_chunked_comms.len(), comm_keys);
                        saver_statement_chunked_comm_key.insert(s_idx, saver_chunked_comms.len());
                        saver_chunked_comms.push((s.chunk_bit_size, comm_gens));
                    }
                }
                _ => (),
            }
        }

        let mut sub_protocols =
            Vec::<SubProtocol<E, G>>::with_capacity(proof_spec.statements.0.len());

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
                        let pk = s.get_snark_proving_key(&proof_spec.setup_params, s_idx)?;
                        let mut sp = SaverProtocol::new_for_prover(
                            s_idx,
                            s.chunk_bit_size,
                            enc_gens,
                            comm_gens,
                            enc_key,
                            pk,
                        );
                        let cc_keys = saver_chunked_comm_keys
                            .get(saver_statement_chunked_comm_key.get(&s_idx).unwrap())
                            .unwrap();
                        sp.init(
                            rng,
                            saver_ek_comm_keys
                                .get(saver_statement_ek_comm_key.get(&s_idx).unwrap())
                                .unwrap(),
                            &cc_keys.0,
                            &cc_keys.1,
                            w,
                            blinding,
                        )?;
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
                        let mut sp =
                            BoundCheckProtocol::new_for_prover(s_idx, s.min, s.max, proving_key);
                        sp.init(
                            rng,
                            bound_check_comm_keys
                                .get(bound_check_statement_comm_key.get(&s_idx).unwrap())
                                .unwrap(),
                            w,
                            blinding,
                        )?;
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
        challenge_bytes.append(&mut proof_spec.context.unwrap_or_else(Vec::new));
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
        Ok(Self(statement_proofs, nonce, PhantomData))
    }

    /// Verify the `Proof` given the `ProofSpec` and `nonce`
    pub fn verify(
        self,
        proof_spec: ProofSpec<E, G>,
        nonce: Option<Vec<u8>>,
    ) -> Result<(), ProofSystemError> {
        if !proof_spec.is_valid() {
            return Err(ProofSystemError::InvalidProofSpec);
        }

        // Number of statement proofs is less than number of statements which means some statements
        // are not satisfied.
        if proof_spec.statements.len() > self.0.len() {
            return Err(ProofSystemError::UnsatisfiedStatements(
                proof_spec.statements.len(),
                self.0.len(),
            ));
        }

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
        challenge_bytes.append(&mut proof_spec.context.unwrap_or_else(Vec::new));

        // Get challenge contribution for each statement and check if response is equal for all witnesses.
        for (s_idx, (statement, proof)) in proof_spec
            .statements
            .0
            .iter()
            .zip(self.0.iter())
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
                        let comm_gens =
                            s.get_chunked_commitment_gens(&proof_spec.setup_params, s_idx)?;
                        let enc_key = s.get_encryption_key(&proof_spec.setup_params, s_idx)?;
                        SaverProtocol::compute_challenge_contribution(
                            s.chunk_bit_size,
                            comm_gens,
                            enc_key,
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

                        let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                        BoundCheckProtocol::compute_challenge_contribution(
                            verifying_key,
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
            .into_iter()
            .zip(self.0.into_iter())
            .enumerate()
        {
            match statement {
                Statement::PoKBBSSignatureG1(s) => match proof {
                    StatementProof::PoKBBSSignatureG1(ref _p) => {
                        let sig_params = s.get_sig_params(&proof_spec.setup_params, s_idx)?;
                        let pk = s.get_public_key(&proof_spec.setup_params, s_idx)?;
                        let sp = PoKBBSSigG1SubProtocol::new(
                            s_idx,
                            &s.revealed_messages,
                            sig_params,
                            pk,
                        );
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
                Statement::AccumulatorMembership(s) => match proof {
                    StatementProof::AccumulatorMembership(ref _p) => {
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
                Statement::AccumulatorNonMembership(s) => match proof {
                    StatementProof::AccumulatorNonMembership(ref _p) => {
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
                    StatementProof::Saver(ref _p) => {
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
                Statement::BoundCheckLegoGroth16Verifier(s) => match proof {
                    StatementProof::BoundCheckLegoGroth16(ref _p) => {
                        let verifying_key = s.get_verifying_key(&proof_spec.setup_params, s_idx)?;
                        let sp = BoundCheckProtocol::new_for_verifier(
                            s_idx,
                            s.min,
                            s.max,
                            verifying_key,
                        );
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
                _ => return Err(ProofSystemError::InvalidStatement),
            }
        }
        Ok(())
    }

    pub fn statement_proof(&self, index: usize) -> Result<&StatementProof<E, G>, ProofSystemError> {
        self.statement_proofs()
            .get(index)
            .ok_or(ProofSystemError::InvalidStatementProofIndex(index))
    }

    pub fn statement_proofs(&self) -> &[StatementProof<E, G>] {
        &self.0
    }

    pub fn nonce(&self) -> &Option<Vec<u8>> {
        &self.1
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

    /// Hash bytes to a field element. This is vulnerable to timing attack and is only used input
    /// is public anyway like when generating setup parameters or challenge
    fn generate_challenge_from_bytes(bytes: &[u8]) -> E::Fr {
        field_elem_from_try_and_incr::<E::Fr, D>(bytes)
    }
}
