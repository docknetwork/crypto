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
};

use crate::statement::Statement;
use crate::sub_protocols::SubProtocol;
use crate::witness::Witness;
use crate::{error::ProofSystemError, witness::Witnesses};
use ark_ff::{PrimeField, SquareRootField};
use digest::Digest;

use crate::meta_statement::WitnessRef;
use crate::proof_spec::ProofSpec;
use crate::statement_proof::StatementProof;
use crate::sub_protocols::accumulator::{
    AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol,
};
use crate::sub_protocols::bbs_plus::PoKBBSSigG1SubProtocol;
use crate::sub_protocols::saver::SaverProtocol;
use crate::sub_protocols::schnorr::SchnorrProtocol;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;
use serde::{Deserialize, Serialize};
pub use serialization::*;

/// Created by the prover and verified by the verifier
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<E: PairingEngine, G: AffineCurve, F: PrimeField + SquareRootField, D: Digest>(
    pub Vec<StatementProof<E, G>>,
    pub Option<Vec<u8>>,
    PhantomData<F>,
    PhantomData<D>,
);

impl<E: PairingEngine, G: AffineCurve, F: PrimeField + SquareRootField, D: Digest> PartialEq
    for Proof<E, G, F, D>
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<E, G, F, D> Proof<E, G, F, D>
where
    E: PairingEngine<Fr = F>,
    G: AffineCurve<ScalarField = F>,
    F: PrimeField + SquareRootField,
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
        let mut blindings = BTreeMap::<WitnessRef, F>::new();

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

        let mut sub_protocols: Vec<SubProtocol<E, G>> = vec![];

        // Initialize sub-protocols for each statement
        for (s_idx, (statement, witness)) in proof_spec
            .statements
            .0
            .into_iter()
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
                        let mut sp = PoKBBSSigG1SubProtocol::new(s_idx, s);
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
                        let mut sp = AccumulatorMembershipSubProtocol::new(s_idx, s);
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
                        let mut sp = AccumulatorNonMembershipSubProtocol::new(s_idx, s);
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
                        let mut sp = SchnorrProtocol::new(s_idx, s);
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
                Statement::Saver(s) => match witness {
                    Witness::Saver(w) => {
                        let blinding = blindings.remove(&(s_idx, 0));
                        let mut sp = SaverProtocol::new(s_idx, s);
                        sp.init(rng, w, blinding)?;
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
        Ok(Self(statement_proofs, nonce, PhantomData, PhantomData))
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
                        // Check witness equalities for this statement.
                        for i in 0..s.params.supported_message_count() {
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
                            &s.params,
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
                        p.challenge_contribution(
                            &s.accumulator_value,
                            &s.public_key,
                            &s.params,
                            &s.proving_key,
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
                        p.challenge_contribution(
                            &s.accumulator_value,
                            &s.public_key,
                            &s.params,
                            &s.proving_key,
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
                        for i in 0..s.bases.len() {
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
                            &s.bases,
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
                Statement::Saver(s) => match proof {
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

                        SaverProtocol::compute_challenge_contribution(s, &p, &mut challenge_bytes)?;
                    }
                    _ => {
                        return Err(ProofSystemError::ProofIncompatibleWithStatement(
                            s_idx,
                            format!("{:?}", proof),
                            format!("{:?}", s),
                        ))
                    }
                },
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
                        let sp = PoKBBSSigG1SubProtocol::new(s_idx, s);
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
                        let sp = AccumulatorMembershipSubProtocol::new(s_idx, s);
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
                        let sp = AccumulatorNonMembershipSubProtocol::new(s_idx, s);
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
                        let sp = SchnorrProtocol::new(s_idx, s);
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
                Statement::Saver(s) => match proof {
                    StatementProof::Saver(ref _p) => {
                        let sp = SaverProtocol::new(s_idx, s);
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

    /// Hash bytes to a field element. This is vulnerable to timing attack and is only used input
    /// is public anyway like when generating setup parameters or challenge
    fn generate_challenge_from_bytes(bytes: &[u8]) -> E::Fr {
        field_elem_from_try_and_incr::<F, D>(bytes)
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for StatementProof<E, G> {
        impl_serialize!();
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for StatementProof<E, G> {
        impl_deserialize!();
    }
}
