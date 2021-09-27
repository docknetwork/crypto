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

use bbs_plus::proof::PoKOfSignatureG1Proof;
use vb_accumulator::proofs::{MembershipProof, NonMembershipProof};

use crate::statement::{MetaStatement, Statement, WitnessRef};
use crate::sub_protocols::{
    AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol, PoKBBSSigG1SubProtocol,
    SchnorrProtocol, SubProtocol,
};
use crate::witness::Witness;
use crate::{
    error::ProofSystemError,
    statement::{MetaStatements, Statements},
    witness::Witnesses,
};
use ark_ff::{PrimeField, SquareRootField};
use digest::Digest;
use schnorr_pok::SchnorrResponse;

use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
pub use serialization::*;

/// Proof corresponding to one `Statement`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum StatementProof<E: PairingEngine, G: AffineCurve> {
    PoKBBSSignatureG1(PoKOfSignatureG1Proof<E>),
    AccumulatorMembership(MembershipProof<E>),
    AccumulatorNonMembership(NonMembershipProof<E>),
    PedersenCommitment(PedersenCommitmentProof<G>),
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitmentProof<G: AffineCurve> {
    #[serde_as(as = "AffineGroupBytes")]
    pub t: G,
    pub response: SchnorrResponse<G>,
}

impl<G: AffineCurve> PedersenCommitmentProof<G> {
    pub fn new(t: G, response: SchnorrResponse<G>) -> Self {
        Self { t, response }
    }
}

/// Describes the relations that need to proven. This is known to the prover and verifier and must
/// be agreed upon before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct ProofSpec<E: PairingEngine, G: AffineCurve> {
    pub statements: Statements<E, G>,
    pub meta_statements: MetaStatements,
}

/// Created by the prover and verified by the verifier
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<E: PairingEngine, G: AffineCurve, F: PrimeField + SquareRootField, D: Digest>(
    pub Vec<StatementProof<E, G>>,
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

impl<E: PairingEngine, G: AffineCurve, F: PrimeField + SquareRootField, D: Digest> Eq
    for Proof<E, G, F, D>
{
}

impl<E, G> ProofSpec<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self {
            statements: Statements::new(),
            meta_statements: MetaStatements::new(),
        }
    }

    pub fn new_with_statements_and_meta_statements(
        statements: Statements<E, G>,
        meta_statements: MetaStatements,
    ) -> Self {
        Self {
            statements,
            meta_statements,
        }
    }

    pub fn add_statement(&mut self, statement: Statement<E, G>) {
        self.statements.add(statement);
    }

    pub fn add_meta_statement(&mut self, meta_statement: MetaStatement) {
        self.meta_statements.add(meta_statement);
    }
}

impl<E, G, F, D> Proof<E, G, F, D>
where
    E: PairingEngine<Fr = F>,
    G: AffineCurve<ScalarField = F>,
    F: PrimeField + SquareRootField,
    D: Digest,
{
    /// Create a new proof. `context` is any arbitrary data that needs to be hashed into the proof and
    /// it must be kept same while creating and verifying the proof.
    pub fn new<R: RngCore>(
        rng: &mut R,
        proof_spec: ProofSpec<E, G>,
        witnesses: Witnesses<E>,
        context: &[u8],
    ) -> Result<Self, ProofSystemError> {
        if proof_spec.statements.len() != witnesses.len() {
            return Err(ProofSystemError::UnequalWitnessAndStatementCount(
                proof_spec.statements.len(),
                witnesses.len(),
            ));
        }

        let mut blindings = BTreeMap::<WitnessRef, F>::new();

        // Prepare blindings for any witnesses that need to be proven equal.
        if !proof_spec.meta_statements.is_empty() {
            if proof_spec.meta_statements.len() > 1 {
                return Err(ProofSystemError::OnlyOneMetaStatementSupportedForNow);
            }

            // NOTE: Assuming all sets in proof_spec.meta_statements.0 are disjoint
            for stmt in proof_spec.meta_statements.0 {
                match stmt {
                    MetaStatement::WitnessEquality(eq_sets) => {
                        for set in eq_sets.0 {
                            let blinding = E::Fr::rand(rng);
                            for wr in set {
                                // Duplicating the same blinding for faster search
                                blindings.insert(wr, blinding);
                            }
                        }
                    }
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
            }
        }

        // Get each sub-protocol's challenge contribution
        let mut challenge_bytes = context.to_vec();
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
        Ok(Self(statement_proofs, PhantomData, PhantomData))
    }

    /// Verify the `Proof` given the `ProofSpec` and `context`
    pub fn verify(
        self,
        proof_spec: ProofSpec<E, G>,
        context: &[u8],
    ) -> Result<(), ProofSystemError> {
        // All the distinct equalities in `ProofSpec`
        let mut witness_equalities = vec![];

        if !proof_spec.meta_statements.is_empty() {
            if proof_spec.meta_statements.len() > 1 {
                return Err(ProofSystemError::OnlyOneMetaStatementSupportedForNow);
            }

            // NOTE: Assuming all sets in proof_spec.meta_statements.0 are disjoint
            for stmt in proof_spec.meta_statements.0 {
                match stmt {
                    MetaStatement::WitnessEquality(eq_sets) => {
                        witness_equalities = eq_sets.0;
                    }
                }
            }
        }

        // This will hold the response for each witness equality
        let mut responses_for_equalities: Vec<Option<&E::Fr>> =
            vec![None; witness_equalities.len()];

        let mut challenge_bytes = context.to_vec();

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
                        for i in 0..s.params.max_message_count() {
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
            }
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

    // TODO: Following code contains duplication that can possible be removed using macros

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for StatementProof<E, G> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    CanonicalSerialize::serialize(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::PedersenCommitment(s) => {
                    CanonicalSerialize::serialize(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorMembership(s) => 1u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorNonMembership(s) => {
                    2u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::PedersenCommitment(s) => 3u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for StatementProof<E, G> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::PoKBBSSignatureG1(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKOfSignatureG1Proof::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    MembershipProof::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembershipProof::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    PedersenCommitmentProof::<G>::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKOfSignatureG1Proof::<E>::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    MembershipProof::<E>::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembershipProof::<E>::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    PedersenCommitmentProof::<G>::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::{
        AccumulatorMembership as AccumulatorMembershipStmt,
        AccumulatorNonMembership as AccumulatorNonMembershipStmt, EqualWitnesses,
        PedersenCommitment as PedersenCommitmentStmt, PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    };
    use crate::witness::{
        Membership as MembershipWit, NonMembership as NonMembershipWit,
        PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
    };
    use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_std::collections::BTreeSet;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use bbs_plus::signature::SignatureG1;
    use blake2::Blake2b;
    use vb_accumulator::positive::Accumulator;
    use vb_accumulator::proofs::{MembershipProvingKey, NonMembershipProvingKey};

    use crate::test_serialization;
    use crate::test_utils::{setup_positive_accum, setup_universal_accum, sig_setup};

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

    #[test]
    fn pok_of_2_bbs_plus_sig_and_message_equality() {
        // Prove knowledge of 2 BBS+ signatures and 3 of the messages are same among them.
        let mut rng = StdRng::seed_from_u64(0u64);

        // 1st BBS+ sig
        let msg_count_1 = 6;
        let (msgs_1, params_1, keypair_1, sig_1) = sig_setup(&mut rng, msg_count_1);

        // Prepare revealed messages for the proof of knowledge of 1st signature
        let mut revealed_indices_1 = BTreeSet::new();
        revealed_indices_1.insert(0);
        revealed_indices_1.insert(2);

        let mut revealed_msgs_1 = BTreeMap::new();
        let mut unrevealed_msgs_1 = BTreeMap::new();
        for i in 0..msg_count_1 {
            if revealed_indices_1.contains(&i) {
                revealed_msgs_1.insert(i, msgs_1[i]);
            } else {
                unrevealed_msgs_1.insert(i, msgs_1[i]);
            }
        }

        // 2nd BBS+ sig
        let msg_count_2 = 10;
        let (mut msgs_2, params_2, keypair_2, _) = sig_setup(&mut rng, msg_count_2);

        // Make 3 messages same
        msgs_2[9] = msgs_1[5].clone();
        msgs_2[8] = msgs_1[4].clone();
        msgs_2[7] = msgs_1[3].clone();

        let sig_2 =
            SignatureG1::<Bls12_381>::new(&mut rng, &msgs_2, &keypair_2.secret_key, &params_2)
                .unwrap();
        sig_2
            .verify(&msgs_2, &keypair_2.public_key, &params_2)
            .unwrap();

        // Prepare revealed messages for the proof of knowledge of 2nd signature
        let mut revealed_indices_2 = BTreeSet::new();
        revealed_indices_2.insert(1);
        revealed_indices_2.insert(3);
        revealed_indices_2.insert(5);

        let mut revealed_msgs_2 = BTreeMap::new();
        let mut unrevealed_msgs_2 = BTreeMap::new();
        for i in 0..msg_count_2 {
            if revealed_indices_2.contains(&i) {
                revealed_msgs_2.insert(i, msgs_2[i]);
            } else {
                unrevealed_msgs_2.insert(i, msgs_2[i]);
            }
        }

        // Since proving knowledge of 2 BBS+ signatures, add 2 statements, both of the same type though.
        let mut statements = Statements::new();
        statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
            params_1.clone(),
            keypair_1.public_key.clone(),
            revealed_msgs_1.clone(),
        ));
        statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
            params_2.clone(),
            keypair_2.public_key.clone(),
            revealed_msgs_2.clone(),
        ));

        // Since 2 of the messages are being proven equal, add a `MetaStatement` describing that
        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, 5), (1, 9)] // 0th statement's 5th witness is equal to 1st statement's 9th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 4), (1, 8)] // 0th statement's 4th witness is equal to 1st statement's 8th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 3), (1, 7)] // 0th statement's 3rd witness is equal to 1st statement's 7th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
        test_serialization!(MetaStatements, meta_statements);

        // Create a proof spec, this is shared between prover and verifier
        let proof_spec =
            ProofSpec::new_with_statements_and_meta_statements(statements, meta_statements);

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        // Prover now creates/loads it witnesses corresponding to the proof spec
        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig_1.clone(),
            unrevealed_msgs_1.clone(),
        ));
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig_2.clone(),
            unrevealed_msgs_2.clone(),
        ));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        // Prover now creates the proof using the proof spec and witnesses. This will be sent to the verifier
        // Context must be known to both prover and verifier
        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses, context).unwrap();

        // Proof with invalid context shouldn't verify
        assert!(proof
            .clone()
            .verify(proof_spec.clone(), "random...".as_bytes())
            .is_err());

        test_serialization!(ProofG1, proof);
        // Verifier verifies the proof
        proof.verify(proof_spec, context).unwrap();
    }

    #[test]
    fn pok_of_bbs_plus_sig_and_accumulator() {
        // Prove knowledge of BBS+ signature and one of the message's membership and non-membership in accumulators
        let mut rng = StdRng::seed_from_u64(0u64);

        let msg_count = 6;
        let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

        let max = 10;
        let (pos_accum_params, pos_accum_keypair, mut pos_accumulator, mut pos_state) =
            setup_positive_accum(&mut rng);
        let mem_prk = MembershipProvingKey::generate_using_rng(&mut rng);

        // Message with index `accum_member_1_idx` is added in the positive accumulator
        let accum_member_1_idx = 1;
        let accum_member_1 = msgs[accum_member_1_idx].clone();

        pos_accumulator = pos_accumulator
            .add(
                accum_member_1.clone(),
                &pos_accum_keypair.secret_key,
                &mut pos_state,
            )
            .unwrap();
        let mem_1_wit = pos_accumulator
            .get_membership_witness(&accum_member_1, &pos_accum_keypair.secret_key, &pos_state)
            .unwrap();
        assert!(pos_accumulator.verify_membership(
            &accum_member_1,
            &mem_1_wit,
            &pos_accum_keypair.public_key,
            &pos_accum_params
        ));

        let mut statements = Statements::new();
        statements.add(PoKSignatureBBSG1Stmt::new_as_statement(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        statements.add(AccumulatorMembershipStmt::new_as_statement(
            pos_accum_params.clone(),
            pos_accum_keypair.public_key.clone(),
            mem_prk.clone(),
            pos_accumulator.value().clone(),
        ));

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        ));
        witnesses.add(MembershipWit::new_as_witness(
            accum_member_1.clone(),
            mem_1_wit.clone(),
        ));

        // Create meta statement describing that message in the signature at index `accum_member_1_idx` is
        // same as the accumulator member
        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, accum_member_1_idx),
            (1, 0), // Since accumulator (non)membership has only one (for applications) which is the (non)member, that witness is at index 0.
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
        test_serialization!(MetaStatements, meta_statements);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec.clone(), context).unwrap();

        // Wrong witness reference fails to verify
        let mut meta_statements_incorrect = MetaStatements::new();
        meta_statements_incorrect.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, 0),
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));
        let proof_spec_incorrect = ProofSpec {
            statements: statements.clone(),
            meta_statements: meta_statements_incorrect,
        };
        let proof =
            ProofG1::new(&mut rng, proof_spec_incorrect.clone(), witnesses, context).unwrap();
        assert!(proof.verify(proof_spec_incorrect, context).is_err());

        // Non-member fails to verify
        let mut witnesses_incorrect = Witnesses::new();
        witnesses_incorrect.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
            signature: sig.clone(),
            unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        }));
        witnesses_incorrect.add(Witness::AccumulatorMembership(MembershipWit {
            element: msgs[2].clone(), // 2nd message from BBS+ sig in accumulator
            witness: mem_1_wit.clone(),
        }));
        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, 2), // 2nd message from BBS+ sig in accumulator
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));
        let proof_spec = ProofSpec {
            statements,
            meta_statements,
        };
        let proof =
            ProofG1::new(&mut rng, proof_spec.clone(), witnesses_incorrect, context).unwrap();
        assert!(proof.verify(proof_spec, context).is_err());

        // Prove knowledge of signature and membership of message with index `accum_member_2_idx` in universal accumulator
        let accum_member_2_idx = 2;
        let accum_member_2 = msgs[accum_member_2_idx].clone();
        let (
            uni_accum_params,
            uni_accum_keypair,
            mut uni_accumulator,
            initial_elements,
            mut uni_state,
        ) = setup_universal_accum(&mut rng, max);
        let non_mem_prk = NonMembershipProvingKey::generate_using_rng(&mut rng);
        let derived_mem_prk = non_mem_prk.derive_membership_proving_key();

        uni_accumulator = uni_accumulator
            .add(
                accum_member_2.clone(),
                &uni_accum_keypair.secret_key,
                &initial_elements,
                &mut uni_state,
            )
            .unwrap();
        let mem_2_wit = uni_accumulator
            .get_membership_witness(&accum_member_2, &uni_accum_keypair.secret_key, &uni_state)
            .unwrap();
        assert!(uni_accumulator.verify_membership(
            &accum_member_2,
            &mem_2_wit,
            &uni_accum_keypair.public_key,
            &uni_accum_params
        ));

        let mut statements = Statements::new();
        statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
            params: sig_params.clone(),
            public_key: sig_keypair.public_key.clone(),
            revealed_messages: BTreeMap::new(),
        }));
        statements.add(Statement::AccumulatorMembership(
            AccumulatorMembershipStmt {
                params: uni_accum_params.clone(),
                public_key: uni_accum_keypair.public_key.clone(),
                proving_key: derived_mem_prk.clone(),
                accumulator_value: uni_accumulator.value().clone(),
            },
        ));

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
            signature: sig.clone(),
            unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        }));
        witnesses.add(Witness::AccumulatorMembership(MembershipWit {
            element: accum_member_2.clone(),
            witness: mem_2_wit.clone(),
        }));

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, accum_member_2_idx),
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
        test_serialization!(MetaStatements, meta_statements);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();

        // Prove knowledge of signature and non-membership of message with index `accum_non_member_idx` in universal accumulator
        let accum_non_member_idx = 3;
        let accum_non_member = msgs[accum_non_member_idx].clone();
        let non_mem_wit = uni_accumulator
            .get_non_membership_witness(
                &accum_non_member,
                &uni_accum_keypair.secret_key,
                &uni_state,
                &uni_accum_params,
            )
            .unwrap();
        assert!(uni_accumulator.verify_non_membership(
            &accum_non_member,
            &non_mem_wit,
            &uni_accum_keypair.public_key,
            &uni_accum_params
        ));

        let mut statements = Statements::new();
        statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
            params: sig_params.clone(),
            public_key: sig_keypair.public_key.clone(),
            revealed_messages: BTreeMap::new(),
        }));
        statements.add(Statement::AccumulatorNonMembership(
            AccumulatorNonMembershipStmt {
                params: uni_accum_params.clone(),
                public_key: uni_accum_keypair.public_key.clone(),
                proving_key: non_mem_prk.clone(),
                accumulator_value: uni_accumulator.value().clone(),
            },
        ));

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
            signature: sig.clone(),
            unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        }));
        witnesses.add(Witness::AccumulatorNonMembership(NonMembershipWit {
            element: accum_non_member.clone(),
            witness: non_mem_wit.clone(),
        }));

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, accum_non_member_idx),
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
        test_serialization!(MetaStatements, meta_statements);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();

        // Prove knowledge of signature and
        // - membership of message with index `accum_member_1_idx` in positive accumulator
        // - -membership of message with index `accum_member_2_idx` in universal accumulator
        // - non-membership of message with index `accum_non_member_idx` in universal accumulator
        let mut statements = Statements::new();
        statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
            params: sig_params.clone(),
            public_key: sig_keypair.public_key.clone(),
            revealed_messages: BTreeMap::new(),
        }));
        statements.add(Statement::AccumulatorMembership(
            AccumulatorMembershipStmt {
                params: pos_accum_params.clone(),
                public_key: pos_accum_keypair.public_key.clone(),
                proving_key: mem_prk.clone(),
                accumulator_value: pos_accumulator.value().clone(),
            },
        ));
        statements.add(Statement::AccumulatorMembership(
            AccumulatorMembershipStmt {
                params: uni_accum_params.clone(),
                public_key: uni_accum_keypair.public_key.clone(),
                proving_key: derived_mem_prk.clone(),
                accumulator_value: uni_accumulator.value().clone(),
            },
        ));
        statements.add(Statement::AccumulatorNonMembership(
            AccumulatorNonMembershipStmt {
                params: uni_accum_params.clone(),
                public_key: uni_accum_keypair.public_key.clone(),
                proving_key: non_mem_prk.clone(),
                accumulator_value: uni_accumulator.value().clone(),
            },
        ));

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, accum_member_1_idx), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, accum_member_2_idx), (2, 0)]
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, accum_non_member_idx), (3, 0)]
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
        test_serialization!(MetaStatements, meta_statements);

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PoKBBSSignatureG1(PoKSignatureBBSG1Wit {
            signature: sig.clone(),
            unrevealed_messages: msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        }));
        witnesses.add(Witness::AccumulatorMembership(MembershipWit {
            element: accum_member_1.clone(),
            witness: mem_1_wit.clone(),
        }));
        witnesses.add(Witness::AccumulatorMembership(MembershipWit {
            element: accum_member_2.clone(),
            witness: mem_2_wit.clone(),
        }));
        witnesses.add(Witness::AccumulatorNonMembership(NonMembershipWit {
            element: accum_non_member.clone(),
            witness: non_mem_wit.clone(),
        }));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();
    }

    #[test]
    fn pok_of_knowledge_in_pedersen_commitment_and_equality() {
        // Prove knowledge of commitment in Pedersen commitments and equality between committed elements
        let mut rng = StdRng::seed_from_u64(0u64);

        let bases_1 = (0..5)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let scalars_1 = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let commitment_1 = VariableBaseMSM::multi_scalar_mul(
            &bases_1,
            &scalars_1.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();

        let bases_2 = (0..10)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let mut scalars_2 = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        // Make 2 of the scalars same
        scalars_2[1] = scalars_1[3].clone();
        scalars_2[4] = scalars_1[0].clone();
        let commitment_2 = VariableBaseMSM::multi_scalar_mul(
            &bases_2,
            &scalars_2.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();

        let mut statements = Statements::new();
        statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases_1.clone(),
            commitment: commitment_1.clone(),
        }));
        statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases_2.clone(),
            commitment: commitment_2.clone(),
        }));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, 3), (1, 1)] // 0th statement's 3rd witness is equal to 1st statement's 1st witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 0), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PedersenCommitment(scalars_1.clone()));
        witnesses.add(Witness::PedersenCommitment(scalars_2.clone()));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements: meta_statements.clone(),
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();

        // Wrong commitment should fail to verify
        let mut statements_wrong = Statements::new();
        statements_wrong.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases_1.clone(),
            commitment: commitment_1.clone(),
        }));
        // The commitment is wrong
        statements_wrong.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases_2.clone(),
            commitment: commitment_1.clone(),
        }));

        let proof_spec_invalid = ProofSpec {
            statements: statements_wrong.clone(),
            meta_statements: meta_statements.clone(),
        };

        let context = "test".as_bytes();
        let proof = ProofG1::new(
            &mut rng,
            proof_spec_invalid.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();
        assert!(proof.verify(proof_spec_invalid, context).is_err());

        // Wrong message equality should fail to verify
        let mut meta_statements_wrong = MetaStatements::new();
        meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, 3), (1, 0)] // this equality doesn't hold
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 0), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        let proof_spec_invalid = ProofSpec {
            statements: statements.clone(),
            meta_statements: meta_statements_wrong,
        };

        let context = "test".as_bytes();
        let proof = ProofG1::new(
            &mut rng,
            proof_spec_invalid.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

        assert!(proof.verify(proof_spec_invalid, context).is_err());
    }

    #[test]
    fn pok_of_knowledge_in_pedersen_commitment_and_BBS_plus_sig() {
        // Prove knowledge of commitment in Pedersen commitments and equality with a BBS+ signature.
        // Useful when requesting a blind signature and proving knowledge of a signature along with
        // some the equality of certain messages in the commitment and signature

        let mut rng = StdRng::seed_from_u64(0u64);

        let msg_count = 6;
        let (msgs, sig_params, sig_keypair, sig) = sig_setup(&mut rng, msg_count);

        let bases = (0..5)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let mut scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        // Make 2 of the messages in the commitment same as in the signature
        scalars[1] = msgs[0].clone();
        scalars[4] = msgs[5].clone();
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &bases,
            &scalars.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();

        let mut statements = Statements::new();
        statements.add(Statement::PoKBBSSignatureG1(PoKSignatureBBSG1Stmt {
            params: sig_params.clone(),
            public_key: sig_keypair.public_key.clone(),
            revealed_messages: BTreeMap::new(),
        }));
        statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases.clone(),
            commitment: commitment.clone(),
        }));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, 0), (1, 1)] // 0th statement's 0th witness is equal to 1st statement's 1st witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 5), (1, 4)] // 0th statement's 5th witness is equal to 1st statement's 4th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements: meta_statements.clone(),
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().map(|t| t).collect(),
        ));
        witnesses.add(Witness::PedersenCommitment(scalars.clone()));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();

        // Wrong message equality should fail to verify
        let mut meta_statements_wrong = MetaStatements::new();
        meta_statements_wrong.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![
            vec![(0, 3), (1, 0)] // this equality doesn't hold
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
            vec![(0, 5), (1, 4)] // 0th statement's 0th witness is equal to 1st statement's 4th witness
                .into_iter()
                .collect::<BTreeSet<(usize, usize)>>(),
        ])));

        let proof_spec_invalid = ProofSpec {
            statements: statements.clone(),
            meta_statements: meta_statements_wrong,
        };

        let context = "test".as_bytes();
        let proof = ProofG1::new(
            &mut rng,
            proof_spec_invalid.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

        assert!(proof.verify(proof_spec_invalid, context).is_err());
    }

    #[test]
    fn requesting_partially_blind_BBS_plus_sig() {
        // Request a partially blind signature by first proving knowledge of values in a Pedersen commitment. The
        // requester then unblinds the signature and verifies it.

        let mut rng = StdRng::seed_from_u64(0u64);

        // The total number of messages in the signature
        let total_msg_count = 10;

        // Setup params and messages
        let (msgs, sig_params, sig_keypair, _) = sig_setup(&mut rng, total_msg_count);

        // Message indices hidden from signer. Here signer does not know msgs[0], msgs[4] and msgs[6]
        let committed_indices = vec![0, 4, 6].into_iter().collect::<BTreeSet<usize>>();

        // Requester commits messages msgs[0], msgs[4] and msgs[6] as `sig_params.h_0 * blinding + params.h[0] * msgs[0] + params.h[4] * msgs[4] + params.h[6] * msgs[6]`
        let blinding = Fr::rand(&mut rng);
        let committed_messages = committed_indices
            .iter()
            .map(|i| (*i, &msgs[*i]))
            .collect::<BTreeMap<_, _>>();
        let commitment = sig_params
            .commit_to_messages(committed_messages, &blinding)
            .unwrap();

        // Requester proves knowledge of committed messages
        let mut statements = Statements::new();
        let mut bases = vec![sig_params.h_0.clone()];
        let mut committed_msgs = vec![blinding.clone()];
        for i in committed_indices.iter() {
            bases.push(sig_params.h[*i].clone());
            committed_msgs.push(msgs[*i].clone());
        }
        statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
            bases: bases.clone(),
            commitment: commitment.clone(),
        }));

        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements: MetaStatements::new(),
        };

        test_serialization!(ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, proof_spec);

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PedersenCommitment(committed_msgs));

        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let context = "test".as_bytes();
        let proof = ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), context).unwrap();

        test_serialization!(ProofG1, proof);

        proof.verify(proof_spec, context).unwrap();

        // Now requester picks the messages he is revealing to the signer and prepares `uncommitted_messages`
        // to request the blind signature
        let uncommitted_messages = (0..total_msg_count)
            .filter(|i| !committed_indices.contains(i))
            .map(|i| (i, &msgs[i]))
            .collect::<BTreeMap<_, _>>();

        // Signer creates the blind signature using the commitment
        let blinded_sig = SignatureG1::<Bls12_381>::new_with_committed_messages(
            &mut rng,
            &commitment,
            uncommitted_messages,
            &sig_keypair.secret_key,
            &sig_params,
        )
        .unwrap();

        let sig = blinded_sig.unblind(&blinding);
        sig.verify(&msgs, &sig_keypair.public_key, &sig_params)
            .unwrap();
    }
}
