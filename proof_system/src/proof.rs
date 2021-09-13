use ark_ec::{AffineCurve, PairingEngine};
use ark_std::{
    collections::BTreeMap, fmt::Debug, format, marker::PhantomData, rand::RngCore, vec, vec::Vec,
    UniformRand,
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
use ark_ff::{to_bytes, Field};
use digest::Digest;
use schnorr_pok::SchnorrResponse;

/// Proof corresponding to one `Statement`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementProof<E: PairingEngine, G: AffineCurve> {
    PoKBBSSignatureG1(PoKOfSignatureG1Proof<E>),
    AccumulatorMembership(MembershipProof<E>),
    AccumulatorNonMembership(NonMembershipProof<E>),
    PedersenCommitment(G, SchnorrResponse<G>),
}

/// Describes the relations that need to proven. This is known to the prover and verifier and must
/// be agreed upon before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofSpec<E: PairingEngine> {
    pub statements: Statements<E>,
    pub meta_statements: MetaStatements,
}

/// Created by the prover and verified by the verifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<E: PairingEngine, G: AffineCurve, D: Digest>(
    pub Vec<StatementProof<E, G>>,
    PhantomData<D>,
);

impl<E, G, D> Proof<E, G, D>
where
    E: PairingEngine,
    G: AffineCurve,
    D: Digest,
{
    /// Create a new proof. `context` is any arbitrary data that needs to be hashed into the proof and
    /// it must be kept same while creating and verifying the proof.
    pub fn new<R: RngCore>(
        rng: &mut R,
        proof_spec: ProofSpec<E>,
        witnesses: Witnesses<E>,
        context: &[u8],
    ) -> Result<Self, ProofSystemError> {
        if proof_spec.statements.len() != witnesses.len() {
            return Err(ProofSystemError::UnequalWitnessAndStatementCount(
                proof_spec.statements.len(),
                witnesses.len(),
            ));
        }

        let mut blindings = BTreeMap::<WitnessRef, E::Fr>::new();

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
                        sub_protocols.push(SubProtocol::PoKDiscreteLogsG1(sp));
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
        Ok(Self(statement_proofs, PhantomData))
    }

    pub fn verify(self, proof_spec: ProofSpec<E>, context: &[u8]) -> Result<(), ProofSystemError> {
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
            }
        }
        Ok(())
    }

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
        let mut hash = D::digest(bytes);
        let mut f = E::Fr::from_random_bytes(&hash);
        let mut j = 1u64;
        while f.is_none() {
            hash = D::digest(&to_bytes![bytes, "-attempt-".as_bytes(), j].unwrap());
            f = E::Fr::from_random_bytes(&hash);
            j += 1;
        }
        f.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::{
        AccumulatorMembership as AccumulatorMembershipStmt,
        AccumulatorNonMembership as AccumulatorNonMembershipStmt, EqualWitnesses,
        PoKBBSSignatureG1 as PoKSignatureBBSG1Stmt,
    };
    use crate::witness::{
        Membership as MembershipWit, NonMembership as NonMembershipWit,
        PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::collections::BTreeSet;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use bbs_plus::setup::{KeypairG2, SignatureParamsG1};
    use bbs_plus::signature::SignatureG1;
    use blake2::Blake2b;
    use std::collections::HashSet;
    use std::hash::Hash;
    use vb_accumulator::persistence::{InitialElementsStore, State, UniversalAccumulatorState};
    use vb_accumulator::positive::{Accumulator, PositiveAccumulator};
    use vb_accumulator::proofs::{MembershipProvingKey, NonMembershipProvingKey};
    use vb_accumulator::setup::{Keypair, SetupParams};
    use vb_accumulator::universal::UniversalAccumulator;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    fn sig_setup<R: RngCore>(
        rng: &mut R,
        message_count: usize,
    ) -> (
        Vec<Fr>,
        SignatureParamsG1<Bls12_381>,
        KeypairG2<Bls12_381>,
        SignatureG1<Bls12_381>,
    ) {
        let messages: Vec<Fr> = (0..message_count)
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
        let keypair = KeypairG2::<Bls12_381>::generate(rng, &params);
        let sig =
            SignatureG1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
        sig.verify(&messages, &keypair.public_key, &params).unwrap();
        (messages, params, keypair, sig)
    }

    #[derive(Clone, Debug)]
    pub struct InMemoryInitialElements<T: Clone> {
        pub db: HashSet<T>,
    }

    impl<T: Clone> InMemoryInitialElements<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Hash + Eq> InitialElementsStore<T> for InMemoryInitialElements<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }
    }

    #[derive(Clone, Debug)]
    pub struct InMemoryState<T: Clone> {
        pub db: HashSet<T>,
    }

    impl<T: Clone> InMemoryState<T> {
        pub fn new() -> Self {
            let db = HashSet::<T>::new();
            Self { db }
        }
    }

    impl<T: Clone + Hash + Eq + Sized> State<T> for InMemoryState<T> {
        fn add(&mut self, element: T) {
            self.db.insert(element);
        }

        fn remove(&mut self, element: &T) {
            self.db.remove(element);
        }

        fn has(&self, element: &T) -> bool {
            self.db.get(element).is_some()
        }

        fn size(&self) -> u64 {
            self.db.len() as u64
        }
    }

    impl<'a, T: Clone + Hash + Eq + Sized + 'a> UniversalAccumulatorState<'a, T> for InMemoryState<T> {
        type ElementIterator = std::collections::hash_set::Iter<'a, T>;

        fn elements(&'a self) -> Self::ElementIterator {
            self.db.iter()
        }
    }

    /// Setup a positive accumulator, its keys, params and state for testing.
    pub fn setup_positive_accum(
        rng: &mut StdRng,
    ) -> (
        SetupParams<Bls12_381>,
        Keypair<Bls12_381>,
        PositiveAccumulator<Bls12_381>,
        InMemoryState<Fr>,
    ) {
        let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
        let keypair = Keypair::<Bls12_381>::generate(rng, &params);

        let accumulator = PositiveAccumulator::initialize(&params);
        let state = InMemoryState::new();
        (params, keypair, accumulator, state)
    }

    /// Setup a universal accumulator, its keys, params and state for testing.
    pub fn setup_universal_accum(
        rng: &mut StdRng,
        max: u64,
    ) -> (
        SetupParams<Bls12_381>,
        Keypair<Bls12_381>,
        UniversalAccumulator<Bls12_381>,
        InMemoryInitialElements<Fr>,
        InMemoryState<Fr>,
    ) {
        let params = SetupParams::<Bls12_381>::generate_using_rng(rng);
        let keypair = Keypair::<Bls12_381>::generate(rng, &params);

        let mut initial_elements = InMemoryInitialElements::new();
        let accumulator = UniversalAccumulator::initialize(
            rng,
            &params,
            max,
            &keypair.secret_key,
            &mut initial_elements,
        );
        let state = InMemoryState::new();
        (params, keypair, accumulator, initial_elements, state)
    }

    #[test]
    fn pok_of_2_bbs_plus_sig_and_message_equality() {
        // Prove knowledge of 2 BBS+ signatures and 3 of the messages are same among them.
        let mut rng = StdRng::seed_from_u64(0u64);

        // 1st BBS sig
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

        // 2nd BBS sig
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

        let proof_spec = ProofSpec {
            statements,
            meta_statements,
        };

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig_1.clone(),
            unrevealed_msgs_1.clone(),
        ));
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig_2.clone(),
            unrevealed_msgs_2.clone(),
        ));

        let context = "test".as_bytes();
        let proof =
            Proof::<Bls12_381, Blake2b>::new(&mut rng, proof_spec.clone(), witnesses, context)
                .unwrap();

        // Proof with invalid context shouldn't verify
        assert!(proof
            .clone()
            .verify(proof_spec.clone(), "random...".as_bytes())
            .is_err());

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

        // Prove knowledge of signature and membership of message with index `accum_member_1_idx` in positive accumulator
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

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(vec![vec![
            (0, accum_member_1_idx),
            (1, 0),
        ]
        .into_iter()
        .collect::<BTreeSet<(usize, usize)>>()])));

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        let context = "test".as_bytes();
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

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
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec_incorrect.clone(),
            witnesses,
            context,
        )
        .unwrap();
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
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec.clone(),
            witnesses_incorrect,
            context,
        )
        .unwrap();
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

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        let context = "test".as_bytes();
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

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

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        let context = "test".as_bytes();
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

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

        let proof_spec = ProofSpec {
            statements: statements.clone(),
            meta_statements,
        };

        let context = "test".as_bytes();
        let proof = Proof::<Bls12_381, Blake2b>::new(
            &mut rng,
            proof_spec.clone(),
            witnesses.clone(),
            context,
        )
        .unwrap();

        proof.verify(proof_spec, context).unwrap();
    }
}
