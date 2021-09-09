use ark_ec::PairingEngine;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};

use bbs_plus::setup::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};

use ark_std::collections::BTreeSet;
use vb_accumulator::{
    proofs::{MembershipProvingKey, NonMembershipProvingKey},
    setup::{PublicKey as AccumPublicKey, SetupParams as AccumParams},
};

use crate::impl_collection;

/// Reference to a witness described as the tuple (`statement_id`, `witness_id`)
pub type WitnessRef = (usize, usize);

/// Type of proof and the public (known to both prover and verifier) values for the proof
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement<E: PairingEngine> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    /// Membership in Accumulator
    AccumulatorMembership(AccumulatorMembership<E>),
    /// Non-membership in Accumulator
    AccumulatorNonMembership(AccumulatorNonMembership<E>),
}

/// Statement describing relation between statements
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaStatement {
    WitnessEquality(EqualWitnesses),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaStatements(pub Vec<MetaStatement>);

impl_collection!(Statements, Statement);

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub params: BBSSignatureParamsG1<E>,
    pub public_key: BBSPublicKeyG2<E>,
    /// Messages being revealed.
    pub revealed_messages: BTreeMap<usize, E::Fr>,
}

/// Public values like setup params, public key, proving key and accumulator for proving membership
/// in positive and universal accumulator.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: MembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
}

/// Public values like setup params, public key, proving key and accumulator for proving non-membership
/// in universal accumulator.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorNonMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: NonMembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
}

/// Describes equality between one or more witnesses across statements. Eg. if witness 3 of statement
/// 0 is to be proven equal to witness 5 of statement 1, then its written as
/// ```
/// use ark_std::collections::BTreeSet;
/// use proof_system::statement::EqualWitnesses;
/// let mut eq = BTreeSet::new();
/// eq.insert((0, 3));
/// eq.insert((1, 5));
/// let eq_w = EqualWitnesses(vec![eq]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualWitnesses(pub Vec<BTreeSet<WitnessRef>>);

impl MetaStatements {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: MetaStatement) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a `Statement` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_statement(
        params: BBSSignatureParamsG1<E>,
        public_key: BBSPublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E> {
        Statement::PoKBBSSignatureG1(Self {
            params,
            public_key,
            revealed_messages,
        })
    }
}

/// Create a `Statement` variant for proving membership in accumulator
impl<E: PairingEngine> AccumulatorMembership<E> {
    pub fn new_as_statement(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E> {
        Statement::AccumulatorMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving non-membership in accumulator
impl<E: PairingEngine> AccumulatorNonMembership<E> {
    pub fn new_as_statement(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E> {
        Statement::AccumulatorNonMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}
