use crate::impl_collection;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};

/// Secret data known only to the prover and whose knowledge is to proven
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Witness<E: PairingEngine> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    AccumulatorMembership(Membership<E>),
    AccumulatorNonMembership(NonMembership<E>),
    PedersenCommitment(Vec<E::Fr>),
}

impl_collection!(Witnesses, Witness);

/// Secret data corresponding when proving knowledge of BBS+ sig
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub signature: BBSSignatureG1<E>,
    pub unrevealed_messages: BTreeMap<usize, E::Fr>,
}

/// Secret data corresponding when proving proving accumulator membership
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Membership<E: PairingEngine> {
    pub element: E::Fr,
    pub witness: MembershipWitness<E::G1Affine>,
}

/// Secret data corresponding when proving proving accumulator non-membership
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct NonMembership<E: PairingEngine> {
    pub element: E::Fr,
    pub witness: NonMembershipWitness<E::G1Affine>,
}

/// Create a `Witness` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_witness(
        signature: BBSSignatureG1<E>,
        unrevealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Witness<E> {
        Witness::PoKBBSSignatureG1(PoKBBSSignatureG1 {
            signature,
            unrevealed_messages,
        })
    }
}

/// Create a `Witness` variant for proving membership in accumulator
impl<E: PairingEngine> Membership<E> {
    pub fn new_as_witness(element: E::Fr, witness: MembershipWitness<E::G1Affine>) -> Witness<E> {
        Witness::AccumulatorMembership(Membership { element, witness })
    }
}

/// Create a `Witness` variant for proving non-membership in accumulator
impl<E: PairingEngine> NonMembership<E> {
    pub fn new_as_witness(
        element: E::Fr,
        witness: NonMembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorNonMembership(NonMembership { element, witness })
    }
}
