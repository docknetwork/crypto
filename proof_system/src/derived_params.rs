//! Parameters derived from parameters during proof generation and verification. Used to prevent repeatedly creating these parameters.
use crate::prelude::bound_check::BoundCheckProtocol;
use crate::sub_protocols::saver::SaverProtocol;
use ark_ec::PairingEngine;
use ark_std::{collections::BTreeMap, marker::PhantomData, vec, vec::Vec};
use legogroth16::{
    PreparedVerifyingKey as LegoPreparedVerifyingKey, VerifyingKey as LegoVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, EncryptionGens, EncryptionKey, PreparedEncryptionGens,
    PreparedEncryptionKey,
};
use saver::saver_groth16::{
    PreparedVerifyingKey as SaverPreparedVerifyingKey, VerifyingKey as SaverVerifyingKey,
};

pub trait DerivedParams<'a, Ref, DP> {
    fn new_derived(orig: &Ref) -> DP;
}

pub struct DerivedParamsTracker<'a, Ref: PartialEq, DP, E> {
    origs_ref: Vec<&'a Ref>,
    derived_params: BTreeMap<usize, DP>,
    derived_params_for_statement: BTreeMap<usize, usize>,
    phantom: PhantomData<E>,
}

pub struct StatementDerivedParams<DP> {
    derived_params: BTreeMap<usize, DP>,
    derived_params_for_statement: BTreeMap<usize, usize>,
}

impl<'a, Ref: PartialEq, DP, E> DerivedParamsTracker<'a, Ref, DP, E>
where
    DerivedParamsTracker<'a, Ref, DP, E>: DerivedParams<'a, Ref, DP>,
{
    pub fn new() -> Self {
        Self {
            origs_ref: vec![],
            derived_params: BTreeMap::new(),
            derived_params_for_statement: BTreeMap::new(),
            phantom: PhantomData,
        }
    }
    pub fn find(&self, orig: &Ref) -> Option<usize> {
        self.origs_ref.iter().position(|v: &&Ref| **v == *orig)
    }

    pub fn update_for_orig(&mut self, orig: &'a Ref, s_idx: usize) {
        if let Some(k) = self.find(orig) {
            self.derived_params_for_statement.insert(s_idx, k);
        } else {
            let derived = Self::new_derived(orig);
            self.derived_params.insert(self.origs_ref.len(), derived);
            self.derived_params_for_statement
                .insert(s_idx, self.origs_ref.len());
            self.origs_ref.push(orig);
        }
    }

    pub fn finish(self) -> StatementDerivedParams<DP> {
        StatementDerivedParams {
            derived_params: self.derived_params,
            derived_params_for_statement: self.derived_params_for_statement,
        }
    }
}

impl<DP> StatementDerivedParams<DP> {
    pub fn get(&self, s_idx: usize) -> Option<&DP> {
        self.derived_params
            .get(self.derived_params_for_statement.get(&s_idx)?)
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, LegoVerifyingKey<E>, Vec<E::G1Affine>>
    for DerivedParamsTracker<'a, LegoVerifyingKey<E>, Vec<E::G1Affine>, E>
{
    fn new_derived(vk: &LegoVerifyingKey<E>) -> Vec<E::G1Affine> {
        BoundCheckProtocol::schnorr_comm_key(vk)
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, EncryptionKey<E>, Vec<E::G1Affine>>
    for DerivedParamsTracker<'a, EncryptionKey<E>, Vec<E::G1Affine>, E>
{
    fn new_derived(ek: &EncryptionKey<E>) -> Vec<E::G1Affine> {
        SaverProtocol::encryption_comm_key(ek)
    }
}

impl<'a, E: PairingEngine>
    DerivedParams<
        'a,
        (&ChunkedCommitmentGens<E::G1Affine>, u8),
        (Vec<E::G1Affine>, Vec<E::G1Affine>),
    >
    for DerivedParamsTracker<
        'a,
        (&ChunkedCommitmentGens<E::G1Affine>, u8),
        (Vec<E::G1Affine>, Vec<E::G1Affine>),
        E,
    >
{
    fn new_derived(
        (comm_gens, chunk_bit_size): &(&ChunkedCommitmentGens<E::G1Affine>, u8),
    ) -> (Vec<E::G1Affine>, Vec<E::G1Affine>) {
        SaverProtocol::<E>::chunked_comm_keys(comm_gens, *chunk_bit_size)
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, EncryptionGens<E>, PreparedEncryptionGens<E>>
    for DerivedParamsTracker<'a, EncryptionGens<E>, PreparedEncryptionGens<E>, E>
{
    fn new_derived(gens: &EncryptionGens<E>) -> PreparedEncryptionGens<E> {
        gens.prepared()
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, EncryptionKey<E>, PreparedEncryptionKey<E>>
    for DerivedParamsTracker<'a, EncryptionKey<E>, PreparedEncryptionKey<E>, E>
{
    fn new_derived(ek: &EncryptionKey<E>) -> PreparedEncryptionKey<E> {
        ek.prepared()
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, SaverVerifyingKey<E>, SaverPreparedVerifyingKey<E>>
    for DerivedParamsTracker<'a, SaverVerifyingKey<E>, SaverPreparedVerifyingKey<E>, E>
{
    fn new_derived(vk: &SaverVerifyingKey<E>) -> SaverPreparedVerifyingKey<E> {
        saver::saver_groth16::prepare_verifying_key(vk)
    }
}

impl<'a, E: PairingEngine> DerivedParams<'a, LegoVerifyingKey<E>, LegoPreparedVerifyingKey<E>>
    for DerivedParamsTracker<'a, LegoVerifyingKey<E>, LegoPreparedVerifyingKey<E>, E>
{
    fn new_derived(vk: &LegoVerifyingKey<E>) -> LegoPreparedVerifyingKey<E> {
        legogroth16::prepare_verifying_key(vk)
    }
}
