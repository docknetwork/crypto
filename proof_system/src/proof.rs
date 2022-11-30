use crate::prelude::StatementProof;
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeSet,
    io::{Read, Write},
    marker::PhantomData,
};
use digest::Digest;
use legogroth16::aggregation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregatedGroth16<E: PairingEngine> {
    pub proof: aggregation::groth16::AggregateProof<E>,
    pub statements: BTreeSet<usize>,
}

/// Created by the prover and verified by the verifier
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<E: PairingEngine, G: AffineCurve, D: Digest> {
    pub statement_proofs: Vec<StatementProof<E, G>>,
    pub nonce: Option<Vec<u8>>,
    // TODO: Remove this skip
    #[serde(skip)]
    pub aggregated_groth16: Option<Vec<AggregatedGroth16<E>>>,
    // TODO: Remove this skip
    #[serde(skip)]
    pub aggregated_legogroth16: Option<Vec<AggregatedGroth16<E>>>,
    pub _phantom: PhantomData<D>,
}

impl<E: PairingEngine, G: AffineCurve, D: Digest> PartialEq for Proof<E, G, D> {
    fn eq(&self, other: &Self) -> bool {
        self.statement_proofs == other.statement_proofs
    }
}
