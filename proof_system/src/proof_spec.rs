use crate::meta_statement::{MetaStatement, MetaStatements};
use crate::prelude::{Statement, Statements};
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

/// Describes the relations that need to proven. This is known to the prover and verifier and must
/// be agreed upon before creating a `Proof`. Represented as collection of `Statement`s and `MetaStatement`s.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct ProofSpec<E: PairingEngine, G: AffineCurve> {
    pub statements: Statements<E, G>,
    pub meta_statements: MetaStatements,
    /// `context` is any arbitrary data that needs to be hashed into the proof and it must be kept
    /// same while creating and verifying the proof. Eg of `context` are the purpose of
    /// the proof or the verifier's identity or some verifier-specific identity of the holder
    /// or all of the above combined.
    pub context: Option<Vec<u8>>,
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
            context: None,
        }
    }

    pub fn new_with_statements_and_meta_statements(
        statements: Statements<E, G>,
        meta_statements: MetaStatements,
        context: Option<Vec<u8>>,
    ) -> Self {
        Self {
            statements,
            meta_statements,
            context,
        }
    }

    pub fn add_statement(&mut self, statement: Statement<E, G>) {
        self.statements.add(statement);
    }

    pub fn add_meta_statement(&mut self, meta_statement: MetaStatement) {
        self.meta_statements.add(meta_statement);
    }

    pub fn is_valid(&self) -> bool {
        for mt in &self.meta_statements.0 {
            match mt {
                // All witness equalities should be valid
                MetaStatement::WitnessEquality(w) => {
                    if !w.is_valid() {
                        return false;
                    }
                }
            }
        }
        true
    }
}
