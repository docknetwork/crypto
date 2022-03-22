use crate::error::ProofSystemError;
use crate::statement::{AccumulatorMembership, AccumulatorNonMembership};
use crate::statement_proof::StatementProof;
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::RngCore;
use ark_std::{
    format,
    io::{Read, Write},
};
use vb_accumulator::prelude::{MembershipProofProtocol, NonMembershipProofProtocol};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorMembershipSubProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: AccumulatorMembership<E>,
    pub protocol: Option<MembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorNonMembershipSubProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: AccumulatorNonMembership<E>,
    pub protocol: Option<NonMembershipProofProtocol<E>>,
}

impl<E: PairingEngine> AccumulatorMembershipSubProtocol<E> {
    pub fn new(id: usize, statement: AccumulatorMembership<E>) -> Self {
        Self {
            id,
            statement,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::Fr>,
        witness: crate::witness::Membership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = MembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            &self.statement.accumulator_value,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorMembership(proof))
    }

    pub fn verify_proof_contribution<G: AffineCurve>(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::AccumulatorMembership(p) => {
                p.verify(
                    &self.statement.accumulator_value,
                    challenge,
                    &self.statement.public_key,
                    &self.statement.params,
                    &self.statement.proving_key,
                )?;
                Ok(())
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }
}

impl<E: PairingEngine> AccumulatorNonMembershipSubProtocol<E> {
    pub fn new(id: usize, statement: AccumulatorNonMembership<E>) -> Self {
        Self {
            id,
            statement,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::Fr>,
        witness: crate::witness::NonMembership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = NonMembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            &self.statement.accumulator_value,
            &self.statement.public_key,
            &self.statement.params,
            &self.statement.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorNonMembership(proof))
    }

    pub fn verify_proof_contribution<G: AffineCurve>(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::AccumulatorNonMembership(p) => {
                p.verify(
                    &self.statement.accumulator_value,
                    challenge,
                    &self.statement.public_key,
                    &self.statement.params,
                    &self.statement.proving_key,
                )?;
                Ok(())
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }
}
