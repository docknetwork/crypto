use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use ark_std::{
    collections::BTreeMap,
    format,
    io::{Read, Write},
    vec::Vec,
};
use schnorr_pok::{SchnorrChallengeContributor, SchnorrCommitment};

use crate::error::ProofSystemError;
use crate::statement::PedersenCommitment;
use crate::statement_proof::{PedersenCommitmentProof, StatementProof};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrProtocol<G: AffineCurve> {
    pub id: usize,
    pub statement: PedersenCommitment<G>,
    pub commitment: Option<SchnorrCommitment<G>>,
    pub witnesses: Option<Vec<G::ScalarField>>,
}

impl<G: AffineCurve> SchnorrProtocol<G> {
    pub fn new(id: usize, statement: PedersenCommitment<G>) -> Self {
        Self {
            id,
            statement,
            commitment: None,
            witnesses: None,
        }
    }

    /// `blindings` specifies the randomness to use. If some index is not present, new randomness is generated for it.
    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        mut blindings: BTreeMap<usize, G::ScalarField>,
        witnesses: Vec<G::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.commitment.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let blindings = (0..witnesses.len())
            .map(|i| {
                blindings
                    .remove(&i)
                    .unwrap_or_else(|| G::ScalarField::rand(rng))
            })
            .collect::<Vec<_>>();
        self.commitment = Some(SchnorrCommitment::new(&self.statement.bases, blindings));
        self.witnesses = Some(witnesses);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.commitment.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.statement.bases.serialize_unchecked(&mut writer)?;
        self.statement.commitment.serialize_unchecked(&mut writer)?;
        self.commitment
            .as_ref()
            .unwrap()
            .challenge_contribution(writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution<E: PairingEngine>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        Ok(StatementProof::PedersenCommitment(
            self.gen_proof_contribution_as_struct(challenge)?,
        ))
    }

    pub fn gen_proof_contribution_as_struct(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<PedersenCommitmentProof<G>, ProofSystemError> {
        if self.commitment.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let commitment = self.commitment.take().unwrap();
        let responses = commitment.response(self.witnesses.as_ref().unwrap(), challenge)?;
        Ok(PedersenCommitmentProof::new(commitment.t, responses))
    }

    pub fn verify_proof_contribution<E: PairingEngine>(
        &self,
        challenge: &G::ScalarField,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::PedersenCommitment(p) => {
                self.verify_proof_contribution_as_struct(challenge, p)
            }
            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }

    pub fn verify_proof_contribution_as_struct(
        &self,
        challenge: &G::ScalarField,
        proof: &PedersenCommitmentProof<G>,
    ) -> Result<(), ProofSystemError> {
        proof
            .response
            .is_valid(
                self.statement.bases.as_slice(),
                &self.statement.commitment,
                &proof.t,
                challenge,
            )
            .map_err(|e| e.into())
    }

    pub fn compute_challenge_contribution<W: Write>(
        bases: &[G],
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        bases.serialize_unchecked(&mut writer)?;
        y.serialize_unchecked(&mut writer)?;
        t.serialize_unchecked(writer)?;
        Ok(())
    }
}
