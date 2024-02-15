use crate::{error::ProofSystemError, statement_proof::StatementProof};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{io::Write, rand::RngCore};
use vb_accumulator::{
    proofs_keyed_verification::{MembershipProof, MembershipProofProtocol},
    setup::SecretKey,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VBAccumulatorMembershipKVSubProtocol<G: AffineRepr> {
    pub id: usize,
    pub accumulator_value: G,
    pub protocol: Option<MembershipProofProtocol<G>>,
}

impl<G: AffineRepr> VBAccumulatorMembershipKVSubProtocol<G> {
    pub fn new(id: usize, accumulator_value: G) -> Self {
        Self {
            id,
            accumulator_value,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<G::ScalarField>,
        witness: crate::witness::Membership<G>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        self.protocol = Some(MembershipProofProtocol::init(
            rng,
            witness.element,
            blinding,
            &witness.witness,
            &self.accumulator_value,
        ));
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol
            .as_ref()
            .unwrap()
            .challenge_contribution(&self.accumulator_value, writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution<E: Pairing<G1Affine = G>>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge)?;
        Ok(StatementProof::VBAccumulatorMembershipKV(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &MembershipProof<G>,
    ) -> Result<(), ProofSystemError> {
        proof
            .verify_schnorr_proof(&self.accumulator_value, challenge)
            .map_err(|e| ProofSystemError::VBAccumProofContributionFailed(self.id as u32, e))
    }

    pub fn verify_full_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &MembershipProof<G>,
        secret_key: &SecretKey<G::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        proof
            .verify(&self.accumulator_value, secret_key, challenge)
            .map_err(|e| ProofSystemError::VBAccumProofContributionFailed(self.id as u32, e))
    }
}
