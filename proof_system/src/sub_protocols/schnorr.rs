use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec::Vec, UniformRand};
use schnorr_pok::{SchnorrChallengeContributor, SchnorrCommitment};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::ProofSystemError,
    statement_proof::{PedersenCommitmentProof, StatementProof},
};

use schnorr_pok::error::SchnorrError;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SchnorrProtocol<'a, G: AffineRepr> {
    #[zeroize(skip)]
    pub id: usize,
    #[zeroize(skip)]
    pub commitment_key: &'a [G],
    #[zeroize(skip)]
    pub commitment: G,
    pub commitment_to_randomness: Option<SchnorrCommitment<G>>,
    pub witnesses: Option<Vec<G::ScalarField>>,
}

impl<'a, G: AffineRepr> SchnorrProtocol<'a, G> {
    pub fn new(id: usize, commitment_key: &'a [G], commitment: G) -> Self {
        Self {
            id,
            commitment_key,
            commitment,
            commitment_to_randomness: None,
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
        if self.commitment_to_randomness.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let blindings = (0..witnesses.len())
            .map(|i| {
                blindings
                    .remove(&i)
                    .unwrap_or_else(|| G::ScalarField::rand(rng))
            })
            .collect::<Vec<_>>();
        self.commitment_to_randomness =
            Some(SchnorrCommitment::new(self.commitment_key, blindings));
        self.witnesses = Some(witnesses);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.commitment_to_randomness.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.commitment_key.serialize_compressed(&mut writer)?;
        self.commitment.serialize_compressed(&mut writer)?;
        self.commitment_to_randomness
            .as_ref()
            .unwrap()
            .challenge_contribution(writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution<E: Pairing<G1Affine = G>>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        Ok(StatementProof::PedersenCommitment(
            self.gen_proof_contribution_as_struct(challenge)?,
        ))
    }

    pub fn gen_proof_contribution_g2<E: Pairing<G2Affine = G>>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        Ok(StatementProof::PedersenCommitmentG2(
            self.gen_proof_contribution_as_struct(challenge)?,
        ))
    }

    pub fn gen_proof_contribution_as_struct(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<PedersenCommitmentProof<G>, ProofSystemError> {
        if self.commitment_to_randomness.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let commitment = self.commitment_to_randomness.take().unwrap();
        let responses = commitment.response(self.witnesses.as_ref().unwrap(), challenge)?;
        Ok(PedersenCommitmentProof::new(commitment.t, responses))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &PedersenCommitmentProof<G>,
    ) -> Result<(), SchnorrError> {
        proof
            .response
            .is_valid(self.commitment_key, &self.commitment, &proof.t, challenge)
    }

    pub fn compute_challenge_contribution<W: Write>(
        bases: &[G],
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        bases.serialize_compressed(&mut writer)?;
        y.serialize_compressed(&mut writer)?;
        t.serialize_compressed(writer)?;
        Ok(())
    }
}
