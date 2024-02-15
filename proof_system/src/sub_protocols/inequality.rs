use crate::{
    error::ProofSystemError,
    statement_proof::{InequalityProof, StatementProof},
    sub_protocols::schnorr::SchnorrProtocol,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec, UniformRand};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use schnorr_pok::inequality::DiscreteLogInequalityProtocol;

#[derive(Clone, Debug, PartialEq)]
pub struct InequalityProtocol<'a, G: AffineRepr> {
    pub id: usize,
    /// The public value with which the inequalty is being proven
    pub inequal_to: G::ScalarField,
    pub comm_key: &'a PedersenCommitmentKey<G>,
    pub comm: Option<G>,
    pub inequality_protocol: Option<DiscreteLogInequalityProtocol<G>>,
    pub sp: Option<SchnorrProtocol<'a, G>>,
}

impl<'a, G: AffineRepr> InequalityProtocol<'a, G> {
    pub fn new(
        id: usize,
        inequal_to: G::ScalarField,
        comm_key: &'a PedersenCommitmentKey<G>,
    ) -> Self {
        Self {
            id,
            inequal_to,
            comm_key,
            comm: None,
            inequality_protocol: None,
            sp: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key_as_slice: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let randomness = G::ScalarField::rand(rng);
        let comm = self.comm_key.commit(&message, &randomness);
        self.inequality_protocol = Some(
            DiscreteLogInequalityProtocol::new_for_inequality_with_public_value(
                rng,
                message,
                randomness,
                &comm,
                &self.inequal_to,
                &self.comm_key,
            )?,
        );
        self.comm = Some(comm);
        self.init_schnorr_protocol(rng, comm_key_as_slice, message, blinding, randomness)
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
        blinding_for_ineqality_protocol_commitment: G::ScalarField,
    ) -> Result<(), ProofSystemError> {
        let blinding = if blinding.is_none() {
            G::ScalarField::rand(rng)
        } else {
            blinding.unwrap()
        };
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);

        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, &comm_key, self.comm.unwrap());
        sp.init(
            rng,
            blindings.clone(),
            vec![message, blinding_for_ineqality_protocol_commitment],
        )?;
        self.sp = Some(sp);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.inequality_protocol
            .as_ref()
            .unwrap()
            .challenge_contribution_for_public_inequality(
                self.comm.as_ref().unwrap(),
                &self.inequal_to,
                &self.comm_key,
                &mut writer,
            )?;
        self.sp
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution<E: Pairing<G1Affine = G>>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let proof = self
            .inequality_protocol
            .take()
            .unwrap()
            .gen_proof(challenge);
        Ok(StatementProof::Inequality(InequalityProof {
            proof,
            comm: self.comm.take().unwrap(),
            sp: self
                .sp
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &InequalityProof<G>,
        comm_key_as_slice: &[G],
    ) -> Result<(), ProofSystemError> {
        proof
            .proof
            .verify_for_inequality_with_public_value(
                &proof.comm,
                &self.inequal_to,
                challenge,
                &self.comm_key,
            )
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))?;
        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key_as_slice, proof.comm);

        sp.verify_proof_contribution(challenge, &proof.sp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key_as_slice: &[G],
        proof: &InequalityProof<G>,
        inequal_to: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        proof.proof.challenge_contribution_for_public_inequality(
            &proof.comm,
            inequal_to,
            comm_key,
            &mut writer,
        )?;
        comm_key_as_slice.serialize_compressed(&mut writer)?;
        proof.comm.serialize_compressed(&mut writer)?;
        proof.sp.t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}
