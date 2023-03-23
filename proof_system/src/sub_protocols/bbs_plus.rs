use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::rand::RngCore;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    vec::Vec,
};
use bbs_plus::prelude::{
    PoKOfSignatureG1Proof, PreparedPublicKeyG2, PreparedSignatureParamsG1, PublicKeyG2,
    SignatureParamsG1,
};
use bbs_plus::proof::PoKOfSignatureG1Protocol;
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

use crate::error::ProofSystemError;
use crate::statement_proof::StatementProof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoKBBSSigG1SubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
    pub signature_params: &'a SignatureParamsG1<E>,
    pub public_key: &'a PublicKeyG2<E>,
    pub protocol: Option<PoKOfSignatureG1Protocol<E>>,
}

impl<'a, E: Pairing> PoKBBSSigG1SubProtocol<'a, E> {
    pub fn new(
        id: usize,
        revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
        signature_params: &'a SignatureParamsG1<E>,
        public_key: &'a PublicKeyG2<E>,
    ) -> Self {
        Self {
            id,
            revealed_messages,
            signature_params,
            public_key,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blindings: BTreeMap<usize, E::ScalarField>,
        mut witness: crate::witness::PoKBBSSignatureG1<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        // Create messages from revealed messages in statement and unrevealed in witness
        let mut messages = Vec::with_capacity(self.signature_params.supported_message_count());
        let mut revealed_indices = BTreeSet::new();
        for i in 0..self.signature_params.supported_message_count() {
            if witness.unrevealed_messages.contains_key(&i) {
                messages.push(witness.unrevealed_messages.remove(&i).unwrap());
            } else if self.revealed_messages.contains_key(&i) {
                revealed_indices.insert(i);
                messages.push(*self.revealed_messages.get(&i).unwrap());
            } else {
                return Err(ProofSystemError::BBSPlusProtocolMessageAbsent(self.id, i));
            }
        }
        let protocol = PoKOfSignatureG1Protocol::init(
            rng,
            &witness.signature,
            self.signature_params,
            &messages,
            blindings,
            revealed_indices,
        )?;
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
            self.revealed_messages,
            self.signature_params,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<G: AffineRepr>(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge)?;
        Ok(StatementProof::PoKBBSSignatureG1(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &PoKOfSignatureG1Proof<E>,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParamsG1<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                self.revealed_messages,
                challenge,
                pk,
                params,
                c,
            )?,
            None => proof.verify(self.revealed_messages, challenge, pk, params)?,
        }
        Ok(())
    }
}
