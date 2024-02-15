use crate::{
    error::ProofSystemError, statement_proof::StatementProof,
    sub_protocols::merge_indexed_messages_with_blindings,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore};
use dock_crypto_utils::{
    expect_equality,
    iter::take_while_satisfy,
    misc::seq_inc_by_n_from,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
    try_iter::CheckLeft,
};
use itertools::Itertools;
use kvac::{
    bddt_2016::{
        proof_cdh::{PoKOfMAC, PoKOfMACProtocol},
        setup::{MACParams, SecretKey},
    },
    error::KVACError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoKOfMACSubProtocol<'a, G: AffineRepr> {
    pub id: usize,
    pub revealed_messages: &'a BTreeMap<usize, G::ScalarField>,
    pub mac_params: &'a MACParams<G>,
    pub protocol: Option<PoKOfMACProtocol<G>>,
}

impl<'a, G: AffineRepr> PoKOfMACSubProtocol<'a, G> {
    pub fn new(
        id: usize,
        revealed_messages: &'a BTreeMap<usize, G::ScalarField>,
        mac_params: &'a MACParams<G>,
    ) -> Self {
        Self {
            id,
            revealed_messages,
            mac_params,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blindings: BTreeMap<usize, G::ScalarField>,
        witness: crate::witness::PoKOfBDDT16MAC<G>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let total_message_count = self.revealed_messages.len() + witness.unrevealed_messages.len();
        expect_equality!(
            total_message_count,
            self.mac_params.supported_message_count(),
            ProofSystemError::BDDT16KVACProtocolInvalidMessageCount
        );

        // Create messages from revealed messages in statement and unrevealed in witness
        let mut invalid_blinding_idx = None;
        let messages_to_commit = merge_indexed_messages_with_blindings(
            &witness.unrevealed_messages,
            blindings,
            MessageOrBlinding::BlindMessageRandomly,
            MessageOrBlinding::blind_message_with,
            &mut invalid_blinding_idx,
        );
        let mut non_seq_idx = None;
        let all_messages = take_while_satisfy(
            messages_to_commit.merge_by(
                self.revealed_messages
                    .iter()
                    .map(|(idx, msg)| (*idx, MessageOrBlinding::RevealMessage(msg))),
                |(a, _), (b, _)| a < b,
            ),
            CheckLeft(seq_inc_by_n_from(1, 0)),
            &mut non_seq_idx,
        )
        .map(|(_, msg)| msg);

        let protocol = PoKOfMACProtocol::init(rng, &witness.mac, self.mac_params, all_messages)?;

        if let Some(idx) = invalid_blinding_idx {
            Err(ProofSystemError::SigProtocolInvalidBlindingIndex(idx))?
        } else if let Some(invalid) = non_seq_idx {
            Err(invalid.over(
                ProofSystemError::SigProtocolMessageIndicesMustStartFromZero,
                ProofSystemError::SigProtocolNonSequentialMessageIndices,
            ))?
        }

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
            self.mac_params,
            writer,
        )?;
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
        Ok(StatementProof::PoKOfBDDT16MAC(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &PoKOfMAC<G>,
    ) -> Result<(), KVACError> {
        proof.verify_schnorr_proofs(self.revealed_messages, challenge, &self.mac_params)
    }

    pub fn verify_full_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &PoKOfMAC<G>,
        secret_key: &SecretKey<G::ScalarField>,
    ) -> Result<(), KVACError> {
        proof.verify(
            self.revealed_messages,
            challenge,
            secret_key,
            &self.mac_params,
        )
    }
}
