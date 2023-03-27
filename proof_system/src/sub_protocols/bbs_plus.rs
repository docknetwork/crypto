use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore};
use bbs_plus::{
    prelude::{
        PoKOfSignatureG1Proof, PreparedPublicKeyG2, PreparedSignatureParamsG1, PublicKeyG2,
        SignatureParamsG1,
    },
    proof::{MessageOrBlinding, PoKOfSignatureG1Protocol},
};
use coconut_crypto::helpers::{check_seq_from, take_while_pairs_satisfy, CheckLeft};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use itertools::{EitherOrBoth, Itertools};

use crate::{error::ProofSystemError, statement_proof::StatementProof};

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
        witness: crate::witness::PoKBBSSignatureG1<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let total_message_count = self.revealed_messages.len() + witness.unrevealed_messages.len();
        if total_message_count != self.signature_params.supported_message_count() {
            Err(ProofSystemError::PSProtocolInvalidMessageCount(
                total_message_count,
                self.signature_params.supported_message_count(),
            ))?
        }

        // Create messages from revealed messages in statement and unrevealed in witness
        let mut invalid_blinding_idx = None;
        let messages_to_commit_with_blindings = witness
            .unrevealed_messages
            .iter()
            .merge_join_by(blindings, |(&m_idx, _), (b_idx, _)| m_idx.cmp(b_idx))
            .scan((), |(), either| {
                let item = match either {
                    EitherOrBoth::Left((idx, msg)) => {
                        (*idx, MessageOrBlinding::BlindMessageRandomly(msg))
                    }
                    EitherOrBoth::Both((idx, message), (_, blinding)) => (
                        *idx,
                        MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding },
                    ),
                    EitherOrBoth::Right((idx, _)) => {
                        invalid_blinding_idx.replace(idx);

                        return None;
                    }
                };

                Some(item)
            });

        let revealed_messages = self
            .revealed_messages
            .iter()
            .map(|(idx, msg)| (*idx, MessageOrBlinding::RevealMessage(msg)));

        let mut invalid_message_idx = None;
        let all_messages = take_while_pairs_satisfy(
            messages_to_commit_with_blindings.merge_by(revealed_messages, |(a, _), (b, _)| a <= b),
            CheckLeft(check_seq_from(0)),
            &mut invalid_message_idx,
        )
        .map(|(_, message)| message);

        let protocol = PoKOfSignatureG1Protocol::init(
            rng,
            &witness.signature,
            self.signature_params,
            all_messages,
        );
        if let Some(idx) = invalid_blinding_idx {
            Err(ProofSystemError::BBSProtocolInvalidBlindingIndex(idx))?
        } else if let Some((prev, cur)) = invalid_message_idx {
            Err(ProofSystemError::BBSProtocolInvalidMessageIndex(prev, cur))?
        }

        self.protocol = Some(protocol?);
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
