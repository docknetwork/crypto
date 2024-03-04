use ark_ec::pairing::Pairing;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore};
use bbs_plus::{
    error::BBSPlusError,
    prelude::{
        PoKOfSignatureG1Proof, PreparedPublicKeyG2, PreparedSignatureParamsG1, PublicKeyG2,
        SignatureParamsG1,
    },
    proof::PoKOfSignatureG1Protocol,
};
use dock_crypto_utils::{
    expect_equality,
    iter::take_while_satisfy,
    misc::seq_inc_by_n_from,
    randomized_pairing_check::RandomizedPairingChecker,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
    try_iter::CheckLeft,
};
use itertools::Itertools;

use crate::{error::ProofSystemError, statement_proof::StatementProof};

use super::merge_indexed_messages_with_blindings;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoKBBSSigG1SubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
    pub signature_params: &'a SignatureParamsG1<E>,
    pub public_key: Option<&'a PublicKeyG2<E>>,
    pub protocol: Option<PoKOfSignatureG1Protocol<E>>,
}

#[macro_export]
macro_rules! impl_bbs_subprotocol {
    ($params: ident, $wit: ident, $protocol: ident, $stmt_proof: ident, $proof: ident, $prepared_params: ident) => {
        /// Create new protocol for prover
        pub fn new_for_prover(
            id: usize,
            revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
            signature_params: &'a $params<E>,
        ) -> Self {
            Self {
                id,
                revealed_messages,
                signature_params,
                public_key: None,
                protocol: None,
            }
        }

        /// Create new protocol for verifier.
        pub fn new_for_verifier(
            id: usize,
            revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
            signature_params: &'a $params<E>,
            public_key: &'a PublicKeyG2<E>,
        ) -> Self {
            Self {
                id,
                revealed_messages,
                signature_params,
                public_key: Some(public_key),
                protocol: None,
            }
        }

        pub fn init<R: RngCore>(
            &mut self,
            rng: &mut R,
            blindings: BTreeMap<usize, E::ScalarField>,
            witness: crate::witness::$wit<E>,
        ) -> Result<(), ProofSystemError> {
            if self.protocol.is_some() {
                return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
            }
            let total_message_count =
                self.revealed_messages.len() + witness.unrevealed_messages.len();
            expect_equality!(
                total_message_count,
                self.signature_params.supported_message_count(),
                ProofSystemError::BBSPlusProtocolInvalidMessageCount
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

            let protocol =
                $protocol::init(rng, &witness.signature, self.signature_params, all_messages);
            if let Some(idx) = invalid_blinding_idx {
                Err(ProofSystemError::SigProtocolInvalidBlindingIndex(idx))?
            } else if let Some(invalid) = non_seq_idx {
                Err(invalid.over(
                    ProofSystemError::SigProtocolMessageIndicesMustStartFromZero,
                    ProofSystemError::SigProtocolNonSequentialMessageIndices,
                ))?
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

        pub fn gen_proof_contribution(
            &mut self,
            challenge: &E::ScalarField,
        ) -> Result<StatementProof<E>, ProofSystemError> {
            if self.protocol.is_none() {
                return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                    self.id,
                ));
            }
            let protocol = self.protocol.take().unwrap();
            let proof = protocol.gen_proof(challenge)?;
            Ok(StatementProof::$stmt_proof(proof))
        }

        pub fn verify_proof_contribution(
            &self,
            challenge: &E::ScalarField,
            proof: &$proof<E>,
            pk: impl Into<PreparedPublicKeyG2<E>>,
            params: impl Into<$prepared_params<E>>,
            pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
        ) -> Result<(), BBSPlusError> {
            match pairing_checker {
                Some(c) => proof.verify_with_randomized_pairing_checker(
                    self.revealed_messages,
                    challenge,
                    pk,
                    params,
                    c,
                ),
                None => proof.verify(self.revealed_messages, challenge, pk, params),
            }
        }
    };
}

impl<'a, E: Pairing> PoKBBSSigG1SubProtocol<'a, E> {
    impl_bbs_subprotocol!(
        SignatureParamsG1,
        PoKBBSSignatureG1,
        PoKOfSignatureG1Protocol,
        PoKBBSSignatureG1,
        PoKOfSignatureG1Proof,
        PreparedSignatureParamsG1
    );
}
