use alloc::vec::Vec;
use ark_ec::pairing::Pairing;
use ark_serialize::*;
use serde::{Deserialize, Serialize};
use utils::{
    join, misc::seq_pairs_satisfy, randomized_pairing_check::RandomizedPairingChecker,
    try_iter::InvalidPair,
};

use crate::{
    helpers::{pluck_missed, take_while_satisfy, SendIfParallel, WithSchnorrResponse},
    setup::{PreparedPublicKey, PreparedSignatureParams},
};

use super::*;

/// Proof of knowledge for the signature.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SignaturePoK<E: Pairing> {
    /// `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`.
    pub(super) k: WithSchnorrResponse<E::G2Affine, K<E>>,
    pub(super) randomized_sig: RandomizedSignature<E>,
}

impl<E: Pairing> SignaturePoK<E> {
    /// Verifies underlying proof of knowledge using supplied arguments.
    /// `indexed_revealed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
    /// an error will be returned.
    pub fn verify<'a, I>(
        &self,
        challenge: &E::ScalarField,
        indexed_revealed_messages_sorted_by_index: I,
        pk: &PublicKey<E>,
        params: &SignatureParams<E>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        I::IntoIter: Clone + SendIfParallel,
    {
        let revealed_messages = indexed_revealed_messages_sorted_by_index.into_iter();
        let revealed_indices = revealed_messages.clone().map(|(idx, _)| idx);

        let (sig_res, proof_res) = join!(
            // Verify randomized signature
            self.randomized_sig
                .verify(revealed_messages, &self.k.value, pk, params)
                .map_err(SignaturePoKError::SignatureError),
            // Verify that `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
            self.verify_response(challenge, revealed_indices, pk, params)
        );

        proof_res.and(sig_res)
    }

    /// The commitment's contribution to the overall challenge of the protocol.
    pub fn challenge_contribution<W: Write>(
        &self,
        mut writer: W,
        PublicKey { beta_tilde, .. }: &PublicKey<E>,
        SignatureParams { g, .. }: &SignatureParams<E>,
    ) -> Result<(), SchnorrError> {
        beta_tilde
            .serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;
        g.serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;

        self.k.challenge_contribution(&mut writer)
    }

    /// Get the response from post-challenge phase of the Schnorr protocol for the given
    /// message index `msg_idx`. Used when comparing message equality.
    pub fn response_for_message<I>(
        &self,
        msg_idx: usize,
        unique_sorted_revealed_msg_ids: I,
    ) -> Result<&E::ScalarField>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut invalid_idx_pair = None;
        let unique_sorted_msg_ids = take_while_satisfy(
            unique_sorted_revealed_msg_ids,
            seq_pairs_satisfy(|a, b| a < b),
            &mut invalid_idx_pair,
        );

        let res = self
            .k
            .response_for_message(msg_idx, unique_sorted_msg_ids)
            .map_err(schnorr_error)
            .map_err(SignaturePoKError::SchnorrError);

        if let Some(InvalidPair(previous, current)) = invalid_idx_pair {
            Err(SignaturePoKError::RevealedIndicesMustBeUniqueAndSorted { previous, current })
        } else {
            res
        }
    }

    /// Verifies `self` using provided `RandomizedPairingChecker`.
    pub fn verify_with_randomized_pairing_checker<'a, MI>(
        &self,
        challenge: &E::ScalarField,
        indexed_revealed_messages_sorted_by_index: MI,
        pk: &PreparedPublicKey<E>,
        params: &PreparedSignatureParams<E>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<()>
    where
        MI: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        MI::IntoIter: Clone + SendIfParallel,
    {
        let revealed_messages = indexed_revealed_messages_sorted_by_index.into_iter();
        let revealed_indices = revealed_messages.clone().map(|(idx, _)| idx);

        let (resp_res, pairing_res) = join!(
            self.verify_response(challenge, revealed_indices, pk, params),
            RandomizedSignature::<E>::prepare_pairing_values(
                revealed_messages,
                &self.k.value,
                pk,
                params,
            )
            .map_err(SignaturePoKError::SignatureError)
        );

        let (p1, p2) = resp_res.and(pairing_res)?;
        let (sigma_1, sigma_2) = self.randomized_sig.split();

        pairing_checker.add_sources(&sigma_1, p1, &sigma_2, p2);

        Ok(())
    }

    /// Verifies that `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
    fn verify_response<I>(
        &self,
        challenge: &E::ScalarField,
        sorted_unique_revealed_indices: I,
        pk: &PublicKey<E>,
        params: &SignatureParams<E>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = usize>,
    {
        // This option may contain an invalid pair of previous - current indices at the end of the iteration
        let mut invalid_idx_pair = None;
        // Pick only committed `beta_tilde` using supplied indices of the revealed messages
        let committed_beta_tilde = pluck_missed(
            take_while_satisfy(
                sorted_unique_revealed_indices,
                seq_pairs_satisfy(|a, b| a < b),
                &mut invalid_idx_pair,
            ),
            &pk.beta_tilde,
        );

        let verification_res = self
            .k
            .verify_challenge(challenge, committed_beta_tilde, &params.g_tilde)
            .map_err(schnorr_error)
            .map_err(SignaturePoKError::SchnorrError);

        if let Some(InvalidPair(previous, current)) = invalid_idx_pair {
            Err(SignaturePoKError::RevealedIndicesMustBeUniqueAndSorted { previous, current })
        } else {
            verification_res
        }
    }
}
