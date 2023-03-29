use alloc::vec::Vec;
use ark_ec::pairing::Pairing;
use ark_serialize::*;

use serde::{Deserialize, Serialize};
use utils::try_iter::InvalidPair;

use crate::{
    helpers::{
        pluck_missed, seq_pairs_satisfy, take_while_satisfy, DoubleEndedExactSizeIterator,
        SendIfParallel, WithSchnorrResponse,
    },
    setup::SignatureParams,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::*;

/// Proof of knowledge for the messages.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MessagesPoK<E: Pairing> {
    /// `com = g * o + \sum_{i}(h_{i} * m_{i})`
    pub(super) com_resp: WithSchnorrResponse<E::G1Affine, MultiMessageCommitment<E>>,
    /// `com_{j} = g * o_{j} + h * m_{j}`
    pub(super) com_j_resp: Vec<WithSchnorrResponse<E::G1Affine, MessageCommitment<E>>>,
}

impl<E: Pairing> MessagesPoK<E> {
    /// Verifies underlying proof of knowledge using supplied arguments.
    /// `unique_sorted_revealed_indices` must produce sorted unique indices, otherwise, an error will be returned.
    pub fn verify<I>(
        &self,
        challenge: &E::ScalarField,
        unique_sorted_revealed_indices: I,
        params: &SignatureParams<E>,
        h: &E::G1Affine,
    ) -> Result<()>
    where
        I: IntoIterator<Item = usize> + SendIfParallel,
    {
        let (eq_res, com_res, com_j_res) = join!(
            // Verify equality of the corresponding Schnorr responses for `m_{i}` in both commitments
            self.verify_responses(),
            // Verify relation `com = g * o + \sum_{i}(h_{i} * m_{i})`
            self.verify_com(challenge, unique_sorted_revealed_indices, params),
            // Verify relation `com_{j} = g * o_{j} + h * m_{j}`
            self.verify_com_j(challenge, params, h)
        );

        eq_res.and(com_res).and(com_j_res)
    }

    /// The commitment's contribution to the overall challenge of the protocol.
    pub fn challenge_contribution<W: Write>(
        &self,
        mut writer: W,
        &SignatureParams {
            g, h: ref h_arr, ..
        }: &SignatureParams<E>,
        h: &E::G1Affine,
    ) -> Result<(), SchnorrError> {
        // `com = g * o + \sum_{i}(h_{i} * m_{i})`
        g.serialize_compressed(&mut writer)?;
        h_arr.serialize_compressed(&mut writer)?;
        self.com_resp.challenge_contribution(&mut writer)?;

        // `com_{j} = g * o_{j} + h * m_{j}`
        h.serialize_compressed(&mut writer)?;
        for com_j in &self.com_j_resp {
            com_j.challenge_contribution(&mut writer)?;
        }

        Ok(())
    }

    /// Returns underlying message commitments.
    pub fn commitments(
        &self,
    ) -> impl DoubleEndedExactSizeIterator<Item = &MessageCommitment<E>> + Clone + '_ {
        self.com_j_resp.iter().map(|resp| &resp.value)
    }

    /// Verifies equality of the corresponding Schnorr responses for `m_{i}` in both commitments.
    fn verify_responses(&self) -> Result<()> {
        if self.com_resp.response.0.len() != self.com_j_resp.len() + 1 {
            Err(MessagesPoKError::SchnorrResponsesHaveDifferentLength)?
        }

        let m_i_resp = cfg_iter!(self.com_resp.response.0).skip(1).map(Some);
        let m_j_resp = cfg_iter!(self.com_j_resp).map(|resp| resp.response.0.get(1));

        #[cfg(feature = "parallel")]
        let find_map = ParallelIterator::find_map_any;
        #[cfg(not(feature = "parallel"))]
        let find_map = |mut iter, f| Iterator::find_map(&mut iter, f);

        let invalid_idx = find_map(
            m_i_resp.zip(m_j_resp).enumerate(),
            |(idx, (m_i_resp, m_j_resp))| (m_i_resp != m_j_resp).then_some(idx),
        );

        if let Some(idx) = invalid_idx {
            Err(MessagesPoKError::SchnorrResponsesNotEqual(idx))
        } else {
            Ok(())
        }
    }

    /// Verifies relation `com = g * o + \sum_{i}(h_{i} * m_{i})`
    fn verify_com(
        &self,
        challenge: &E::ScalarField,
        unique_sorted_revealed_indices: impl IntoIterator<Item = usize>,
        SignatureParams { g, h, .. }: &SignatureParams<E>,
    ) -> Result<()> {
        // This option may contain an invalid pair of previous - current indices at the end of the iteration
        let mut invalid_idx_pair = None;
        // Pick only committed `h` using supplied indices of the revealed messages
        let committed_h = pluck_missed(
            take_while_satisfy(
                unique_sorted_revealed_indices,
                seq_pairs_satisfy(|a, b| a < b),
                &mut invalid_idx_pair,
            ),
            h,
        );
        let verification_res = self
            .com_resp
            .verify_challenge(challenge, g, committed_h)
            .map_err(schnorr_error)
            .map_err(MessagesPoKError::InvalidComProof);

        if let Some(InvalidPair(previous, current)) = invalid_idx_pair {
            Err(MessagesPoKError::RevealedIndicesMustBeUniqueAndSorted { previous, current })
        } else {
            verification_res
        }
    }

    /// Verifies relation `com_{j} = g * o_{j} + h * m_{j}`
    fn verify_com_j(
        &self,
        challenge: &E::ScalarField,
        SignatureParams { g, .. }: &SignatureParams<E>,
        h: &E::G1Affine,
    ) -> Result<()> {
        cfg_iter!(self.com_j_resp)
            .enumerate()
            .map(|(index, com_j)| {
                com_j
                    .verify_challenge(challenge, g, h)
                    .map_err(schnorr_error)
                    .map_err(|error| MessagesPoKError::InvalidComJProof { index, error })
            })
            .collect()
    }
}
