use super::ParticipantId;
use crate::{error::BBSPlusError, threshold::utils::compute_masked_arguments_to_multiply};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use digest::DynDigest;
use oblivious_transfer_protocols::{cointoss, zero_sharing};

/// This is the first phase of the signing protocol where parties generate random values, jointly and
/// individually including additive shares of 0.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<F: PrimeField, const SALT_SIZE: usize> {
    pub id: ParticipantId,
    /// Number of threshold signatures being generated in a single batch.
    pub batch_size: u32,
    /// Shares of the random `r`, one share for each item in the batch
    pub r: Vec<F>,
    /// Protocols to generate shares of random values used in signature like `e` for BBS and (`e`, `s`) for BBS+
    pub commitment_protocol: cointoss::Party<F, SALT_SIZE>,
    /// Protocols to generate shares of 0s.
    pub zero_sharing_protocol: zero_sharing::Party<F, SALT_SIZE>,
}

impl<F: PrimeField, const SALT_SIZE: usize> Phase1<F, SALT_SIZE> {
    pub fn get_comm_shares_and_salts(&self) -> Vec<(F, [u8; SALT_SIZE])> {
        self.commitment_protocol.own_shares_and_salts.clone()
    }

    pub fn get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(
        &self,
        other_id: &ParticipantId,
    ) -> Vec<(F, [u8; SALT_SIZE])> {
        // TODO: Remove unwrap
        self.zero_sharing_protocol
            .cointoss_protocols
            .get(other_id)
            .unwrap()
            .own_shares_and_salts
            .clone()
    }

    /// Process received commitments for joint randomness and zero sharing protocol
    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        comm: cointoss::Commitments,
        comm_zero_share: cointoss::Commitments,
    ) -> Result<(), BBSPlusError> {
        self.commitment_protocol
            .receive_commitment(sender_id, comm)?;
        self.zero_sharing_protocol
            .receive_commitment(sender_id, comm_zero_share)?;
        Ok(())
    }

    /// Process received shares for joint randomness and zero
    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares: Vec<(F, [u8; SALT_SIZE])>,
        zero_shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), BBSPlusError> {
        self.commitment_protocol.receive_shares(sender_id, shares)?;
        self.zero_sharing_protocol
            .receive_shares(sender_id, zero_shares)?;
        Ok(())
    }

    /// Computes joint randomness and masked arguments to multiply
    pub fn compute_randomness_and_arguments_for_multiplication<D: Default + DynDigest + Clone>(
        self,
        signing_key: &F,
    ) -> Result<(Vec<ParticipantId>, Vec<F>, Vec<F>, Vec<F>), BBSPlusError> {
        let others = self
            .commitment_protocol
            .other_shares
            .keys()
            .map(|p| *p)
            .collect::<Vec<_>>();
        let randomness = self.commitment_protocol.compute_joint_randomness();
        let zero_shares = self.zero_sharing_protocol.compute_zero_shares::<D>()?;
        let (masked_signing_key_share, masked_r) = compute_masked_arguments_to_multiply(
            signing_key,
            self.r,
            zero_shares,
            self.id,
            &others,
        )?;
        Ok((others, randomness, masked_signing_key_share, masked_r))
    }

    pub fn ready_to_compute_randomness_and_arguments_for_multiplication(&self) -> bool {
        self.commitment_protocol.has_shares_from_all_who_committed()
            && self
                .zero_sharing_protocol
                .has_shares_from_all_who_committed()
    }
}
