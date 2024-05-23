//! The multiplication phase of the threshold signing protocol of BBS and BBS+.

use super::ParticipantId;
use crate::error::BBSPlusError;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use digest::DynDigest;
use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput,
    batch_mul_multi_party::{
        Message1, Message2, Participant as MultiplicationParty,
        ParticipantOutput as MultiplicationPartyOutput,
    },
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>(
    pub MultiplicationParty<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2Output<F: PrimeField>(pub MultiplicationPartyOutput<F>);

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Phase2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        masked_signing_key_share: Vec<F>,
        masked_r: Vec<F>,
        base_ot_output: BaseOTOutput,
        others: BTreeSet<ParticipantId>,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), BBSPlusError> {
        let (p, m) = MultiplicationParty::init(
            rng,
            id,
            masked_signing_key_share,
            masked_r,
            base_ot_output,
            others,
            ote_params,
            gadget_vector,
            b"Multiplication phase for threshold BBS and BBS+",
        )?;
        Ok((Self(p), m))
    }

    /// Process received message from Party2 of multiplication protocol
    pub fn receive_message1<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message1<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Message2<F>, BBSPlusError> {
        let m = self
            .0
            .receive_message1::<D>(sender_id, message, gadget_vector)?;
        Ok(m)
    }

    /// Process received message from Party1 of multiplication protocol
    pub fn receive_message2<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message2<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(), BBSPlusError> {
        self.0
            .receive_message2::<D>(sender_id, message, gadget_vector)?;
        Ok(())
    }

    pub fn finish(self) -> Phase2Output<F> {
        Phase2Output(self.0.finish())
    }
}
