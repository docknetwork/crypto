//! The multiplication phase of the threshold signing protocol of BBS and BBS+.

use crate::{error::BBSPlusError, threshold::base_ot_phase::BaseOTPhaseOutput};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use digest::DynDigest;
use dock_crypto_utils::transcript::Merlin;
use itertools::interleave;
use oblivious_transfer_protocols::{
    ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::{GadgetVector, MaskedInputs, Party1, Party2, RLC},
    },
    ot_extensions::kos_ote::{CorrelationTag, RLC as KOSRLC},
    BitMatrix, ParticipantId,
};

/// The participant will acts as
///     - a receiver in OT extension, also called Party2 in multiplication protocol, and its id is less than other participant
///     - a sender in OT extension, also called Party1 in multiplication protocol, and its id is greater than other participant
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub id: ParticipantId,
    /// Number of threshold signatures being generated in a single batch.
    pub batch_size: u64,
    /// Transcripts to record protocol interactions with each participant and later used to generate random challenges
    pub transcripts: BTreeMap<ParticipantId, Merlin>,
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    /// Map where this participant plays the role of sender, i.e Party1
    pub multiplication_party1:
        BTreeMap<ParticipantId, Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    /// Map where this participant plays the role of receiver, i.e Party2
    pub multiplication_party2:
        BTreeMap<ParticipantId, Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    pub z_A: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
    pub z_B: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
}

/// Message sent from Party2 to Party1 of multiplication protocol
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Message1<F: PrimeField>(BitMatrix, KOSRLC, MaskedInputs<F>);

/// Message sent from Party1 to Party2 of multiplication protocol. This message is created after Part1 processes `Message1`
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Message2<F: PrimeField>(CorrelationTag<F>, RLC<F>, MaskedInputs<F>);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2Output<F: PrimeField> {
    pub z_A: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
    pub z_B: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Phase2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        masked_signing_key_share: Vec<F>,
        masked_r: Vec<F>,
        mut base_ot_output: BaseOTPhaseOutput,
        others: BTreeSet<ParticipantId>,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), BBSPlusError> {
        assert_eq!(masked_signing_key_share.len(), masked_r.len());
        let batch_size = masked_signing_key_share.len() as u64;

        let mut transcripts = BTreeMap::<ParticipantId, Merlin>::new();
        let mut multiplication_party1 =
            BTreeMap::<ParticipantId, Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>::new();
        let mut multiplication_party2 =
            BTreeMap::<ParticipantId, Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>::new();
        let mut Us = BTreeMap::new();

        // When an OT extension receiver, generate input to multiplication as `[masked_signing_key_share[0], masked_r[0], masked_signing_key_share[1], masked_r[1]], masked_signing_key_share[2], masked_r[2], ...`
        let mult_when_ot_recv =
            interleave(masked_signing_key_share.clone(), masked_r.clone()).collect::<Vec<_>>();
        // When an OT extension sender, generate input to multiplication as `[masked_r[0], masked_signing_key_share[0], masked_r[1], masked_signing_key_share[1], masked_r[2], masked_signing_key_share[2], ...`
        let mult_when_ot_sendr =
            interleave(masked_r.clone(), masked_signing_key_share.clone()).collect::<Vec<_>>();

        for other in others {
            let mut trans = Merlin::new(b"Multiplication phase for threshold BBS and BBS+");
            if id > other {
                if let Some((base_ot_choices, base_ot_keys)) =
                    base_ot_output.receiver.remove(&other)
                {
                    let party1 = Party1::new(
                        rng,
                        mult_when_ot_recv.clone(),
                        base_ot_choices,
                        base_ot_keys,
                        ote_params,
                    )?;
                    multiplication_party1.insert(other, party1);
                } else {
                    return Err(BBSPlusError::MissingOTReceiverFor(other));
                }
            } else {
                if let Some(base_ot_keys) = base_ot_output.sender_keys.remove(&other) {
                    let (party2, U, rlc, gamma) = Party2::new(
                        rng,
                        mult_when_ot_sendr.clone(),
                        base_ot_keys,
                        &mut trans,
                        ote_params,
                        &gadget_vector,
                    )?;
                    multiplication_party2.insert(other, party2);
                    Us.insert(other, Message1(U, rlc, gamma));
                } else {
                    return Err(BBSPlusError::MissingOTSenderFor(other));
                }
            }
            transcripts.insert(other, trans);
        }
        Ok((
            Self {
                id,
                batch_size,
                transcripts,
                ote_params,
                multiplication_party1,
                multiplication_party2,
                z_A: Default::default(),
                z_B: Default::default(),
            },
            Us,
        ))
    }

    /// Process received message from Party2 of multiplication protocol
    pub fn receive_message1<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message1<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Message2<F>, BBSPlusError> {
        if self.multiplication_party2.contains_key(&sender_id) {
            return Err(BBSPlusError::NotAMultiplicationParty2(sender_id));
        }
        if !self.multiplication_party1.contains_key(&sender_id) {
            return Err(BBSPlusError::NotAMultiplicationParty1(sender_id));
        }
        let Message1(U, rlc, gamma) = message;
        let party1 = self.multiplication_party1.remove(&sender_id).unwrap();
        let trans = self.transcripts.get_mut(&sender_id).unwrap();

        let (shares, tau, r, gamma_a) =
            party1.receive::<D>(U, rlc, gamma, trans, &gadget_vector)?;
        debug_assert_eq!(shares.len() as u64, 2 * self.batch_size);
        let mut z_A_0 = Vec::with_capacity(self.batch_size as usize);
        let mut z_A_1 = Vec::with_capacity(self.batch_size as usize);
        for (i, share) in shares.0.into_iter().enumerate() {
            if (i & 1) == 0 {
                z_A_0.push(share);
            } else {
                z_A_1.push(share);
            }
        }
        self.z_A.insert(sender_id, (z_A_0, z_A_1));
        Ok(Message2(tau, r, gamma_a))
    }

    /// Process received message from Party1 of multiplication protocol
    pub fn receive_message2<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message2<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(), BBSPlusError> {
        if self.multiplication_party1.contains_key(&sender_id) {
            return Err(BBSPlusError::NotAMultiplicationParty1(sender_id));
        }
        if !self.multiplication_party2.contains_key(&sender_id) {
            return Err(BBSPlusError::NotAMultiplicationParty2(sender_id));
        }
        let Message2(tau, rlc, gamma) = message;
        let party2 = self.multiplication_party2.remove(&sender_id).unwrap();
        let trans = self.transcripts.get_mut(&sender_id).unwrap();
        let shares = party2.receive::<D>(tau, rlc, gamma, trans, &gadget_vector)?;
        debug_assert_eq!(shares.len() as u64, 2 * self.batch_size);
        let mut z_B_0 = Vec::with_capacity(self.batch_size as usize);
        let mut z_B_1 = Vec::with_capacity(self.batch_size as usize);
        for (i, share) in shares.0.into_iter().enumerate() {
            if (i & 1) == 0 {
                z_B_0.push(share);
            } else {
                z_B_1.push(share);
            }
        }
        self.z_B.insert(sender_id, (z_B_0, z_B_1));
        Ok(())
    }

    pub fn finish(self) -> Phase2Output<F> {
        Phase2Output {
            z_A: self.z_A,
            z_B: self.z_B,
        }
    }
}
