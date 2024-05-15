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
use dock_crypto_utils::transcript::MerlinTranscript;
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
    pub batch_size: u32,
    /// Transcripts to record protocol interactions with each participant and later used to generate random challenges
    pub transcripts: BTreeMap<ParticipantId, MerlinTranscript>,
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
        let batch_size = masked_signing_key_share.len() as u32;

        let mut transcripts = BTreeMap::<ParticipantId, MerlinTranscript>::new();
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
            let mut trans =
                MerlinTranscript::new(b"Multiplication phase for threshold BBS and BBS+");
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
        debug_assert_eq!(shares.len() as u32, 2 * self.batch_size);
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
        debug_assert_eq!(shares.len() as u32, 2 * self.batch_size);
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use std::time::Instant;

    use crate::threshold::base_ot_phase::tests::do_base_ot_for_threshold_sig;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
    };

    #[test]
    fn multiplication_phase() {
        let mut rng = StdRng::seed_from_u64(0u64);
        const BASE_OT_KEY_SIZE: u16 = 128;
        const KAPPA: u16 = 256;
        const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        fn check(
            rng: &mut StdRng,
            ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
            threshold: u16,
            total: u16,
            batch_size: u32,
            gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        ) {
            let total_party_set = (1..=total).into_iter().collect::<BTreeSet<_>>();
            let threshold_party_set = (1..=threshold).into_iter().collect::<BTreeSet<_>>();

            // Run OT protocol instances. This is also a one time setup.
            let base_ot_outputs = do_base_ot_for_threshold_sig::<BASE_OT_KEY_SIZE>(
                rng,
                ote_params.num_base_ot(),
                total,
                total_party_set.clone(),
            );

            let mut mult_phase = vec![];
            let mut all_msg_1s = vec![];
            let total_time;
            let mut times = BTreeMap::new();
            let mut products = vec![];

            // Initiate multiplication phase and each party sends messages to others
            let start = Instant::now();
            for i in 1..=threshold {
                let start = Instant::now();
                let mut others = threshold_party_set.clone();
                others.remove(&i);
                let a = (0..batch_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let b = (0..batch_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let (phase, U) = Phase2::init(
                    rng,
                    i,
                    a.clone(),
                    b.clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    others,
                    ote_params,
                    &gadget_vector,
                )
                .unwrap();
                times.insert(i, start.elapsed());
                products.push((a, b));
                mult_phase.push(phase);
                all_msg_1s.push((i, U));
            }

            // Each party process messages received from others
            let mut all_msg_2s = vec![];
            for (sender_id, msg_1s) in all_msg_1s {
                for (receiver_id, m) in msg_1s {
                    let start = Instant::now();
                    let m2 = mult_phase[receiver_id as usize - 1]
                        .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                        .unwrap();
                    times.insert(
                        receiver_id,
                        *times.get(&receiver_id).unwrap() + start.elapsed(),
                    );
                    all_msg_2s.push((receiver_id, sender_id, m2));
                }
            }

            for (sender_id, receiver_id, m2) in all_msg_2s {
                let start = Instant::now();
                mult_phase[receiver_id as usize - 1]
                    .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                    .unwrap();
                times.insert(
                    receiver_id,
                    *times.get(&receiver_id).unwrap() + start.elapsed(),
                );
            }

            let mult_phase_outputs = mult_phase
                .into_iter()
                .map(|p| {
                    let start = Instant::now();
                    let i = p.id;
                    let o = p.finish();
                    times.insert(i, *times.get(&i).unwrap() + start.elapsed());
                    o
                })
                .collect::<Vec<_>>();
            total_time = start.elapsed();
            println!(
                "Multiplication of batch size {} among parties with threshold {} took {:?}",
                batch_size, threshold, total_time
            );

            // Check that multiplication works, i.e. each party has an additive share of
            // a multiplication with every other party
            for i in 1..=threshold {
                for (j, z_A) in &mult_phase_outputs[i as usize - 1].z_A {
                    let z_B = mult_phase_outputs[*j as usize - 1].z_B.get(&i).unwrap();
                    for k in 0..batch_size as usize {
                        assert_eq!(
                            z_A.0[k] + z_B.0[k],
                            products[i as usize - 1].0[k] * products[*j as usize - 1].1[k]
                        );
                        assert_eq!(
                            z_A.1[k] + z_B.1[k],
                            products[i as usize - 1].1[k] * products[*j as usize - 1].0[k]
                        );
                    }
                }
            }
        }

        check(&mut rng, ote_params, 5, 8, 1, &gadget_vector);
        check(&mut rng, ote_params, 5, 8, 10, &gadget_vector);
        check(&mut rng, ote_params, 5, 8, 20, &gadget_vector);
        check(&mut rng, ote_params, 5, 8, 30, &gadget_vector);
        check(&mut rng, ote_params, 10, 20, 10, &gadget_vector);
        check(&mut rng, ote_params, 20, 30, 10, &gadget_vector);
    }
}
