//! A multi-party multiplication protocol based on 2-party multiplication from DKLS19.
//! This assumes that each party has already run an OT protocol with other.
//! This is described as part of protocol 4.1 of the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)

use crate::{
    error::OTError,
    ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput,
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::{GadgetVector, MaskedInputs, Party1, Party2, RLC},
    },
    ot_extensions::kos_ote::CorrelationTag,
    BitMatrix, ParticipantId,
};
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

/// The participant will acts as
///     - a receiver in OT extension, also called Party2 in multiplication protocol, and its id is less than other participant
///     - a sender in OT extension, also called Party1 in multiplication protocol, and its id is greater than other participant
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Participant<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub id: ParticipantId,
    /// Number of multiplications done in a single batch.
    pub batch_size: u32,
    /// Transcripts to record protocol interactions with each participant and later used to generate random challenges
    pub transcripts: BTreeMap<ParticipantId, MerlinTranscript>,
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    /// Map where this participant plays the role of sender, i.e. Party1
    pub multiplication_party1:
        BTreeMap<ParticipantId, Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    /// Map where this participant plays the role of receiver, i.e. Party2
    pub multiplication_party2:
        BTreeMap<ParticipantId, Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>,
    pub z_A: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
    pub z_B: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
}

/// Message sent from Party2 to Party1 of multiplication protocol
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Message1<F: PrimeField>(
    BitMatrix,
    crate::ot_extensions::kos_ote::RLC,
    MaskedInputs<F>,
);

/// Message sent from Party1 to Party2 of multiplication protocol. This message is created after Party1 processes `Message1`
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Message2<F: PrimeField>(pub CorrelationTag<F>, RLC<F>, MaskedInputs<F>);

/// A participant's output on completion of the multiplication protocol
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ParticipantOutput<F: PrimeField> {
    pub z_A: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
    pub z_B: BTreeMap<ParticipantId, (Vec<F>, Vec<F>)>,
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Participant<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        x: Vec<F>,
        y: Vec<F>,
        mut base_ot_output: BaseOTOutput,
        others: BTreeSet<ParticipantId>,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &'static [u8],
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), OTError> {
        assert_eq!(x.len(), y.len());
        let batch_size = x.len() as u32;

        let mut transcripts = BTreeMap::<ParticipantId, MerlinTranscript>::new();
        let mut multiplication_party1 =
            BTreeMap::<ParticipantId, Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>::new();
        let mut multiplication_party2 =
            BTreeMap::<ParticipantId, Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>>::new();
        let mut Us = BTreeMap::new();

        // When an OT extension receiver, generate input to multiplication as `[x[0], y[0], x[1], y[1], x[2], y[2], ...`
        let mult_when_ot_recv = interleave(x.clone(), y.clone()).collect::<Vec<_>>();
        // When an OT extension sender, generate input to multiplication as `[y[0], x[0], y[1], x[1], y[2], x[2], ...`
        let mult_when_ot_sendr = interleave(y.clone(), x.clone()).collect::<Vec<_>>();

        for other in others {
            let mut trans = MerlinTranscript::new(label);
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
                    return Err(OTError::MissingOTReceiverFor(other));
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
                    return Err(OTError::MissingOTSenderFor(other));
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
    ) -> Result<Message2<F>, OTError> {
        if self.multiplication_party2.contains_key(&sender_id) {
            return Err(OTError::NotAMultiplicationParty2(sender_id));
        }
        if !self.multiplication_party1.contains_key(&sender_id) {
            return Err(OTError::NotAMultiplicationParty1(sender_id));
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
    ) -> Result<(), OTError> {
        if self.multiplication_party1.contains_key(&sender_id) {
            return Err(OTError::NotAMultiplicationParty1(sender_id));
        }
        if !self.multiplication_party2.contains_key(&sender_id) {
            return Err(OTError::NotAMultiplicationParty2(sender_id));
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

    pub fn finish(self) -> ParticipantOutput<F> {
        ParticipantOutput {
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

    use crate::ot_based_multiplication::{
        base_ot_multi_party_pairwise::tests::do_pairwise_base_ot,
        dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
    };
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn multi_party_multiplication() {
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
            let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
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

            let label = b"mutliparty multiplication";
            // Initiate multiplication phase and each party sends messages to others
            let start = Instant::now();
            for i in 1..=threshold {
                let mut others = threshold_party_set.clone();
                others.remove(&i);
                // Create 2 random vectors whose elements will be multiplied pairwise
                let a = (0..batch_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let b = (0..batch_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let start = Instant::now();
                let (phase, U) = Participant::init(
                    rng,
                    i,
                    a.clone(),
                    b.clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    others,
                    ote_params,
                    &gadget_vector,
                    label,
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
                    assert_eq!(z_A.0.len() as u32, batch_size);
                    assert_eq!(z_B.0.len() as u32, batch_size);
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
