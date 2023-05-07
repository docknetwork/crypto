//! Each pair of participants must run a base OT among themselves and stores the OT receiver choices and
//! the output, i.e sender and receiver keys. This needs to be done only once unless they are lost or compromised.

use ark_ec::AffineRepr;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use oblivious_transfer::{
    base_ot::simplest_ot::{
        OneOfTwoROTSenderKeys, ROTReceiverKeys, ROTSenderSetup, ReceiverPubKeys, SenderPubKey,
    },
    configs::OTConfig,
    Bit, ParticipantId,
};

#[derive(Clone, Debug, PartialEq)]
pub struct BaseOTPhase<G: AffineRepr> {
    pub id: ParticipantId,
    /// Number of base OTs to perform
    pub count: u16,
    pub sender_setup: BTreeMap<ParticipantId, ROTSenderSetup<G>>,
    pub receiver_choices: BTreeMap<ParticipantId, Vec<Bit>>,
    pub sender_keys: BTreeMap<ParticipantId, OneOfTwoROTSenderKeys>,
    pub receiver_keys: BTreeMap<ParticipantId, ROTReceiverKeys>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BaseOTPhaseOutput {
    pub id: ParticipantId,
    pub sender_keys: BTreeMap<ParticipantId, OneOfTwoROTSenderKeys>,
    pub receiver: BTreeMap<ParticipantId, (Vec<Bit>, ROTReceiverKeys)>,
}

impl<G: AffineRepr> BaseOTPhase<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        num_base_ot: u16,
        B: &G,
    ) -> (Self, BTreeMap<ParticipantId, SenderPubKey<G>>) {
        // TODO: Do VSOT
        let mut base_ot_sender_setup = BTreeMap::new();
        let mut base_ot_receiver_choices = BTreeMap::new();
        let mut base_ot_s = BTreeMap::new();
        for other in others {
            if id < other {
                // TODO: Remove unwrap
                let (setup, S) =
                    ROTSenderSetup::new(rng, OTConfig::new_2_message(num_base_ot).unwrap(), B);
                base_ot_s.insert(other, S);
                base_ot_sender_setup.insert(other, setup);
            } else {
                let base_ot_choices = (0..num_base_ot)
                    .map(|_| (u8::rand(rng) % 2) != 0)
                    .collect::<Vec<_>>();
                base_ot_receiver_choices.insert(other, base_ot_choices);
            }
        }
        (
            Self {
                id,
                count: num_base_ot,
                sender_setup: base_ot_sender_setup,
                receiver_choices: base_ot_receiver_choices,
                sender_keys: Default::default(),
                receiver_keys: Default::default(),
            },
            base_ot_s,
        )
    }

    pub fn receive_s<R: RngCore, const KEY_SIZE: u16>(
        &mut self,
        rng: &mut R,
        sender_id: ParticipantId,
        S: SenderPubKey<G>,
        B: &G,
    ) -> ReceiverPubKeys<G> {
        debug_assert!(self.id >= sender_id);
        assert!(self.receiver_choices.contains_key(&sender_id));
        assert!(!self.receiver_keys.contains_key(&sender_id));
        let (receiver_keys, pub_key) = ROTReceiverKeys::new::<_, _, KEY_SIZE>(
            rng,
            OTConfig::new_2_message(self.count).unwrap(),
            self.receiver_choices
                .get(&sender_id)
                .unwrap()
                .into_iter()
                .map(|b| *b as u16)
                .collect(),
            S,
            B,
        )
        .unwrap();
        self.receiver_keys.insert(sender_id, receiver_keys);
        pub_key
    }

    pub fn receive_r<const KEY_SIZE: u16>(
        &mut self,
        sender_id: ParticipantId,
        R: ReceiverPubKeys<G>,
    ) {
        assert!(self.sender_setup.contains_key(&sender_id));
        assert!(!self.sender_keys.contains_key(&sender_id));
        // TODO: Remove unwraps
        let sender_keys = OneOfTwoROTSenderKeys::try_from(
            self.sender_setup
                .get(&sender_id)
                .unwrap()
                .derive_keys::<KEY_SIZE>(R)
                .unwrap(),
        )
        .unwrap();
        self.sender_keys.insert(sender_id, sender_keys);
    }

    pub fn finish(mut self) -> BaseOTPhaseOutput {
        // TODO: Ensure keys from everyone
        let mut base_ot_receiver = BTreeMap::new();
        for (id, choice) in self.receiver_choices {
            let keys = self.receiver_keys.remove(&id).unwrap();
            base_ot_receiver.insert(id, (choice, keys));
        }
        BaseOTPhaseOutput {
            id: self.id,
            sender_keys: self.sender_keys,
            receiver: base_ot_receiver,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    pub fn check_base_ot_keys(
        choices: &[Bit],
        receiver_keys: &ROTReceiverKeys,
        sender_keys: &OneOfTwoROTSenderKeys,
    ) {
        for i in 0..sender_keys.len() {
            if choices[i] {
                assert_eq!(sender_keys.0[i].1, receiver_keys.0[i]);
            } else {
                assert_eq!(sender_keys.0[i].0, receiver_keys.0[i]);
            }
        }
    }

    pub fn do_base_ot_for_threshold_sig<const KEY_SIZE: u16>(
        rng: &mut StdRng,
        num_base_ot: u16,
        num_parties: u16,
        all_party_set: BTreeSet<ParticipantId>,
    ) -> Vec<BaseOTPhaseOutput> {
        let B = <Bls12_381 as Pairing>::G1Affine::rand(rng);
        let mut base_ots = vec![];
        let mut sender_pks = BTreeMap::new();
        let mut receiver_pks = BTreeMap::new();

        for i in 1..=num_parties {
            let mut others = all_party_set.clone();
            others.remove(&i);
            let (base_ot, sender_pk) = BaseOTPhase::init(rng, i, others, num_base_ot, &B);
            base_ots.push(base_ot);
            sender_pks.insert(i, sender_pk);
        }

        for (sender_id, pks) in sender_pks {
            for (id, pk) in pks {
                let recv_pk =
                    base_ots[id as usize - 1].receive_s::<_, KEY_SIZE>(rng, sender_id, pk, &B);
                receiver_pks.insert((id, sender_id), recv_pk);
            }
        }

        for ((sender, receiver), pk) in receiver_pks {
            base_ots[receiver as usize - 1].receive_r::<KEY_SIZE>(sender, pk);
        }

        let mut base_ot_outputs = vec![];
        for b in base_ots {
            base_ot_outputs.push(b.finish());
        }

        for base_ot in &base_ot_outputs {
            for (other, sender_keys) in &base_ot.sender_keys {
                let (choices, rec_keys) = base_ot_outputs[*other as usize - 1]
                    .receiver
                    .get(&base_ot.id)
                    .unwrap();
                assert_eq!(rec_keys.len(), sender_keys.len());
                check_base_ot_keys(&choices, &rec_keys, &sender_keys);
            }
        }
        base_ot_outputs
    }

    #[test]
    fn base_ot_for_threshold_sig() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let num_base_ot = 256;

        let num_parties = 5;
        let all_party_set = (1..=num_parties).into_iter().collect::<BTreeSet<_>>();

        do_base_ot_for_threshold_sig::<16>(&mut rng, num_base_ot, num_parties, all_party_set);
    }
}
