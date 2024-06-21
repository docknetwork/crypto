//! Each pair of participants must run a base OT among themselves and stores the OT receiver choices and
//! the output, i.e sender and receiver keys. This needs to be done only once unless they are lost or compromised.

use crate::{
    base_ot::simplest_ot::{
        Challenges, HashedKey, OneOfTwoROTSenderKeys, ROTReceiverKeys, ROTSenderSetup,
        ReceiverPubKeys, Responses, SenderPubKey, VSROTChallenger, VSROTResponder,
    },
    error::OTError,
    Bit, ParticipantId,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use digest::Digest;
use schnorr_pok::discrete_log::PokDiscreteLog;
use serde::{Deserialize, Serialize};

/// The participant runs an independent base OT with each participant and stores each OT's state. If
/// its id is less than other's then it acts as an OT sender else it acts as a receiver
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Participant<G: AffineRepr> {
    pub id: ParticipantId,
    /// Number of base OTs to perform
    pub count: u16,
    /// Map where this participant plays the role of sender
    pub sender_setup: BTreeMap<ParticipantId, ROTSenderSetup<G>>,
    /// Map where this participant plays the role of receiver
    pub receiver_choices: BTreeMap<ParticipantId, Vec<Bit>>,
    pub sender_keys: BTreeMap<ParticipantId, OneOfTwoROTSenderKeys>,
    pub receiver_keys: BTreeMap<ParticipantId, ROTReceiverKeys>,
    pub sender_challenger: BTreeMap<ParticipantId, VSROTChallenger>,
    pub receiver_responder: BTreeMap<ParticipantId, VSROTResponder>,
}

/// Output of base OT run between each pair of participants of the multi-party multiplication protocol
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct BaseOTOutput {
    pub id: ParticipantId,
    pub sender_keys: BTreeMap<ParticipantId, OneOfTwoROTSenderKeys>,
    pub receiver: BTreeMap<ParticipantId, (Vec<Bit>, ROTReceiverKeys)>,
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SenderPubKeyAndProof<G: AffineRepr>(pub SenderPubKey<G>, PokDiscreteLog<G>);

impl<G: AffineRepr> Participant<G> {
    pub fn init<R: RngCore, D: Digest>(
        rng: &mut R,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        num_base_ot: u16,
        B: &G,
    ) -> Result<(Self, BTreeMap<ParticipantId, SenderPubKeyAndProof<G>>), OTError> {
        let mut base_ot_sender_setup = BTreeMap::new();
        let mut base_ot_receiver_choices = BTreeMap::new();
        let mut base_ot_s = BTreeMap::new();
        for other in others {
            if id < other {
                let (setup, S, proof) =
                    ROTSenderSetup::new_verifiable::<R, D>(rng, num_base_ot, B)?;
                base_ot_s.insert(other, SenderPubKeyAndProof(S, proof));
                base_ot_sender_setup.insert(other, setup);
            } else {
                let base_ot_choices = (0..num_base_ot)
                    .map(|_| (u8::rand(rng) % 2) != 0)
                    .collect::<Vec<_>>();
                base_ot_receiver_choices.insert(other, base_ot_choices);
            }
        }
        Ok((
            Self {
                id,
                count: num_base_ot,
                sender_setup: base_ot_sender_setup,
                receiver_choices: base_ot_receiver_choices,
                sender_keys: Default::default(),
                receiver_keys: Default::default(),
                sender_challenger: Default::default(),
                receiver_responder: Default::default(),
            },
            base_ot_s,
        ))
    }

    pub fn receive_sender_pubkey<R: RngCore, D: Digest, const KEY_SIZE: u16>(
        &mut self,
        rng: &mut R,
        sender_id: ParticipantId,
        sender_pk_and_proof: SenderPubKeyAndProof<G>,
        B: &G,
    ) -> Result<ReceiverPubKeys<G>, OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.id < sender_id {
            return Err(OTError::NotABaseOTSender(sender_id));
        }
        if !self.receiver_choices.contains_key(&sender_id) {
            return Err(OTError::NotABaseOTSender(sender_id));
        }
        if self.receiver_keys.contains_key(&sender_id) {
            return Err(OTError::AlreadyHaveSenderPubkeyFrom(sender_id));
        }
        let SenderPubKeyAndProof(S, proof) = sender_pk_and_proof;
        let (receiver_keys, pub_key) = ROTReceiverKeys::new_verifiable::<_, _, D, KEY_SIZE>(
            rng,
            self.count,
            self.receiver_choices.get(&sender_id).unwrap().clone(),
            S,
            &proof,
            B,
        )?;
        self.receiver_keys.insert(sender_id, receiver_keys);
        Ok(pub_key)
    }

    pub fn receive_receiver_pubkey<const KEY_SIZE: u16>(
        &mut self,
        sender_id: ParticipantId,
        R: ReceiverPubKeys<G>,
    ) -> Result<Challenges, OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.id > sender_id {
            return Err(OTError::NotABaseOTReceiver(sender_id));
        }
        if self.sender_keys.contains_key(&sender_id) {
            return Err(OTError::AlreadyHaveReceiverPubkeyFrom(sender_id));
        }
        if !self.sender_setup.contains_key(&sender_id) {
            return Err(OTError::NotABaseOTReceiver(sender_id));
        }
        if let Some(sender_setup) = self.sender_setup.get(&sender_id) {
            let sender_keys =
                OneOfTwoROTSenderKeys::try_from(sender_setup.derive_keys::<KEY_SIZE>(R)?)?;
            let (sender_challenger, challenges) = VSROTChallenger::new(&sender_keys)?;
            self.sender_challenger.insert(sender_id, sender_challenger);
            self.sender_keys.insert(sender_id, sender_keys);
            Ok(challenges)
        } else {
            Err(OTError::NotABaseOTReceiver(sender_id))
        }
    }

    pub fn receive_challenges(
        &mut self,
        sender_id: ParticipantId,
        challenges: Challenges,
    ) -> Result<Responses, OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.id < sender_id {
            return Err(OTError::NotABaseOTSender(sender_id));
        }
        if self.receiver_responder.contains_key(&sender_id) {
            return Err(OTError::AlreadyHaveChallengesFrom(sender_id));
        }
        if let Some(receiver_keys) = self.receiver_keys.get(&sender_id) {
            let (receiver_responder, responses) = VSROTResponder::new(
                receiver_keys,
                self.receiver_choices.get(&sender_id).unwrap().clone(),
                challenges,
            )?;
            self.receiver_responder
                .insert(sender_id, receiver_responder);
            Ok(responses)
        } else {
            Err(OTError::ReceiverNotReadyForChallengeFrom(sender_id))
        }
    }

    pub fn receive_responses(
        &mut self,
        sender_id: ParticipantId,
        responses: Responses,
    ) -> Result<Vec<(HashedKey, HashedKey)>, OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.id > sender_id {
            return Err(OTError::NotABaseOTReceiver(sender_id));
        }
        if let Some(sender_challenger) = self.sender_challenger.remove(&sender_id) {
            let hashed_keys = sender_challenger.verify_responses(responses)?;
            Ok(hashed_keys)
        } else {
            Err(OTError::SenderEitherNotReadyForResponseOrAlreadySentIt(
                sender_id,
            ))
        }
    }

    pub fn receive_hashed_keys(
        &mut self,
        sender_id: ParticipantId,
        hashed_keys: Vec<(HashedKey, HashedKey)>,
    ) -> Result<(), OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.id < sender_id {
            return Err(OTError::NotABaseOTSender(sender_id));
        }
        if let Some(receiver_responder) = self.receiver_responder.remove(&sender_id) {
            receiver_responder.verify_sender_hashed_keys(hashed_keys)?;
            Ok(())
        } else {
            Err(OTError::ReceiverEitherNotReadyForHashedKeysOrAlreadyVerifiedIt(sender_id))
        }
    }

    pub fn finish(mut self) -> BaseOTOutput {
        // TODO: Ensure keys from everyone
        let mut base_ot_receiver = BTreeMap::new();
        for (id, choice) in self.receiver_choices {
            let keys = self.receiver_keys.remove(&id).unwrap();
            base_ot_receiver.insert(id, (choice, keys));
        }
        BaseOTOutput {
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
    use blake2::Blake2b512;

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

    pub fn do_pairwise_base_ot<const KEY_SIZE: u16>(
        rng: &mut StdRng,
        num_base_ot: u16,
        num_parties: u16,
        all_party_set: BTreeSet<ParticipantId>,
    ) -> Vec<BaseOTOutput> {
        let B = <Bls12_381 as Pairing>::G1Affine::rand(rng);
        let mut base_ots = vec![];
        let mut sender_pks = BTreeMap::new();
        let mut receiver_pks = BTreeMap::new();

        for i in 1..=num_parties {
            let mut others = all_party_set.clone();
            others.remove(&i);
            let (base_ot, sender_pk_and_proof) =
                Participant::init::<_, Blake2b512>(rng, i, others, num_base_ot, &B).unwrap();
            base_ots.push(base_ot);
            sender_pks.insert(i, sender_pk_and_proof);
        }

        for (sender_id, pks) in sender_pks {
            for (id, pk) in pks {
                let recv_pk = base_ots[id as usize - 1]
                    .receive_sender_pubkey::<_, Blake2b512, KEY_SIZE>(rng, sender_id, pk, &B)
                    .unwrap();
                receiver_pks.insert((id, sender_id), recv_pk);
            }
        }

        let mut challenges = BTreeMap::new();
        let mut responses = BTreeMap::new();
        let mut hashed_keys = BTreeMap::new();

        for ((sender, receiver), pk) in receiver_pks {
            let chal = base_ots[receiver as usize - 1]
                .receive_receiver_pubkey::<KEY_SIZE>(sender, pk)
                .unwrap();
            challenges.insert((receiver, sender), chal);
        }

        for ((sender, receiver), chal) in challenges {
            let resp = base_ots[receiver as usize - 1]
                .receive_challenges(sender, chal)
                .unwrap();
            responses.insert((receiver, sender), resp);
        }

        for ((sender, receiver), resp) in responses {
            let hk = base_ots[receiver as usize - 1]
                .receive_responses(sender, resp)
                .unwrap();
            hashed_keys.insert((receiver, sender), hk);
        }

        for ((sender, receiver), hk) in hashed_keys {
            base_ots[receiver as usize - 1]
                .receive_hashed_keys(sender, hk)
                .unwrap()
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
    fn base_ot_pairwise() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let num_base_ot = 256;
        for num_parties in vec![5, 10, 15, 20] {
            let all_party_set = (1..=num_parties).into_iter().collect::<BTreeSet<_>>();

            do_pairwise_base_ot::<16>(&mut rng, num_base_ot, num_parties, all_party_set);
        }
    }
}
