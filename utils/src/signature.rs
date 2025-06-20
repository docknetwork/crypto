use crate::{extend_some::ExtendSome, misc::rand};
use ark_ff::Field;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use core::result::Result;

/// Trait implemented by a signature scheme params that can sign multiple messages
pub trait MultiMessageSignatureParams {
    /// Number of messages supported in the multi-message
    fn supported_message_count(&self) -> usize;
}

/// Each message can be either randomly blinded, unblinded, or blinded using supplied blinding.
/// By default, a message is blinded with random blinding.
pub enum MessageOrBlinding<'a, F: Field> {
    /// Message will be blinded using random blinding.
    BlindMessageRandomly(&'a F),
    /// Message will be revealed, and thus won't be included in the proof of knowledge.
    RevealMessage(&'a F),
    /// Message will be blinded using the supplied blinding.
    BlindMessageWithConcreteBlinding { message: &'a F, blinding: F },
}

impl<'a, F: Field> MessageOrBlinding<'a, F> {
    /// Blinds given `message` using supplied `blinding`.
    pub fn blind_message_with(message: &'a F, blinding: F) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

// TODO: Document this
pub fn split_messages_and_blindings<
    'a,
    R: RngCore,
    F: Field,
    MBI: IntoIterator<Item = MessageOrBlinding<'a, F>>,
>(
    rng: &mut R,
    messages_and_blindings: MBI,
    params: impl MultiMessageSignatureParams,
) -> Result<(Vec<F>, impl IntoIterator<Item = (usize, F)>), usize> {
    let (messages, ExtendSome::<Vec<_>>(indexed_blindings)): (Vec<_>, _) = messages_and_blindings
        .into_iter()
        .enumerate()
        .map(|(idx, msg_or_blinding)| match msg_or_blinding {
            MessageOrBlinding::BlindMessageRandomly(message) => (message, (idx, rand(rng)).into()),
            MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding } => {
                (message, (idx, blinding).into())
            }
            MessageOrBlinding::RevealMessage(message) => (message, None),
        })
        .unzip();
    let l = messages.len();
    (l == params.supported_message_count())
        .then_some((messages, indexed_blindings))
        .ok_or_else(|| l)
}

// TODO: Document this and rename
pub fn schnorr_responses_to_msg_index_map<T>(
    witnesses: Vec<T>,
    revealed_msg_ids: &BTreeSet<usize>,
    skip_responses_for: &BTreeSet<usize>,
) -> BTreeMap<usize, T> {
    let mut wits = BTreeMap::new();
    let mut shift = 0;
    for (i, w) in witnesses.into_iter().enumerate() {
        let mut msg_idx = i + shift;
        while revealed_msg_ids.contains(&msg_idx) {
            shift += 1;
            msg_idx += 1;
        }
        if !skip_responses_for.contains(&msg_idx) {
            wits.insert(i, w);
        }
    }
    wits
}

// TODO: Document this and rename
pub fn msg_index_map_to_schnorr_response_map<'a, T>(
    missing_responses: BTreeMap<usize, T>,
    revealed_msg_ids: impl IntoIterator<Item = &'a usize> + Clone,
) -> BTreeMap<usize, T> {
    let mut adjusted_missing = BTreeMap::new();
    for (i, w) in missing_responses {
        let mut adj_i = i;
        for j in revealed_msg_ids.clone().into_iter() {
            if i > *j {
                adj_i -= 1;
            }
        }
        adjusted_missing.insert(adj_i, w);
    }
    adjusted_missing
}

pub fn msg_index_to_schnorr_response_index(
    msg_idx: usize,
    revealed_msg_ids: &BTreeSet<usize>,
) -> Option<usize> {
    // Revealed messages are not part of Schnorr protocol
    if revealed_msg_ids.contains(&msg_idx) {
        return None;
    }
    // Adjust message index as the revealed messages are not part of the Schnorr protocol
    let mut adjusted_idx = msg_idx;
    for i in revealed_msg_ids {
        if *i < msg_idx {
            adjusted_idx -= 1;
        }
    }
    Some(adjusted_idx)
}
