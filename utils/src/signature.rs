use crate::{extend_some::ExtendSome, misc::rand};
use ark_ff::PrimeField;
use ark_std::{rand::RngCore, vec::Vec};
use core::result::Result;

/// Trait implemented by a signature scheme params that can sign multiple messages
pub trait MultiMessageSignatureParams {
    /// Number of messages supported in the multi-message
    fn supported_message_count(&self) -> usize;
}

/// Each message can be either randomly blinded, unblinded, or blinded using supplied blinding.
/// By default, a message is blinded with random blinding.
pub enum MessageOrBlinding<'a, F: PrimeField> {
    /// Message will be blinded using random blinding.
    BlindMessageRandomly(&'a F),
    /// Message will be revealed, and thus won't be included in the proof of knowledge.
    RevealMessage(&'a F),
    /// Message will be blinded using the supplied blinding.
    BlindMessageWithConcreteBlinding { message: &'a F, blinding: F },
}

impl<'a, F: PrimeField> MessageOrBlinding<'a, F> {
    /// Blinds given `message` using supplied `blinding`.
    pub fn blind_message_with(message: &'a F, blinding: F) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

// TODO: Document this
pub fn split_messages_and_blindings<
    'a,
    R: RngCore,
    F: PrimeField,
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
