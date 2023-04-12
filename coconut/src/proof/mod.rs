//! Proofs of knowledge for the signature and messages.

use alloc::vec::Vec;

pub mod messages_pok;
pub mod signature_pok;

use ark_ff::PrimeField;

use ark_std::rand::RngCore;

use itertools::process_results;
pub use messages_pok::*;
use serde::{Deserialize, Serialize};
pub use signature_pok::*;

use crate::helpers::{pair_with_slice, rand, IndexIsOutOfBounds};

/// Each message can be either randomly blinded, unblinded, or blinded using supplied blinding.
/// By default, a message is blinded with random blinding.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CommitMessage<M, B> {
    /// Message will be randomly blinded into the commitment.
    BlindMessageRandomly(M),
    /// Message will be revealed, and thus won't be included in PoK.
    RevealMessage,
    /// Message will be blinded into the commitment with the supplied blinding.
    BlindMessageWithConcreteBlinding { message: M, blinding: B },
}

impl<M, B: PrimeField> CommitMessage<M, B> {
    /// Splits blinded message into the message and blinding, returns `None` for the revealed message.
    pub fn split<R: RngCore>(self, rng: &mut R) -> Option<(M, B)> {
        match self {
            Self::BlindMessageRandomly(message) => Some((message, rand(rng))),
            Self::BlindMessageWithConcreteBlinding { message, blinding } => {
                Some((message, blinding))
            }
            Self::RevealMessage => None,
        }
    }

    /// Blinds given `message` using supplied `blinding`.
    pub fn blind_message_with(message: M, blinding: B) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F> From<F> for CommitMessage<F, F> {
    fn from(message: F) -> Self {
        Self::BlindMessageRandomly(message)
    }
}

impl<F: PrimeField> From<&'_ F> for CommitMessage<F, F> {
    fn from(&message: &'_ F) -> Self {
        Self::BlindMessageRandomly(message)
    }
}

impl<M, B> From<(M, B)> for CommitMessage<M, B> {
    fn from((message, blinding): (M, B)) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<M, B> From<(M, Option<B>)> for CommitMessage<M, B> {
    fn from((message, blinding): (M, Option<B>)) -> Self {
        if let Some(blinding) = blinding {
            Self::BlindMessageWithConcreteBlinding { message, blinding }
        } else {
            Self::BlindMessageRandomly(message)
        }
    }
}

impl<F> From<Option<F>> for CommitMessage<F, F> {
    fn from(opt: Option<F>) -> Self {
        match opt {
            Some(msg) => Self::BlindMessageRandomly(msg),
            None => Self::RevealMessage,
        }
    }
}

impl<F: PrimeField> From<CommitMessage<&'_ F, F>> for CommitMessage<F, F> {
    fn from(com_msg: CommitMessage<&'_ F, F>) -> Self {
        match com_msg {
            CommitMessage::BlindMessageRandomly(&msg) => Self::BlindMessageRandomly(msg),
            CommitMessage::RevealMessage => Self::RevealMessage,
            CommitMessage::BlindMessageWithConcreteBlinding { message, blinding } => {
                Self::BlindMessageWithConcreteBlinding {
                    message: *message,
                    blinding,
                }
            }
        }
    }
}

impl<F: PrimeField> From<(&'_ F, F)> for CommitMessage<F, F> {
    fn from((&message, blinding): (&'_ F, F)) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F: PrimeField> From<(&'_ F, Option<F>)> for CommitMessage<F, F> {
    fn from((&message, blinding): (&'_ F, Option<F>)) -> Self {
        if let Some(blinding) = blinding {
            Self::BlindMessageWithConcreteBlinding { message, blinding }
        } else {
            Self::BlindMessageRandomly(message)
        }
    }
}

impl<F: PrimeField> From<Option<&'_ F>> for CommitMessage<F, F> {
    fn from(opt: Option<&'_ F>) -> Self {
        match opt {
            Some(&msg) => Self::BlindMessageRandomly(msg),
            None => Self::RevealMessage,
        }
    }
}

/// Contains vectors of items paired with messages along with messages and blindings.
/// All vectors have one item per message.
#[derive(Debug, PartialEq, Eq, Clone)]
struct UnpackedBlindedMessages<'pair, Pair, F>(pub Vec<&'pair Pair>, pub Vec<F>, pub Vec<F>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageUnpackingError {
    MessageIndexIsOutOfBounds(IndexIsOutOfBounds),
    NoMessagesProvided,
    LessMessagesThanExpected { provided: usize, expected: usize },
}

impl From<IndexIsOutOfBounds> for MessageUnpackingError {
    fn from(err: IndexIsOutOfBounds) -> Self {
        Self::MessageIndexIsOutOfBounds(err)
    }
}

impl<'pair, Pair, F: PrimeField> UnpackedBlindedMessages<'pair, Pair, F> {
    /// Accepts a random generator, an iterator of blinded and revealed messages, and a slice
    /// to pair blinded messages with.
    /// Returns a result containing a vectors of corresponding `pair_with` elements along with
    /// messages and blindings. Each collection has one item per message.
    pub fn new(
        rng: &mut impl RngCore,
        messages: impl IntoIterator<Item = impl Into<CommitMessage<F, F>>>,
        pair_with: &'pair [Pair],
    ) -> Result<Self, MessageUnpackingError> {
        let mut total_count = 0;
        let indexed_blinded_msgs = messages
            .into_iter()
            .map(Into::into)
            .enumerate()
            .inspect(|_| total_count += 1)
            .filter_map(|(idx, msg_with_blinding)| {
                msg_with_blinding.split(rng).map(|split| (idx, split))
            });

        // Pair each indexed blinded message with an item from the provided slice.
        let paired = pair_with_slice(indexed_blinded_msgs, pair_with);

        let (paired, (msgs, blindings)): (Vec<_>, _) =
            process_results(paired, |iter| iter.unzip())?;
        if paired.is_empty() {
            Err(MessageUnpackingError::NoMessagesProvided)
        } else if pair_with.len() != total_count {
            Err(MessageUnpackingError::LessMessagesThanExpected {
                provided: total_count,
                expected: pair_with.len(),
            })
        } else {
            Ok(Self(paired, msgs, blindings))
        }
    }
}
