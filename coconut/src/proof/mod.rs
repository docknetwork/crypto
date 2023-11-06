//! Proofs of knowledge for the signature and messages.

use alloc::vec::Vec;

pub mod messages_pok;
pub mod signature_pok;

use ark_ff::PrimeField;

use ark_std::rand::RngCore;

use itertools::process_results;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::ArkObjectBytes;

pub use messages_pok::*;
pub use signature_pok::*;

use crate::helpers::{pair_with_slice, rand, IndexIsOutOfBounds};

/// Each message can be either randomly blinded, unblinded, or blinded using supplied blinding.
/// By default, a message is blinded with random blinding.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum CommitMessage<F: PrimeField> {
    /// Message will be randomly blinded into the commitment.
    BlindMessageRandomly(#[serde_as(as = "ArkObjectBytes")] F),
    /// Message will be revealed, and thus won't be included in PoK.
    RevealMessage,
    /// Message will be blinded into the commitment with the supplied blinding.
    BlindMessageWithConcreteBlinding {
        #[serde_as(as = "ArkObjectBytes")]
        message: F,
        #[serde_as(as = "ArkObjectBytes")]
        blinding: F,
    },
}

impl<F: PrimeField> CommitMessage<F> {
    /// Splits blinded message into the message and blinding, returns `None` for the revealed message.
    pub fn split<R: RngCore>(self, rng: &mut R) -> Option<(F, F)> {
        match self {
            Self::BlindMessageRandomly(message) => Some((message, rand(rng))),
            Self::BlindMessageWithConcreteBlinding { message, blinding } => {
                Some((message, blinding))
            }
            Self::RevealMessage => None,
        }
    }

    /// Blinds given `message` using supplied `blinding`.
    pub fn blind_message_with(message: F, blinding: F) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F: PrimeField> From<F> for CommitMessage<F> {
    fn from(message: F) -> Self {
        Self::BlindMessageRandomly(message)
    }
}

impl<F: PrimeField> From<&'_ F> for CommitMessage<F> {
    fn from(&message: &'_ F) -> Self {
        Self::BlindMessageRandomly(message)
    }
}

impl<F: PrimeField> From<(F, F)> for CommitMessage<F> {
    fn from((message, blinding): (F, F)) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F: PrimeField> From<(F, Option<F>)> for CommitMessage<F> {
    fn from((message, blinding): (F, Option<F>)) -> Self {
        if let Some(blinding) = blinding {
            Self::BlindMessageWithConcreteBlinding { message, blinding }
        } else {
            Self::BlindMessageRandomly(message)
        }
    }
}

impl<F: PrimeField> From<Option<F>> for CommitMessage<F> {
    fn from(opt: Option<F>) -> Self {
        match opt {
            Some(msg) => Self::BlindMessageRandomly(msg),
            None => Self::RevealMessage,
        }
    }
}

impl<F: PrimeField> From<Option<&'_ F>> for CommitMessage<F> {
    fn from(opt: Option<&'_ F>) -> Self {
        match opt {
            Some(&msg) => Self::BlindMessageRandomly(msg),
            None => Self::RevealMessage,
        }
    }
}

impl<F: PrimeField> From<(&'_ F, F)> for CommitMessage<F> {
    fn from((&message, blinding): (&'_ F, F)) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F: PrimeField> From<(&'_ F, &'_ F)> for CommitMessage<F> {
    fn from((&message, &blinding): (&'_ F, &'_ F)) -> Self {
        Self::BlindMessageWithConcreteBlinding { message, blinding }
    }
}

impl<F: PrimeField> From<(&'_ F, Option<F>)> for CommitMessage<F> {
    fn from((&message, blinding): (&'_ F, Option<F>)) -> Self {
        if let Some(blinding) = blinding {
            Self::BlindMessageWithConcreteBlinding { message, blinding }
        } else {
            Self::BlindMessageRandomly(message)
        }
    }
}

impl<F: PrimeField> From<(&'_ F, Option<&'_ F>)> for CommitMessage<F> {
    fn from((&message, blinding): (&'_ F, Option<&'_ F>)) -> Self {
        if let Some(blinding) = blinding.copied() {
            Self::BlindMessageWithConcreteBlinding { message, blinding }
        } else {
            Self::BlindMessageRandomly(message)
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
        messages: impl IntoIterator<Item = impl Into<CommitMessage<F>>>,
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
        if pair_with.len() != total_count {
            Err(MessageUnpackingError::LessMessagesThanExpected {
                provided: total_count,
                expected: pair_with.len(),
            })
        } else {
            Ok(Self(paired, msgs, blindings))
        }
    }
}
