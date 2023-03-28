pub mod accumulator;
pub mod bbs_plus;
pub mod bound_check_legogroth16;
pub mod ps_signature;
pub mod r1cs_legogorth16;
pub mod saver;
pub mod schnorr;

use core::borrow::Borrow;

use crate::error::ProofSystemError;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::io::Write;
use dock_crypto_utils::{
    iter::take_while_pairs_satisfy, misc::check_seq_from, try_iter::CheckLeft,
};
use itertools::{EitherOrBoth, Itertools};

use crate::{
    statement_proof::StatementProof,
    sub_protocols::{
        bound_check_legogroth16::BoundCheckProtocol, r1cs_legogorth16::R1CSLegogroth16Protocol,
    },
};
use accumulator::{AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol};

/// Various sub-protocols that are executed to create a `StatementProof` which are then combined to
/// form a `Proof`
#[derive(Clone, Debug, PartialEq)]
pub enum SubProtocol<'a, E: Pairing, G: AffineRepr> {
    PoKBBSSignatureG1(self::bbs_plus::PoKBBSSigG1SubProtocol<'a, E>),
    AccumulatorMembership(AccumulatorMembershipSubProtocol<'a, E>),
    AccumulatorNonMembership(AccumulatorNonMembershipSubProtocol<'a, E>),
    PoKDiscreteLogs(self::schnorr::SchnorrProtocol<'a, G>),
    /// For verifiable encryption using SAVER
    Saver(self::saver::SaverProtocol<'a, E>),
    /// For range proof using LegoGroth16
    BoundCheckProtocol(BoundCheckProtocol<'a, E>),
    R1CSLegogroth16Protocol(R1CSLegogroth16Protocol<'a, E>),
    PSSignaturePoK(self::ps_signature::PSSignaturePoK<'a, E>),
}

macro_rules! delegate {
    ($self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PoKDiscreteLogs,
                Saver,
                BoundCheckProtocol,
                R1CSLegogroth16Protocol,
                PSSignaturePoK
            : $($tt)+
        }
    }};
}

pub trait ProofSubProtocol<E: Pairing, G: AffineRepr<ScalarField = E::ScalarField>> {
    fn challenge_contribution(&self, target: &mut [u8]) -> Result<(), ProofSystemError>;
    fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError>;
}

impl<'a, E: Pairing, G: AffineRepr<ScalarField = E::ScalarField>> SubProtocol<'a, E, G> {
    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        delegate!(self.challenge_contribution(writer))
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        delegate!(self.gen_proof_contribution(challenge))
    }
}

fn merge_msgs_with_blindings<'a, M, B, R>(
    msgs: impl IntoIterator<Item = (impl Borrow<usize>, M)> + 'a,
    blindings: impl IntoIterator<Item = (impl Borrow<usize>, B)> + 'a,
    revealed_msgs: impl IntoIterator<Item = (impl Borrow<usize>, M)> + 'a,
    mut map_msg: impl FnMut(M) -> R + 'a,
    mut map_blinded_msg: impl FnMut(M, B) -> R + 'a,
    mut map_revealed_msg: impl FnMut(M) -> R + 'a,
    invalid_blinding_idx: &'a mut Option<usize>,
    invalid_message_idx: &'a mut Option<(usize, usize)>,
) -> impl Iterator<Item = R> + 'a {
    let blinded_msgs = msgs
        .into_iter()
        .map(|(idx, msg)| (*idx.borrow(), msg))
        .merge_join_by(
            blindings.into_iter().map(|(idx, msg)| (*idx.borrow(), msg)),
            |(m_idx, _), (b_idx, _)| m_idx.cmp(b_idx),
        )
        .scan((), move |(), either| {
            let item = match either {
                EitherOrBoth::Left((idx, msg)) => (idx, map_msg(msg)),
                EitherOrBoth::Both((idx, message), (_, blinding)) => {
                    (idx, (map_blinded_msg)(message, blinding))
                }
                EitherOrBoth::Right((idx, _)) => {
                    invalid_blinding_idx.replace(idx);

                    return None;
                }
            };

            Some(item)
        });
    let revealed_msgs = revealed_msgs
        .into_iter()
        .map(move |(idx, msg)| (*idx.borrow(), map_revealed_msg(msg)));

    take_while_pairs_satisfy(
        blinded_msgs.merge_by(revealed_msgs, |(a, _), (b, _)| a <= b),
        CheckLeft(check_seq_from(0)),
        invalid_message_idx,
    )
    .map(|(_, message)| message)
}
