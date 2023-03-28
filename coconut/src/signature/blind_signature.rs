use core::ops::Mul;

use ark_ec::pairing::Pairing;

use alloc::vec::Vec;
use ark_serialize::*;
use ark_std::cfg_into_iter;
use itertools::{process_results, Itertools};
use utils::join;

use super::{error::BlindPSError, ps_signature::Signature};
use crate::{
    helpers::{
        pair_is_lt, pair_valid_items_with_slice, pair_with_slice, CheckLeft, ExtendSome, OwnedPairs,
    },
    setup::{PublicKey, SecretKey},
    MessageCommitment,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type Result<T, E = BlindPSError> = core::result::Result<T, E>;

/// Each message can be either revealed or blinded into the commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentOrMessage<'a, E: Pairing> {
    /// Message blinded into the commitment.
    BlindedMessage(&'a MessageCommitment<E>),
    /// Revealed message.
    RevealedMessage(&'a E::ScalarField),
}

impl<'a, E: Pairing> From<&'a MessageCommitment<E>> for CommitmentOrMessage<'a, E> {
    fn from(commitment: &'a MessageCommitment<E>) -> Self {
        Self::BlindedMessage(commitment)
    }
}

/// Pointcheval-Sanders signature created over commitments (blinded messages) and revealed messages.
/// To verify this signature, you would have to unblind by providing blindings used to produce commitments.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindSignature<E: Pairing>(Signature<E>);

type DoubleOwnedPairs<A, B, C, D> = (ExtendSome<OwnedPairs<A, B>>, ExtendSome<OwnedPairs<C, D>>);

impl<E: Pairing> BlindSignature<E> {
    /// Creates new `BlindSignature` using supplied commitments (blinded messages) and revealed messages.
    pub fn new<'a, CMI>(
        commitments_and_messages: CMI,
        SecretKey { x, y }: &SecretKey<E::ScalarField>,
        &h: &E::G1Affine,
    ) -> Result<Self>
    where
        CMI: IntoIterator,
        CMI::Item: Into<CommitmentOrMessage<'a, E>>,
    {
        let indexed_coms_and_msgs = commitments_and_messages
            .into_iter()
            .map(Into::into)
            .enumerate();
        let com_and_msg_paired_with_y = pair_with_slice(indexed_coms_and_msgs, y).map_ok(
            |(&y_i, com_or_msg)| match com_or_msg {
                CommitmentOrMessage::BlindedMessage(com) => (None, Some((**com, y_i))),
                CommitmentOrMessage::RevealedMessage(message) => (Some((message, y_i)), None),
            },
        );
        let (ExtendSome(m_y_pairs), ExtendSome(com_y_pairs)): DoubleOwnedPairs<_, _, _, _> =
            process_results(com_and_msg_paired_with_y, |iter| iter.unzip())?;

        match m_y_pairs.len().checked_add(com_y_pairs.len()) {
            Some(0) => Err(BlindPSError::NoCommitmentsOrMessages)?,
            Some(amount) if amount == y.len() => {}
            received => Err(BlindPSError::InvalidCommitmentsAndMessagesCount {
                received,
                expected: y.len(),
            })?,
        }

        // `h * (x + \sum_{i}(m_{i} * y_{i})) + \sum_{j}(com_{j} * y_{j})`
        let sigma_2 = {
            let (com_mul_y, m_mul_y) = join!(
                com_y_pairs.msm(),
                cfg_into_iter!(m_y_pairs)
                    .map(|(&message, sec_key_y)| sec_key_y * message)
                    .sum::<E::ScalarField>()
            );

            h.mul(*x + m_mul_y) + com_mul_y
        };

        Ok(Self(Signature::combine(h, sigma_2)))
    }

    /// Prior to verification, the signature needs to be unblinded using the blindings used in the commitments.
    /// Blindings must be provided along with the indices of the corresponding commitments for the positions as
    /// they were used in `BlindSignature::new`. For the revealed messages, no blindings should be provided.
    /// `indexed_blindings_sorted_by_index` must produce items sorted by unique indices, otherwise, an error
    /// will be returned.
    pub fn unblind<'a, IB>(
        self,
        indexed_blindings_sorted_by_index: IB,
        PublicKey { beta, .. }: &PublicKey<E>,
    ) -> Result<Signature<E>>
    where
        IB: IntoIterator<Item = (usize, &'a E::ScalarField)>,
    {
        let blindings_with_beta: OwnedPairs<_, _> = pair_valid_items_with_slice(
            indexed_blindings_sorted_by_index,
            CheckLeft(pair_is_lt),
            beta,
        )
        .map_ok(|(beta_j, o)| (*beta_j, (-*o)))
        .collect::<Result<_>>()?;

        // \sum_{j}(beta_{j} * (-o_{j}))
        let beta_mul_neg_o = blindings_with_beta.msm();

        Ok(Signature::combine(
            self.0.sigma_1,
            beta_mul_neg_o + self.0.sigma_2,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter::repeat_with;

    use itertools::Itertools;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use crate::{
        helpers::{n_rand, rand, Pairs},
        setup::test_setup,
        signature::message_commitment::MessageCommitment,
    };

    use super::*;

    use ark_bls12_381::Bls12_381;
    use ark_ec::CurveGroup;
    use ark_std::{
        cfg_iter,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;
    type G1 = <Bls12_381 as Pairing>::G1;

    #[test]
    fn test_signature_single_blinded_message() {
        // Only 1 blinded message, no message known to signer
        let mut rng = StdRng::seed_from_u64(0u64);
        for _ in 1..10 {
            let (sk, pk, params, msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);

            let blindings = [Fr::rand(&mut rng)];
            let h = G1::rand(&mut rng).into_affine();

            let blinding_msg_pairs = Pairs::new(&blindings, &msgs).unwrap();
            let comms: Vec<_> =
                MessageCommitment::new_iter(blinding_msg_pairs, &h, &params).collect();

            let sig_blinded = BlindSignature::new(
                comms.iter().map(CommitmentOrMessage::BlindedMessage),
                &sk,
                &h,
            )
            .unwrap();
            let sig_unblinded = sig_blinded
                .unblind(blindings.iter().enumerate(), &pk)
                .unwrap();

            sig_unblinded.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_signature_all_blinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let h = G1::rand(&mut rng).into_affine();
            let blindings: Vec<_> = n_rand(&mut rng, count_msgs).collect();

            let blinding_msg_pairs = Pairs::new(&blindings, &msgs).unwrap();
            let comms: Vec<_> =
                MessageCommitment::new_iter(blinding_msg_pairs, &h, &params).collect();

            let sig_blinded = BlindSignature::new(
                comms.iter().map(CommitmentOrMessage::BlindedMessage),
                &sk,
                &h,
            )
            .unwrap();
            let sig_unblinded = sig_blinded
                .unblind(blindings.iter().enumerate(), &pk)
                .unwrap();
            sig_unblinded.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_empty_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, _pk, _params, _msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 10);

        let h = G1::rand(&mut rng).into_affine();

        assert!(BlindSignature::<Bls12_381>::new(&[], &sk, &h,).is_err());
    }

    #[test]
    fn test_signature_all_unblinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let h = G1::rand(&mut rng).into_affine();

            let sig_blinded = BlindSignature::new(
                msgs.iter().map(CommitmentOrMessage::RevealedMessage),
                &sk,
                &h,
            )
            .unwrap();
            let sig_unblinded = sig_blinded.unblind(None, &pk).unwrap();

            sig_unblinded.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_signature_some_unblinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let h = G1::rand(&mut rng).into_affine();

            let (blind_msgs, reveal_msgs): (Vec<_>, Vec<_>) =
                msgs.iter().enumerate().partition(|(idx, _)| idx % 2 == 0);

            let blind_msgs_with_blindings: OwnedPairs<_, _> =
                repeat_with(|| Fr::rand(&mut rng)).zip(blind_msgs).collect();

            let com_msgs: Vec<_> = MessageCommitment::new_iter(
                cfg_iter!(blind_msgs_with_blindings).map(|(blinding, &(_, msg))| (blinding, msg)),
                &h,
                &params,
            )
            .collect();

            let com_and_msgs = com_msgs
                .iter()
                .map(CommitmentOrMessage::BlindedMessage)
                .interleave(
                    reveal_msgs
                        .into_iter()
                        .map(|(_, msg)| msg)
                        .map(CommitmentOrMessage::RevealedMessage),
                );

            let sig_blinded = BlindSignature::new(com_and_msgs, &sk, &h).unwrap();

            let sig_unblinded = sig_blinded
                .unblind(
                    blind_msgs_with_blindings
                        .iter()
                        .map(|(blinding, (idx, _))| (*idx, blinding)),
                    &pk,
                )
                .unwrap();

            sig_unblinded.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_signature_known_and_blinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for i in 1..10 {
            let count_msgs = (i % 6) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let blindings: Vec<_> = n_rand(&mut rng, msgs.len()).collect();
            let h = rand::<G1, _>(&mut rng).into_affine();

            let blinding_msg_pairs = Pairs::new(&blindings, &msgs).unwrap();
            let comms: Vec<_> =
                MessageCommitment::new_iter(blinding_msg_pairs, &h, &params).collect();

            let sig_blinded = BlindSignature::new(
                comms.iter().map(CommitmentOrMessage::BlindedMessage),
                &sk,
                &h,
            )
            .unwrap();
            let sig_unblinded = sig_blinded
                .unblind(blindings.iter().enumerate(), &pk)
                .unwrap();
            sig_unblinded.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_signature_invalid_message_count() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for i in 1..10 {
            let count_msgs = (i % 6) + 1;
            let (sk, _, _, _) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);
            let (_, _, _, invalid_msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs + 1);

            let h = rand::<G1, _>(&mut rng).into_affine();

            assert!(BlindSignature::<Bls12_381>::new(
                invalid_msgs
                    .iter()
                    .map(CommitmentOrMessage::RevealedMessage),
                &sk,
                &h,
            )
            .is_err());
        }
    }
}
