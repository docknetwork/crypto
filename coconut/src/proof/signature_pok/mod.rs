//! Proof of knowledge for the signature.

use alloc::vec::Vec;
use ark_ec::pairing::Pairing;

use ark_serialize::*;
use ark_std::rand::RngCore;

use serde::{Deserialize, Serialize};

use schnorr_pok::{error::SchnorrError, SchnorrChallengeContributor};

mod error;
mod k;
pub mod proof;
pub mod randomized_signature;
mod witnesses;

use super::UnpackedBlindedMessages;
use crate::{
    helpers::{schnorr_error, WithSchnorrAndBlindings},
    setup::{PublicKey, SignatureParams},
    CommitMessage, Signature,
};
use utils::{join, pairs};

pub use error::*;
use k::*;
pub use proof::*;
pub use randomized_signature::*;
use witnesses::*;

pub type Result<T, E = SignaturePoKError> = core::result::Result<T, E>;

/// Generates proof of knowledge for the given signature using supplied messages.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
#[serde(bound = "")]
pub struct SignaturePoKGenerator<E: Pairing> {
    witness: SignaturePoKWitnesses<E::ScalarField>,
    /// `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
    k: WithSchnorrAndBlindings<E::G2Affine, K<E>>,
    randomized_sig: RandomizedSignature<E>,
}

impl<E: Pairing> SignaturePoKGenerator<E> {
    /// Initializes generator of Proof of Knowledge of signature with supplied params.
    /// Each message can be either randomly blinded, unblinded, or blinded using supplied blinding.
    /// By default, a message is blinded with random blinding.
    /// Signature will be randomized and **must be** verified later using generated `k`.
    pub fn init<MI, R: RngCore>(
        rng: &mut R,
        messages: MI,
        signature: &Signature<E>,
        pk: &PublicKey<E>,
        params: &SignatureParams<E>,
    ) -> Result<SignaturePoKGenerator<E>>
    where
        MI: IntoIterator,
        MI::Item: Into<CommitMessage<E::ScalarField>>,
    {
        let UnpackedBlindedMessages(beta_tilde, messages, blindings) =
            UnpackedBlindedMessages::new(rng, messages, &pk.beta_tilde)?;

        // Capture `m`s and generate random `r`, `r_bar`.
        let witness = SignaturePoKWitnesses::new(rng, messages);
        let SignaturePoKWitnesses { r, r_bar, msgs } = &witness;

        // Pair `beta_tilde` with `m` and then with blindings.
        // All of them have equal lengths because they were previously paired during unpacking.
        let beta_tilde_blinding_pairs = pairs!(beta_tilde, blindings);
        let beta_tilde_message_pairs = pairs!(beta_tilde, msgs);

        // Prepare randomness commitment for `K`
        let k_randomness = KRandomness::init(rng, beta_tilde_blinding_pairs, params);

        let (randomized_sig, k, k_schnorr) = join!(
            RandomizedSignature::new(signature, r, r_bar),
            K::new(beta_tilde_message_pairs, r, params),
            k_randomness.commit()
        );

        Ok(SignaturePoKGenerator {
            witness,
            k: (k, k_schnorr).into(),
            randomized_sig,
        })
    }

    /// The commitment's contribution to the overall challenge of the protocol.
    pub fn challenge_contribution<W: Write>(
        &self,
        mut writer: W,
        PublicKey { beta_tilde, .. }: &PublicKey<E>,
        SignatureParams { g, .. }: &SignatureParams<E>,
    ) -> Result<(), SchnorrError> {
        beta_tilde
            .serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;
        g.serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;

        self.k.challenge_contribution(&mut writer)
    }

    /// Generate proof. Post-challenge phase of the protocol.
    pub fn gen_proof(&self, challenge: &E::ScalarField) -> Result<SignaturePoK<E>> {
        let Self {
            witness,
            k,
            randomized_sig,
        } = self;

        // Schnorr response for relation `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
        k.response(&witness.msgs, &witness.r, challenge)
            .map(|k| SignaturePoK {
                k,
                randomized_sig: randomized_sig.clone(),
            })
            .map_err(schnorr_error)
            .map_err(SignaturePoKError::SchnorrError)
    }
}

impl<E: Pairing> SignaturePoKGenerator<E> {
    /// Returns underlying `k` along with the Schnorr commitment.
    pub fn k(&self) -> &WithSchnorrAndBlindings<E::G2Affine, K<E>> {
        &self.k
    }

    /// Returns underlying randomized signatures.
    pub fn randomized_sig(&self) -> &RandomizedSignature<E> {
        &self.randomized_sig
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::{schnorr_error, IndexIsOutOfBounds};
    use alloc::{vec, vec::Vec};
    use core::iter::empty;

    use super::error::SignaturePoKError;
    use ark_bls12_381::{Bls12_381, G2Projective};
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::{
        cfg_into_iter,
        rand::{rngs::StdRng, SeedableRng},
    };
    use blake2::Blake2b512;
    use itertools::Itertools;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use schnorr_pok::{compute_random_oracle_challenge, error::SchnorrError};

    use crate::{proof::MessageUnpackingError, setup::test_setup, CommitMessage, Signature};

    use super::SignaturePoKGenerator;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn basic() {
        cfg_into_iter!(1..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, messages) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            let sig = Signature::new(&mut rng, messages.as_slice(), &sk, &params).unwrap();

            let pok = SignaturePoKGenerator::init(&mut rng, &messages, &sig, &pk, &params).unwrap();

            let mut chal_bytes = vec![];
            pok.challenge_contribution(&mut chal_bytes, &pk, &params)
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let proof = pok.clone().gen_proof(&challenge).unwrap();

            proof.verify(&challenge, empty(), &pk, &params).unwrap();
        })
    }

    #[test]
    fn some_messages_revealed() {
        cfg_into_iter!(1..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            let (blind_msgs, reveal_msgs): (Vec<_>, Vec<_>) =
                msgs.iter().enumerate().partition(|(idx, _)| idx % 2 == 0);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

            let pok = SignaturePoKGenerator::init(
                &mut rng,
                blind_msgs
                    .iter()
                    .map(|(_, msg)| **msg)
                    .map(CommitMessage::BlindMessageRandomly)
                    .interleave(reveal_msgs.iter().map(|_| CommitMessage::RevealMessage)),
                &sig,
                &pk,
                &params,
            )
            .unwrap();

            let mut chal_bytes = vec![];
            pok.challenge_contribution(&mut chal_bytes, &pk, &params)
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let proof = pok.clone().gen_proof(&challenge).unwrap();

            proof.verify(&challenge, reveal_msgs, &pk, &params).unwrap();
        })
    }

    #[test]
    fn message_count_exceeded() {
        let message_count = 10;
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, pk, params, msgs) =
            test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

        let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

        assert_eq!(
            SignaturePoKGenerator::init(
                &mut rng,
                msgs.iter()
                    .cycle()
                    .copied()
                    .enumerate()
                    .map(|(idx, msg)| if idx % 2 == 0 {
                        CommitMessage::BlindMessageRandomly(msg)
                    } else {
                        CommitMessage::RevealMessage
                    })
                    .take(100),
                &sig,
                &pk,
                &params,
            )
            .unwrap_err(),
            SignaturePoKError::MessageInputError(MessageUnpackingError::MessageIndexIsOutOfBounds(
                IndexIsOutOfBounds {
                    index: 10,
                    length: message_count as usize
                }
            ))
        );
    }

    #[test]
    fn message_count_less_than_expected() {
        let message_count = 10;
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, pk, params, msgs) =
            test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

        let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

        assert_eq!(
            SignaturePoKGenerator::init(
                &mut rng,
                msgs.iter()
                    .cycle()
                    .copied()
                    .enumerate()
                    .map(|(idx, msg)| if idx % 2 == 0 {
                        CommitMessage::BlindMessageRandomly(msg)
                    } else {
                        CommitMessage::RevealMessage
                    })
                    .take(9),
                &sig,
                &pk,
                &params,
            )
            .unwrap_err(),
            SignaturePoKError::MessageInputError(MessageUnpackingError::LessMessagesThanExpected {
                provided: 9,
                expected: 10
            })
        );
    }

    #[test]
    fn invalid_revealed_indices_order() {
        cfg_into_iter!(4..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            let (blind_msgs, reveal_msgs): (Vec<_>, Vec<_>) =
                msgs.iter().enumerate().partition(|(idx, _)| idx % 2 == 0);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

            let pok = SignaturePoKGenerator::init(
                &mut rng,
                blind_msgs
                    .iter()
                    .map(|(_, msg)| **msg)
                    .map(CommitMessage::BlindMessageRandomly)
                    .interleave(reveal_msgs.iter().map(|_| CommitMessage::RevealMessage)),
                &sig,
                &pk,
                &params,
            )
            .unwrap();

            let mut chal_bytes = vec![];
            pok.challenge_contribution(&mut chal_bytes, &pk, &params)
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let proof = pok.clone().gen_proof(&challenge).unwrap();
            let mut revealed = reveal_msgs.into_iter().rev();

            assert_eq!(
                proof.verify(&challenge, revealed.clone(), &pk, &params,),
                Err(SignaturePoKError::RevealedIndicesMustBeUniqueAndSorted {
                    previous: revealed.next().unwrap().0,
                    current: revealed.next().unwrap().0
                })
            );
        })
    }

    #[test]
    fn empty_proof() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, pk, params, messages) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);

        let sig = Signature::new(&mut rng, messages.as_slice(), &sk, &params).unwrap();

        let pok = SignaturePoKGenerator::init(
            &mut rng,
            messages.iter().map(|_| CommitMessage::RevealMessage),
            &sig,
            &pk,
            &params,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        pok.challenge_contribution(&mut chal_bytes, &pk, &params)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let proof = pok.clone().gen_proof(&challenge).unwrap();
        let revealed = messages.iter().enumerate().into_iter().rev();

        assert!(proof
            .verify(&challenge, revealed.clone(), &pk, &params)
            .is_ok());
    }

    #[test]
    fn invalid_proof() {
        cfg_into_iter!(1..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, messages) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);
            let (_sk, pk1, _params, _messages) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            let sig = Signature::new(&mut rng, messages.as_slice(), &sk, &params).unwrap();

            let pok = SignaturePoKGenerator::init(&mut rng, &messages, &sig, &pk, &params).unwrap();

            let mut chal_bytes = vec![];
            pok.challenge_contribution(&mut chal_bytes, &pk, &params)
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let mut proof = pok.clone().gen_proof(&challenge).unwrap();

            assert!(proof.verify(&challenge, empty(), &pk, &params).is_ok());
            assert!(proof.verify(&challenge, empty(), &pk1, &params).is_err());
            *proof.k.value = G2Projective::rand(&mut rng).into_affine();
            assert!(proof.verify(&challenge, empty(), &pk, &params).is_err())
        })
    }

    #[test]
    fn get_resp_for_message() {
        (4..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            let (reveal_msgs, blind_msgs) = msgs.split_at(message_count as usize / 2);
            let comms = reveal_msgs
                .iter()
                .map(|_| CommitMessage::RevealMessage)
                .chain(
                    blind_msgs
                        .iter()
                        .copied()
                        .map(CommitMessage::BlindMessageRandomly),
                );
            let reveal_indices = 0..reveal_msgs.len();
            let committed_msg_indices = message_count as usize / 2..msgs.len();

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

            let pok = SignaturePoKGenerator::init(&mut rng, comms, &sig, &pk, &params).unwrap();

            let mut chal_bytes = vec![];
            pok.challenge_contribution(&mut chal_bytes, &pk, &params)
                .unwrap();
            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

            let proof = pok.clone().gen_proof(&challenge).unwrap();

            for idx in committed_msg_indices {
                assert_eq!(
                    proof
                        .response_for_message(idx, reveal_indices.clone())
                        .unwrap(),
                    proof
                        .k
                        .response
                        .0
                        .get(idx.max(message_count as usize / 2) - (message_count as usize / 2))
                        .unwrap()
                );
                assert_eq!(
                    proof
                        .k
                        .response_for_message(idx, reveal_indices.clone())
                        .unwrap(),
                    proof
                        .k
                        .response
                        .0
                        .get(idx.max(message_count as usize / 2) - (message_count as usize / 2))
                        .unwrap()
                );

                assert_eq!(
                    proof.response_for_message(idx, idx..idx + 1).unwrap_err(),
                    SignaturePoKError::SchnorrError(schnorr_error(SchnorrError::InvalidResponse))
                );
            }
        })
    }

    #[test]
    fn invalid_message_count() {
        cfg_into_iter!(1..10).for_each(|message_count| {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, messages) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);
            let (_sk, _pk1, _params, invalid_messages) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count + 1);

            let sig = Signature::new(&mut rng, messages.as_slice(), &sk, &params).unwrap();

            assert!(
                SignaturePoKGenerator::init(&mut rng, &invalid_messages, &sig, &pk, &params)
                    .is_err()
            );
        })
    }
}
