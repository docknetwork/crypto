//! Shamir secret sharing.

use alloc::vec::Vec;

use ark_ff::PrimeField;
use ark_std::rand::RngCore;

use super::*;
use secret_sharing_and_dkg::{error::SSError, shamir_ss};

use crate::setup::SecretKey;

/// Produces threshold secret key and individual secret keys supporting `message_count` messages for all participants.
pub fn deal<R: RngCore, F: PrimeField>(
    rng: &mut R,
    message_count: u32,
    Threshold(threshold, total): Threshold,
) -> Result<(SecretKey<F>, Vec<SecretKey<F>>), SSError> {
    let sk = SecretKey::rand(rng, message_count);

    let mut all_shares = SecretKeyModel::from(&sk).try_map_ref_mut(|secret| {
        let secret = core::mem::take(secret);

        shamir_ss::deal_secret(rng, secret, threshold, total)
            .map(|(secret_shares, _)| secret_shares.0.into_iter())
    })?;

    let secrets = (1..=total)
        .map(|_| all_shares.map_ref_mut(|iter| iter.next().unwrap()))
        .map(Into::into)
        .collect();

    Ok((sk, secrets))
}

#[cfg(test)]
mod shamir_ss_tests {
    use super::Threshold;
    use alloc::vec::Vec;

    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::{
        cfg_into_iter,
        rand::{rngs::StdRng, SeedableRng},
    };
    use blake2::Blake2b512;

    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use secret_sharing_and_dkg::common::{Share, Shares};

    use crate::{
        helpers::{n_rand, skip_up_to_n},
        setup::{keygen::common::SecretKeyModel, test_setup, PublicKey},
        AggregatedSignature, BlindSignature, CommitmentOrMessage, MessageCommitment,
    };

    type G1 = <Bls12_381 as Pairing>::G1;

    #[test]
    fn basic_keygen() {
        cfg_into_iter!(2..5).for_each(|message_count| {
            cfg_into_iter!(1..message_count).for_each(|blind_message_count| {
                cfg_into_iter!(4..6).for_each(|authority_count| {
                    let mut rng = StdRng::seed_from_u64(0u64);
                    let h = G1::rand(&mut rng).into_affine();
                    let (_, _, params, msgs) =
                        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

                    let (blind_msgs, reveal_msgs) = msgs.split_at(blind_message_count as usize);
                    let blind_indices = 0..blind_msgs.len();

                    let blindings: Vec<_> = n_rand(&mut rng, blind_msgs.len()).collect();
                    let o_m_pairs = utils::pairs!(blindings, blind_msgs);

                    let m_comms: Vec<_> =
                        MessageCommitment::new_iter(o_m_pairs, &h, &params).collect();
                    let comm_and_blindings = m_comms
                        .iter()
                        .copied()
                        .map(CommitmentOrMessage::BlindedMessage)
                        .chain(
                            reveal_msgs
                                .iter()
                                .copied()
                                .map(CommitmentOrMessage::RevealedMessage),
                        );
                    let threshold =
                        Threshold::new(1.max(authority_count / 2), authority_count).unwrap();

                    let (threshold_sk, sks) =
                        super::deal(&mut rng, message_count as u32, threshold).unwrap();

                    let vk = PublicKey::new(&threshold_sk, &params);

                    let (sks, sigs): (Vec<_>, Vec<_>) = sks
                        .into_iter()
                        .map(|sk| {
                            let pk = PublicKey::new(&sk, &params);
                            let blind_signature =
                                BlindSignature::new(comm_and_blindings.clone(), &sk, &h).unwrap();

                            let sig = blind_signature
                                .unblind(blind_indices.clone().zip(&blindings), &pk, &h)
                                .unwrap();

                            (sk, sig)
                        })
                        .unzip();

                    for i in threshold.into_iter().map(|v| v as usize) {
                        let shares: SecretKeyModel<Vec<Share<_>>> = skip_up_to_n(
                            &mut rng,
                            sks.iter().map(SecretKeyModel::from).enumerate(),
                            authority_count as usize - i,
                        )
                        .map(|(idx, model)| {
                            model.map(|share| Share {
                                share,
                                id: idx as u16 + 1,
                                threshold: 1.max(authority_count / 2),
                            })
                        })
                        .collect();

                        let combined_shares = shares
                            .map(Shares)
                            .map(|shares| Shares::reconstruct_secret(&shares).unwrap());

                        assert_eq!(combined_shares, SecretKeyModel::from(&threshold_sk));

                        let signatures = skip_up_to_n(
                            &mut rng,
                            sigs.iter().enumerate(),
                            authority_count as usize - i,
                        )
                        .map(|(idx, v)| (idx as u16 + 1, v));

                        let aggregated = AggregatedSignature::new(signatures, &h).unwrap();
                        aggregated.verify(&msgs, &vk, &params).unwrap();
                    }

                    for i in 1..threshold.0 as usize {
                        let signatures = skip_up_to_n(
                            &mut rng,
                            sigs.iter().enumerate().map(|(idx, v)| (idx as u16 + 1, v)),
                            i,
                        )
                        .take(i);

                        let aggregated = AggregatedSignature::new(signatures, &h).unwrap();
                        aggregated.verify(&msgs, &vk, &params).unwrap_err();
                    }
                })
            })
        });
    }
}
