//! Pedersen Distributed Verifiable secret sharing. Based on the paper "Non-interactive and information-theoretic
//! secure verifiable secret sharing", section 5. <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>
//! Does not involve a trusted third party but assumes that all participants (and not just threshold) participate till the end.
//! Even if one participant aborts, the protocol needs to be restarted. A workaround is for each participant to ignore the
//! faulty participant's share essentially making it such that the faulty participant was never there.
//! - `n` participants want to generate a shared secret `s` `k-of-n` manner
//! - Each of the `n` participants chooses a secret and runs a VSS for that secret in `k-of-n` manner. Say participant `i` chooses a secret `{s_i}_0`
//! - The shared secret `s` the becomes sum of secrets chosen by all `n` participants so `s = {s_1}_0 + {s_2}_0 + {s_3}_0 + ... {s_n}_0`
//! - After each of the `n` participants has successfully runs a VSS, they generate their corresponding share of `s` by adding
//! their shares of each `{s_i}_0` for `i` in 1 to `n`.

#[cfg(test)]
pub mod tests {
    use crate::{
        common::{ParticipantId, ShareId, SharesAccumulator, VerifiableShare, VerifiableShares},
        pedersen_vss::deal_random_secret,
    };
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use dock_crypto_utils::commitment::PedersenCommitmentKey;
    use test_utils::{test_serialization, G1, G2};

    #[test]
    fn pedersen_distributed_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key1 = PedersenCommitmentKey::<G1>::new::<Blake2b512>(b"test");
        let comm_key2 = PedersenCommitmentKey::<G2>::new::<Blake2b512>(b"test");

        fn check<G: AffineRepr>(rng: &mut StdRng, comm_key: &PedersenCommitmentKey<G>) {
            let mut checked_serialization = false;
            for (threshold, total) in vec![
                (2, 2),
                (2, 3),
                (2, 4),
                (2, 5),
                (3, 3),
                (3, 4),
                (3, 5),
                (4, 5),
                (4, 8),
                (4, 9),
                (4, 12),
                (5, 5),
                (5, 7),
                (5, 10),
                (5, 13),
                (7, 10),
                (7, 15),
            ] {
                // There are `total` number of participants
                let mut accumulators = (1..=total)
                    .map(|i| {
                        SharesAccumulator::<G, VerifiableShare<G::ScalarField>>::new(
                            i as ParticipantId,
                            threshold as ShareId,
                        )
                    })
                    .collect::<Vec<_>>();
                let mut secrets = vec![];
                let mut blindings = vec![];
                let mut final_shares = vec![];

                // Each participant creates a secret and secret-shares it with other participants
                for sender_id in 1..=total {
                    // Participant creates a secret and its shares
                    let (secret, blinding, shares, commitments, _, _) = deal_random_secret::<_, G>(
                        rng,
                        threshold as ShareId,
                        total as ShareId,
                        &comm_key,
                    )
                    .unwrap();
                    secrets.push(secret);
                    blindings.push(blinding);
                    // The participant sends other participants their respective shares and stores its own share as well
                    for receiver_id in 1..=total {
                        if sender_id != receiver_id {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = shares.0[receiver_id - 1].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    share_with_wrong_id,
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = shares.0[receiver_id - 1].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    share_with_wrong_threshold,
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0.remove(0);
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    shares.0[receiver_id - 1].clone(),
                                    wrong_commitments,
                                    &comm_key,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0[0] =
                                wrong_commitments.0[0].into_group().double().into_affine();
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    shares.0[receiver_id - 1].clone(),
                                    wrong_commitments,
                                    &comm_key,
                                )
                                .is_err());

                            // Participant processes a valid received share
                            accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .unwrap();

                            // Adding duplicate share not allowed
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());
                        } else {
                            // Participant processes its own share for its created secret
                            accumulators[receiver_id - 1].add_self_share(
                                shares.0[receiver_id - 1].clone(),
                                commitments.clone(),
                            );

                            // Cannot add share with own id
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as u16,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());
                        }

                        // Cannot create the final share when having shares from less than threshold number of participants
                        if (accumulators[receiver_id - 1].shares.len() as ShareId) < threshold {
                            assert!(accumulators[receiver_id - 1]
                                .clone()
                                .finalize(comm_key)
                                .is_err());
                        }
                    }
                }

                if !checked_serialization {
                    test_serialization!(SharesAccumulator<G, VerifiableShare<G::ScalarField>>, accumulators[0].clone());
                    checked_serialization = true;
                }

                for accumulator in accumulators {
                    let share = accumulator.finalize(comm_key).unwrap();
                    final_shares.push(share);
                }

                let final_secret = secrets.iter().sum::<G::ScalarField>();
                let final_blinding = blindings.iter().sum::<G::ScalarField>();
                let final_shares = VerifiableShares(final_shares);

                let (secret, blinding) = final_shares.reconstruct_secret().unwrap();
                assert_eq!(secret, final_secret);
                assert_eq!(blinding, final_blinding);
            }
        }

        check(&mut rng, &comm_key1);
        check(&mut rng, &comm_key2);
    }
}
