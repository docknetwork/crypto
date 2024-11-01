//! Feldman Distributed Verifiable secret sharing and distributed key generation.

use crate::{common, common::ShareId, error::SSError};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::vec::Vec;

/// Reconstruct threshold key using the individual public keys. Multiplies each public key with its
/// Lagrange coefficient and adds the result. Assumes that public key ids are unique
pub fn reconstruct_threshold_public_key<G: AffineRepr>(
    public_keys: Vec<(ShareId, G)>,
    threshold: ShareId,
) -> Result<G, SSError> {
    let len = public_keys.len() as ShareId;
    if threshold > len {
        return Err(SSError::BelowThreshold(threshold, len));
    }
    let pkt = &public_keys[0..threshold as usize];
    let pk_ids = pkt.iter().map(|(i, _)| *i).collect::<Vec<_>>();
    let pks = pkt.iter().map(|(_, pk)| *pk).collect::<Vec<_>>();
    let lcs = common::lagrange_basis_at_0_for_all::<G::ScalarField>(pk_ids)?;
    Ok(G::Group::msm_unchecked(&pks, &lcs).into_affine())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        common::{ParticipantId, Share, Shares, SharesAccumulator},
        feldman_vss::deal_random_secret,
    };
    use ark_ec::Group;
    use ark_ff::PrimeField;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use test_utils::{test_serialization, G1, G2};

    #[test]
    fn feldman_distributed_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, g: &G) {
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
                        SharesAccumulator::<G, Share<G::ScalarField>>::new(
                            i as ParticipantId,
                            threshold as ShareId,
                        )
                    })
                    .collect::<Vec<_>>();
                let mut secrets = vec![];
                let mut final_shares = vec![];

                // Each participant creates a secret and secret-shares it with other participants
                for sender_id in 1..=total {
                    // Participant creates a secret and its shares
                    let (secret, shares, commitments, _) =
                        deal_random_secret::<_, G>(rng, threshold as ShareId, total as ShareId, g)
                            .unwrap();
                    secrets.push(secret);
                    // The participant sends other participants their respective shares and stores its own share as well
                    for receiver_id in 1..=total {
                        if sender_id != receiver_id {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = shares.0[receiver_id - 1].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    share_with_wrong_id,
                                    commitments.clone(),
                                    g,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = shares.0[receiver_id - 1].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    share_with_wrong_threshold,
                                    commitments.clone(),
                                    g,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0.remove(0);
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    shares.0[receiver_id - 1].clone(),
                                    wrong_commitments,
                                    g,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0[0] =
                                wrong_commitments.0[0].into_group().double().into_affine();
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    shares.0[receiver_id - 1].clone(),
                                    wrong_commitments,
                                    g,
                                )
                                .is_err());

                            // Participant processes a received share
                            accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    g,
                                )
                                .unwrap();

                            // Adding duplicate share not allowed
                            assert!(accumulators[receiver_id - 1]
                                .add_received_share(
                                    sender_id as ParticipantId,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    g,
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
                                    sender_id as ParticipantId,
                                    shares.0[receiver_id - 1].clone(),
                                    commitments.clone(),
                                    g,
                                )
                                .is_err());
                        }

                        // Cannot create the final share when having shares from less than threshold number of participants
                        if (accumulators[receiver_id - 1].shares.len() as ShareId) < threshold {
                            assert!(accumulators[receiver_id - 1].clone().finalize(g).is_err());
                        }
                    }
                }

                if !checked_serialization {
                    test_serialization!(SharesAccumulator<G, Share<G::ScalarField>>, accumulators[0].clone());
                    checked_serialization = true;
                }

                let mut tk = None;
                let mut all_pk = vec![];
                // Each participant computes its share of the final secret
                for accumulator in accumulators {
                    let (share, pk, t_pk) = accumulator.finalize(g).unwrap();
                    assert_eq!(g.mul_bigint(share.share.into_bigint()).into_affine(), pk);
                    if tk.is_none() {
                        tk = Some(t_pk);
                    } else {
                        // All generate the same threshold key
                        assert_eq!(tk, Some(t_pk));
                    }
                    all_pk.push(pk);
                    final_shares.push(share);
                }

                let final_secret = secrets.iter().sum::<G::ScalarField>();
                let final_shares = Shares(final_shares);

                assert_eq!(final_shares.reconstruct_secret().unwrap(), final_secret);

                let pk_with_ids = all_pk
                    .into_iter()
                    .enumerate()
                    .map(|(i, pk)| ((i + 1) as ShareId, pk))
                    .collect::<Vec<_>>();
                assert_eq!(
                    tk,
                    Some(reconstruct_threshold_public_key(pk_with_ids, threshold).unwrap())
                );
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
