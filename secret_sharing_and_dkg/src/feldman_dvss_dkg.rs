//! Feldman Distributed Verifiable secret sharing and distributed key generation.

use crate::{
    common,
    common::{CommitmentToCoefficients, ParticipantId, Share, ShareId},
    error::SSError,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Used by a participant to store received shares and commitment coefficients.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SharesAccumulator<G: AffineRepr> {
    pub participant_id: ParticipantId,
    pub threshold: ShareId,
    pub shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
}

impl<G: AffineRepr> Zeroize for SharesAccumulator<G> {
    fn zeroize(&mut self) {
        self.shares.values_mut().for_each(|v| v.zeroize())
    }
}

impl<G: AffineRepr> Drop for SharesAccumulator<G> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<G: AffineRepr> SharesAccumulator<G> {
    pub fn new(id: ParticipantId, threshold: ShareId) -> Self {
        Self {
            participant_id: id,
            threshold,
            shares: Default::default(),
            coeff_comms: Default::default(),
        }
    }

    /// Called by a participant when it creates a share for itself
    pub fn add_self_share(
        &mut self,
        share: Share<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
    ) {
        self.update_unchecked(self.participant_id, share, commitment_coeffs)
    }

    /// Called by a participant when it receives a share from another participant
    pub fn add_received_share<'a>(
        &mut self,
        sender_id: ParticipantId,
        share: Share<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        ck: impl Into<&'a G>,
    ) -> Result<(), SSError> {
        if sender_id == self.participant_id {
            return Err(SSError::SenderIdSameAsReceiver(
                sender_id,
                self.participant_id,
            ));
        }
        if self.shares.contains_key(&sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(sender_id));
        }
        self.update(sender_id, share, commitment_coeffs, ck.into())
    }

    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret, own public key and the threshold public key
    pub fn finalize<'a>(
        mut self,
        ck: impl Into<&'a G> + Clone,
    ) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        let shares = core::mem::take(&mut self.shares);
        let comms = core::mem::take(&mut self.coeff_comms);
        Self::gen_final_share_and_public_key(self.participant_id, self.threshold, shares, comms, ck)
    }

    /// Compute the final share after receiving shares from all other participants. Also returns
    /// own public key and the threshold public key
    pub fn gen_final_share_and_public_key<'a>(
        participant_id: ParticipantId,
        threshold: ShareId,
        shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
        coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
        ck: impl Into<&'a G> + Clone,
    ) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        // Check early that sufficient shares present
        let len = shares.len() as ShareId;
        if threshold > len {
            return Err(SSError::BelowThreshold(threshold, len));
        }

        let mut final_share = G::ScalarField::zero();
        let mut final_comm_coeffs = vec![G::Group::zero(); threshold as usize];

        for (_, share) in shares {
            final_share += share.share;
        }

        let mut threshold_pk = G::Group::zero();
        for comm in coeff_comms.values() {
            for i in 0..threshold as usize {
                final_comm_coeffs[i] += comm.0[i];
            }
            threshold_pk += comm.commitment_to_secret();
        }
        let comm_coeffs = G::Group::normalize_batch(&final_comm_coeffs).into();
        let final_share = Share {
            id: participant_id,
            threshold,
            share: final_share,
        };
        final_share.verify(&comm_coeffs, ck.clone())?;
        let pk = ck
            .into()
            .mul_bigint(final_share.share.into_bigint())
            .into_affine();
        Ok((final_share, pk, threshold_pk.into_affine()))
    }

    /// Update accumulator on share sent by another party. If the share verifies, stores it.
    fn update(
        &mut self,
        id: ParticipantId,
        share: Share<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        ck: &G,
    ) -> Result<(), SSError> {
        if self.participant_id != share.id {
            return Err(SSError::UnequalParticipantAndShareId(
                self.participant_id,
                share.id,
            ));
        }
        if self.threshold != share.threshold {
            return Err(SSError::UnequalThresholdInReceivedShare(
                self.threshold,
                share.threshold,
            ));
        }
        share.verify(&commitment_coeffs, ck)?;
        self.update_unchecked(id, share, commitment_coeffs);
        Ok(())
    }

    /// Update accumulator on share created by self. Assumes the share is valid
    fn update_unchecked(
        &mut self,
        id: ParticipantId,
        share: Share<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
    ) {
        self.shares.insert(id, share);
        self.coeff_comms.insert(id, commitment_coeffs);
    }
}

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
    use crate::{common::Shares, feldman_vss::deal_random_secret};
    use ark_ec::Group;
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
                    .map(|i| SharesAccumulator::new(i as ParticipantId, threshold as ShareId))
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
                    test_serialization!(SharesAccumulator<G>, accumulators[0].clone());
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
