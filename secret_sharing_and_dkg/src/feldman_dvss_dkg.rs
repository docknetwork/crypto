//! Feldman Distributed Verifiable secret sharing and distributed key generation.

use crate::common::{lagrange_basis_at_0, CommitmentToCoefficients, ParticipantId, Share, ShareId};
use crate::error::SSError;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::collections::BTreeMap;
use ark_std::io::{Read, Write};
use ark_std::{cfg_iter, vec, vec::Vec};
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use zeroize::Zeroize;

use dock_crypto_utils::msm::variable_base_msm;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Used by a participant to store received shares and commitment coefficients.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct SharesAccumulator<G: AffineCurve> {
    pub participant_id: ParticipantId,
    pub threshold: ShareId,
    pub shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
}

impl<G: AffineCurve> SharesAccumulator<G> {
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
    pub fn add_received_share(
        &mut self,
        sender_id: ParticipantId,
        share: Share<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        ck: &G,
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
        self.update(sender_id, share, commitment_coeffs, ck)
    }

    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret, own public key and the threshold public key
    pub fn finalize(self, ck: &G) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        Self::gen_final_share_and_public_key(
            self.participant_id,
            self.threshold,
            self.shares,
            self.coeff_comms,
            ck,
        )
    }

    /// Compute the final share after receiving shares from all other participants. Also returns
    /// own public key and the threshold public key
    pub fn gen_final_share_and_public_key(
        participant_id: ParticipantId,
        threshold: ShareId,
        shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
        coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
        ck: &G,
    ) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        // TODO: Here assuming that all participants submit their share but we should be able to tolerate faults
        // here and accepts a participant size s with threshold < s <= total

        let mut final_share = G::ScalarField::zero();
        let mut final_comm_coeffs = vec![G::Projective::zero(); threshold as usize];

        for (_, share) in shares {
            final_share += share.share;
        }

        let mut threshold_pk = G::Projective::zero();
        for comm in coeff_comms.values() {
            for i in 0..threshold as usize {
                final_comm_coeffs[i].add_assign_mixed(&comm.0[i]);
            }
            threshold_pk.add_assign_mixed(comm.commitment_to_secret());
        }
        let comm_coeffs = batch_normalize_projective_into_affine(final_comm_coeffs).into();
        let pk = ck.mul(final_share.into_repr()).into_affine();
        let final_share = Share {
            id: participant_id,
            threshold,
            share: final_share,
        };
        final_share.verify(&comm_coeffs, ck)?;
        Ok((final_share, pk, threshold_pk.into_affine()))
    }

    /// Update accumulator on share sent by another party. Verifies the share and rejects an invalid share.
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
/// Lagrange coefficient and adds the result
pub fn reconstruct_threshold_public_key<G: AffineCurve>(
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
    let lcs = cfg_iter!(pk_ids)
        .map(|i| lagrange_basis_at_0::<G::ScalarField>(&pk_ids, *i))
        .collect::<Vec<_>>();
    Ok(variable_base_msm(&pks, &lcs).into_affine())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::common::Shares;
    use crate::feldman_vss::deal_random_secret;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;

    #[test]
    fn feldman_distributed_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
        let g2 = <Bls12_381 as PairingEngine>::G2Projective::rand(&mut rng).into_affine();

        fn check<G: AffineCurve>(rng: &mut StdRng, g: &G) {
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
                for i in 1..=total {
                    // Participant creates a secret and its shares
                    let (secret, shares, commitments, _) =
                        deal_random_secret::<_, G>(rng, threshold as ShareId, total as ShareId, g)
                            .unwrap();
                    secrets.push(secret);
                    // The participant sends other participants their respective shares and stores its own share as well
                    for j in 1..=total {
                        if i != j {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = shares.0[j - 1].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    share_with_wrong_id,
                                    commitments.clone(),
                                    &g,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = shares.0[j - 1].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    share_with_wrong_threshold,
                                    commitments.clone(),
                                    &g,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0.remove(0);
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    shares.0[j - 1].clone(),
                                    wrong_commitments,
                                    &g,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0[0] = wrong_commitments.0[0]
                                .into_projective()
                                .double()
                                .into_affine();
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    shares.0[j - 1].clone(),
                                    wrong_commitments,
                                    &g,
                                )
                                .is_err());

                            // Participant processes a received share
                            accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    g,
                                )
                                .unwrap();

                            // Adding duplicate share not allowed
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    &g,
                                )
                                .is_err());
                        } else {
                            // Participant processes its own share for its created secret
                            accumulators[j - 1]
                                .add_self_share(shares.0[j - 1].clone(), commitments.clone());

                            // Cannot add share with own id
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as ParticipantId,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    &g,
                                )
                                .is_err());
                        }
                    }
                }

                let mut tk = None;
                let mut all_pk = vec![];
                // Each participant computes its share of the final secret
                for accumulator in accumulators {
                    let (share, pk, t_pk) = accumulator.finalize(g).unwrap();
                    assert_eq!(g.mul(share.share.into_repr()).into_affine(), pk);
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
