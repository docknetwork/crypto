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

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, vec, vec::Vec};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    common::{CommitmentToCoefficients, ParticipantId, ShareId, VerifiableShare},
    error::SSError,
};

/// Used by a participant to store received shares and commitment coefficients.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SharesAccumulator<G: AffineRepr> {
    pub participant_id: ParticipantId,
    pub threshold: ShareId,
    pub shares: BTreeMap<ParticipantId, VerifiableShare<G::ScalarField>>,
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
        share: VerifiableShare<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
    ) {
        self.update_unchecked(self.participant_id, share, commitment_coeffs)
    }

    /// Called by a participant when it receives a share from another participant
    pub fn add_received_share(
        &mut self,
        sender_id: ParticipantId,
        share: VerifiableShare<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        comm_key: &PedersenCommitmentKey<G>,
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
        self.update(sender_id, share, commitment_coeffs, comm_key)
    }

    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret
    pub fn finalize(
        mut self,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<VerifiableShare<G::ScalarField>, SSError> {
        // Check early that sufficient shares present
        let len = self.shares.len() as ShareId;
        if self.threshold > len {
            return Err(SSError::BelowThreshold(self.threshold, len));
        }

        let mut final_s_share = G::ScalarField::zero();
        let mut final_t_share = G::ScalarField::zero();
        let mut final_comm_coeffs = vec![G::Group::zero(); self.threshold as usize];

        let shares = core::mem::take(&mut self.shares);
        let comms = core::mem::take(&mut self.coeff_comms);

        for (_, share) in shares {
            final_s_share += share.secret_share;
            final_t_share += share.blinding_share;
        }

        for (_, comm) in comms {
            for i in 0..self.threshold as usize {
                final_comm_coeffs[i] += comm.0[i];
            }
        }
        let comm_coeffs = G::Group::normalize_batch(&final_comm_coeffs).into();
        let final_share = VerifiableShare {
            id: self.participant_id,
            threshold: self.threshold,
            secret_share: final_s_share,
            blinding_share: final_t_share,
        };
        final_share.verify(&comm_coeffs, comm_key)?;
        Ok(final_share)
    }

    /// Update accumulator on share sent by another party. If the share verifies, stores it.
    fn update(
        &mut self,
        id: ParticipantId,
        share: VerifiableShare<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        comm_key: &PedersenCommitmentKey<G>,
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
        share.verify(&commitment_coeffs, comm_key)?;
        self.update_unchecked(id, share, commitment_coeffs);
        Ok(())
    }

    /// Update accumulator on share created by self. Assumes the share is valid
    fn update_unchecked(
        &mut self,
        id: ParticipantId,
        share: VerifiableShare<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
    ) {
        self.shares.insert(id, share);
        self.coeff_comms.insert(id, commitment_coeffs);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{common::VerifiableShares, pedersen_vss::deal_random_secret};
    use ark_ec::Group;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
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
                    .map(|i| SharesAccumulator::new(i as ParticipantId, threshold as ShareId))
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
                    test_serialization!(SharesAccumulator<G>, accumulators[0].clone());
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
