//! Pedersen Distributed Verifiable secret sharing. Based on the paper "Non-interactive and information-theoretic
//! secure verifiable secret sharing", section 5. https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
//! Does not involve a trusted third party but assumes that all participants (and not just threshold) participate till the end.
//! Even if one participant aborts, the protocol needs to be restarted. A workaround is for each participant to ignore the
//! faulty participant's share essentially making it such that the faulty participant was never there.
//! - `n` participants want to generate a shared secret `s` `k-of-n` manner
//! - Each of the `n` participants chooses a secret and runs a VSS for that secret in `k-of-n` manner. Say participant `i` chooses a secret `{s_i}_0`
//! - The shared secret `s` the becomes sum of secrets chosen by all `n` participants so `s = {s_1}_0 + {s_2}_0 + {s_3}_0 + ... {s_n}_0`
//! - After each of the `n` participants has successfully runs a VSS, they generate their corresponding share of `s` by adding
//! their shares of each `{s_i}_0` for `i` in 1 to `n`.

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::collections::BTreeMap;
use ark_std::io::{Read, Write};
use ark_std::vec;
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use zeroize::Zeroize;

use crate::common::{CommitmentToCoefficients, ParticipantId, ShareId, VerifiableShare};
use crate::error::SSError;
use crate::pedersen_vss::CommitmentKey;

/// Used by a participant to store received shares and commitment coefficients.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct SharesAccumulator<G: AffineCurve> {
    pub participant_id: ParticipantId,
    pub threshold: ShareId,
    pub shares: BTreeMap<ParticipantId, VerifiableShare<G::ScalarField>>,
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
        comm_key: &CommitmentKey<G>,
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
        self,
        comm_key: &CommitmentKey<G>,
    ) -> Result<VerifiableShare<G::ScalarField>, SSError> {
        // TODO: Here assuming that all participants submit their share but we should be able to tolerate faults
        // here and accepts a participant size s with threshold < s <= total

        let mut final_s_share = G::ScalarField::zero();
        let mut final_t_share = G::ScalarField::zero();
        let mut final_comm_coeffs = vec![G::Projective::zero(); self.threshold as usize];

        for (_, share) in self.shares {
            final_s_share += share.secret_share;
            final_t_share += share.blinding_share;
        }

        for (_, comm) in self.coeff_comms {
            for i in 0..self.threshold as usize {
                final_comm_coeffs[i].add_assign_mixed(&comm.0[i]);
            }
        }
        let comm_coeffs = batch_normalize_projective_into_affine(final_comm_coeffs).into();
        let final_share = VerifiableShare {
            id: self.participant_id,
            threshold: self.threshold,
            secret_share: final_s_share,
            blinding_share: final_t_share,
        };
        final_share.verify(&comm_coeffs, comm_key)?;
        Ok(final_share)
    }

    /// Update accumulator on share sent by another party. Verifies the share and rejects an invalid share.
    fn update(
        &mut self,
        id: ParticipantId,
        share: VerifiableShare<G::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<G>,
        comm_key: &CommitmentKey<G>,
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
    use crate::common::VerifiableShares;
    use crate::pedersen_vss::{deal_random_secret, CommitmentKey};
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b;

    type G1 = <Bls12_381 as PairingEngine>::G1Affine;
    type G2 = <Bls12_381 as PairingEngine>::G2Affine;

    #[test]
    fn pedersen_distributed_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key1 = CommitmentKey::<G1>::new::<Blake2b>(b"test");
        let comm_key2 = CommitmentKey::<G2>::new::<Blake2b>(b"test");

        fn check<G: AffineCurve>(rng: &mut StdRng, comm_key: &CommitmentKey<G>) {
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
                for i in 1..=total {
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
                    for j in 1..=total {
                        if i != j {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = shares.0[j - 1].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    share_with_wrong_id,
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = shares.0[j - 1].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    share_with_wrong_threshold,
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0.remove(0);
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    shares.0[j - 1].clone(),
                                    wrong_commitments,
                                    &comm_key,
                                )
                                .is_err());

                            let mut wrong_commitments = commitments.clone();
                            wrong_commitments.0[0] = wrong_commitments.0[0]
                                .into_projective()
                                .double()
                                .into_affine();
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    shares.0[j - 1].clone(),
                                    wrong_commitments,
                                    &comm_key,
                                )
                                .is_err());

                            // Participant processes a valid received share
                            accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .unwrap();

                            // Adding duplicate share not allowed
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());
                        } else {
                            // Participant processes its own share for its created secret
                            accumulators[j - 1]
                                .add_self_share(shares.0[j - 1].clone(), commitments.clone());

                            // Cannot add share with own id
                            assert!(accumulators[j - 1]
                                .add_received_share(
                                    i as u16,
                                    shares.0[j - 1].clone(),
                                    commitments.clone(),
                                    &comm_key,
                                )
                                .is_err());
                        }
                    }
                }

                for accumulator in accumulators {
                    let share = accumulator.finalize(&comm_key).unwrap();
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
