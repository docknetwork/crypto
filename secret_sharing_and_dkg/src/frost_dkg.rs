//! This is the keygen implemented in the [FROST paper](https://eprint.iacr.org/2020/852.pdf) in Figure 1.
//! This is a slight addition to the DKG based on Feldman VSS as it contains a Schnorr proof of knowledge
//! for the secret key.

use crate::{
    common::{CommitmentToCoefficients, ParticipantId, Share, ShareId, Shares},
    error::SSError,
    feldman_dvss_dkg, feldman_vss,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::{
    compute_random_oracle_challenge, error::SchnorrError, impl_proof_of_knowledge_of_discrete_log,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

impl_proof_of_knowledge_of_discrete_log!(SecretKeyKnowledgeProtocol, SecretKeyKnowledge);

/// State of a participant during Round 1
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round1State<G: AffineRepr> {
    pub id: ParticipantId,
    pub threshold: ShareId,
    pub shares: Shares<G::ScalarField>,
    /// Stores the commitment to the coefficients of the polynomial by each participant
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
    /// Secret chosen by the participant
    pub secret: G::ScalarField,
}

/// Message sent by a participant during Round 1
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round1Msg<G: AffineRepr> {
    pub sender_id: ParticipantId,
    pub comm_coeffs: CommitmentToCoefficients<G>,
    /// Proof of knowledge of the secret key for the public key
    pub schnorr_proof: SecretKeyKnowledge<G>,
}

/// State of a participant during Round 2
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round2State<G: AffineRepr> {
    pub id: ParticipantId,
    pub threshold: ShareId,
    /// Stores the shares sent by each participant
    pub shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
    /// Stores the commitment to the coefficients of the polynomial by each participant. Created during Round 1
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
}

impl<G: AffineRepr> Round1State<G> {
    /// Start Phase 1 with a randomly generated secret.
    pub fn start_with_random_secret<R: RngCore, D: Digest>(
        rng: &mut R,
        participant_id: ParticipantId,
        threshold: ShareId,
        total: ShareId,
        schnorr_proof_ctx: &[u8],
        comm_key: &G,
    ) -> Result<(Self, Round1Msg<G>), SSError> {
        let secret = G::ScalarField::rand(rng);
        Self::start_with_given_secret::<R, D>(
            rng,
            participant_id,
            secret,
            threshold,
            total,
            schnorr_proof_ctx,
            comm_key,
        )
    }

    /// Start Phase 1 with a given secret.
    pub fn start_with_given_secret<R: RngCore, D: Digest>(
        rng: &mut R,
        id: ParticipantId,
        secret: G::ScalarField,
        threshold: ShareId,
        total: ShareId,
        schnorr_proof_ctx: &[u8],
        comm_key: &G,
    ) -> Result<(Self, Round1Msg<G>), SSError> {
        // Create shares of the secret and commit to it
        let (shares, commitments, _) =
            feldman_vss::deal_secret::<R, G>(rng, secret, threshold, total, comm_key)?;
        let mut coeff_comms = BTreeMap::new();
        coeff_comms.insert(id, commitments.clone());

        // Create the proof of knowledge for the secret key
        let blinding = G::ScalarField::rand(rng);
        let schnorr = SecretKeyKnowledgeProtocol::init(secret, blinding, comm_key);
        let mut challenge_bytes = vec![];
        schnorr
            .challenge_contribution(
                comm_key,
                commitments.commitment_to_secret(),
                &mut challenge_bytes,
            )
            .map_err(SSError::SchnorrError)?;
        challenge_bytes.extend_from_slice(schnorr_proof_ctx);
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let schnorr_proof = schnorr.gen_proof(&challenge);
        Ok((
            Round1State {
                id,
                threshold,
                shares,
                coeff_comms,
                secret,
            },
            Round1Msg {
                sender_id: id,
                comm_coeffs: commitments,
                schnorr_proof,
            },
        ))
    }

    /// Called by a participant when it receives a message during Round 1
    pub fn add_received_message<R: RngCore, D: Digest>(
        &mut self,
        msg: Round1Msg<G>,
        schnorr_proof_ctx: &[u8],
        comm_key: &G,
    ) -> Result<(), SSError> {
        if msg.sender_id == self.id {
            return Err(SSError::SenderIdSameAsReceiver(msg.sender_id, self.id));
        }
        if !msg.comm_coeffs.supports_threshold(self.threshold) {
            return Err(SSError::DoesNotSupportThreshold(self.threshold));
        }
        // Verify Schnorr proof
        let mut challenge_bytes = vec![];
        msg.schnorr_proof
            .challenge_contribution(
                comm_key,
                msg.comm_coeffs.commitment_to_secret(),
                &mut challenge_bytes,
            )
            .map_err(SSError::SchnorrError)?;
        challenge_bytes.extend_from_slice(schnorr_proof_ctx);
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !msg
            .schnorr_proof
            .verify(msg.comm_coeffs.commitment_to_secret(), comm_key, &challenge)
        {
            return Err(SSError::InvalidProofOfSecretKeyKnowledge);
        }

        // Store commitments
        self.coeff_comms.insert(msg.sender_id, msg.comm_coeffs);
        Ok(())
    }

    /// Participant finishes Round 1 and starts Round 2.
    pub fn finish(self) -> (Round2State<G>, Shares<G::ScalarField>) {
        let mut shares = BTreeMap::new();
        shares.insert(self.id, self.shares.0[self.id as usize - 1].clone());
        (
            Round2State {
                id: self.id,
                threshold: self.threshold,
                shares,
                coeff_comms: self.coeff_comms,
            },
            self.shares,
        )
    }

    pub fn total_participants(&self) -> usize {
        self.coeff_comms.len()
    }
}

impl<G: AffineRepr> Round2State<G> {
    /// Called by a participant when it receives its share during Round 1
    pub fn add_received_share<R: RngCore>(
        &mut self,
        sender_id: ShareId,
        share: Share<G::ScalarField>,
        comm_key: &G,
    ) -> Result<(), SSError> {
        if sender_id == self.id {
            return Err(SSError::SenderIdSameAsReceiver(sender_id, self.id));
        }
        if self.shares.contains_key(&sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(sender_id));
        }
        if self.id != share.id {
            return Err(SSError::UnequalParticipantAndShareId(self.id, share.id));
        }
        if self.threshold != share.threshold {
            return Err(SSError::UnequalThresholdInReceivedShare(
                self.threshold,
                share.threshold,
            ));
        }
        if let Some(comm) = self.coeff_comms.get(&sender_id) {
            share.verify(comm, comm_key)?;
            self.shares.insert(sender_id, share);
            Ok(())
        } else {
            Err(SSError::ParticipantNotAllowedInPhase2(sender_id))
        }
    }

    /// Participant finishes Round 1 and outputs final share that contains its own secret key, its own
    /// public key and the threshold public key
    pub fn finish(self, comm_key: &G) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        feldman_dvss_dkg::SharesAccumulator::gen_final_share_and_public_key(
            self.id,
            self.threshold,
            self.shares,
            self.coeff_comms,
            comm_key,
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn frost_distributed_key_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let g2 = <Bls12_381 as Pairing>::G2Affine::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, comm_key: &G) {
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
                let mut all_round1_states = vec![];
                let mut all_round1_msgs = vec![];
                let mut all_round2_states = vec![];
                let mut all_shares = vec![];
                let mut secrets = vec![];
                let schnorr_ctx = b"test-ctx";

                // Each participant starts Round 1
                for i in 1..=total {
                    let (round1_state, round1_msg) =
                        Round1State::start_with_random_secret::<StdRng, Blake2b512>(
                            rng,
                            i as ParticipantId,
                            threshold as ShareId,
                            total as ShareId,
                            schnorr_ctx,
                            comm_key,
                        )
                        .unwrap();
                    secrets.push(round1_state.secret.clone());
                    all_round1_states.push(round1_state);
                    all_round1_msgs.push(round1_msg);
                }

                // Each participant receives message during Round 1
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            // Reject invalid message
                            let mut msg_with_wrong_id = all_round1_msgs[j].clone();
                            msg_with_wrong_id.sender_id = i as ShareId + 1;
                            assert!(all_round1_states[i]
                                .add_received_message::<StdRng, Blake2b512>(
                                    msg_with_wrong_id,
                                    schnorr_ctx,
                                    comm_key,
                                )
                                .is_err());

                            let mut comms = all_round1_msgs[j].clone();
                            comms.comm_coeffs.0.remove(0);
                            assert!(all_round1_states[i]
                                .add_received_message::<StdRng, Blake2b512>(
                                    comms,
                                    schnorr_ctx,
                                    comm_key,
                                )
                                .is_err());

                            assert!(all_round1_states[i]
                                .add_received_message::<StdRng, Blake2b512>(
                                    all_round1_msgs[j].clone(),
                                    b"another-ctx",
                                    comm_key,
                                )
                                .is_err());

                            all_round1_states[i]
                                .add_received_message::<StdRng, Blake2b512>(
                                    all_round1_msgs[j].clone(),
                                    schnorr_ctx,
                                    comm_key,
                                )
                                .unwrap();
                        }
                    }
                }

                // Each participant ends Round 1 and begins Round 2
                for i in 0..total {
                    assert_eq!(all_round1_states[i].total_participants(), total);
                    let (round2, shares) = all_round1_states[i].clone().finish();
                    all_round2_states.push(round2);
                    all_shares.push(shares);
                }

                // Each participant receives shares and commitments during Round2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = all_shares[j].0[i].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_id,
                                    comm_key,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = all_shares[j].0[i].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_threshold,
                                    comm_key,
                                )
                                .is_err());

                            let mut share_with_wrong_value = all_shares[j].0[i].clone();
                            share_with_wrong_value.share =
                                share_with_wrong_value.share + G::ScalarField::from(10u64);
                            assert!(all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_value,
                                    comm_key,
                                )
                                .is_err());

                            // Sender id same as participant
                            assert!(all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (i + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    comm_key,
                                )
                                .is_err());

                            all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (j + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    comm_key,
                                )
                                .unwrap();

                            // Adding duplicate share not allowed
                            assert!(all_round2_states[i]
                                .add_received_share::<StdRng>(
                                    (j + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    comm_key,
                                )
                                .is_err());
                        }
                    }
                }

                // Each participant ends Round2
                let mut tk = None;
                let mut all_pk = vec![];
                let mut final_shares = vec![];
                for i in 0..total {
                    let (share, pk, t_pk) = all_round2_states[i].clone().finish(comm_key).unwrap();
                    assert_eq!(
                        comm_key.mul_bigint(share.share.into_bigint()).into_affine(),
                        pk
                    );
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
                    Some(
                        feldman_dvss_dkg::reconstruct_threshold_public_key(pk_with_ids, threshold)
                            .unwrap()
                    )
                );
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
