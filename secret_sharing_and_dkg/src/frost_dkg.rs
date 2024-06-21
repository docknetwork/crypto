//! This is the keygen implemented in the [FROST paper](https://eprint.iacr.org/2020/852.pdf) in Figure 1.
//! This is a slight addition to the DKG based on Feldman VSS as it contains a Schnorr proof of knowledge
//! of the secret key.

use crate::{
    common::{CommitmentToCoefficients, ParticipantId, Share, ShareId, Shares},
    error::SSError,
    feldman_dvss_dkg, feldman_vss,
};
use ark_ec::AffineRepr;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// State of a participant during Round 1
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Round1State<G: AffineRepr> {
    pub id: ParticipantId,
    pub threshold: ShareId,
    pub shares: Shares<G::ScalarField>,
    /// Stores the commitment to the coefficients of the polynomial by each participant
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
    /// Secret chosen by the participant
    #[serde_as(as = "ArkObjectBytes")]
    pub secret: G::ScalarField,
}

/// Message sent by a participant during Round 1
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Round1Msg<G: AffineRepr> {
    pub sender_id: ParticipantId,
    pub comm_coeffs: CommitmentToCoefficients<G>,
    /// Proof of knowledge of the secret key for the public key
    pub schnorr_proof: PokDiscreteLog<G>,
}

/// State of a participant during Round 2
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Round2State<G: AffineRepr> {
    pub id: ParticipantId,
    pub threshold: ShareId,
    /// Stores the shares sent by each participant
    pub shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
    /// Stores the commitment to the coefficients of the polynomial by each participant. Created during Round 1
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
}

impl<G: AffineRepr> Round1State<G> {
    /// Start Phase 1 with a randomly generated secret. `schnorr_proof_ctx` is the context used in the Schnorr proof
    /// to prevent replay attacks. `pk_gen` is the EC group generator for the public key
    pub fn start_with_random_secret<'a, R: RngCore, D: Digest>(
        rng: &mut R,
        participant_id: ParticipantId,
        threshold: ShareId,
        total: ShareId,
        schnorr_proof_ctx: &[u8],
        pk_gen: impl Into<&'a G> + Clone,
    ) -> Result<(Self, Round1Msg<G>), SSError> {
        let secret = G::ScalarField::rand(rng);
        Self::start_with_given_secret::<R, D>(
            rng,
            participant_id,
            secret,
            threshold,
            total,
            schnorr_proof_ctx,
            pk_gen,
        )
    }

    /// Similar to `Self::start_with_random_secret` except it expects a secret from the caller.
    pub fn start_with_given_secret<'a, R: RngCore, D: Digest>(
        rng: &mut R,
        id: ParticipantId,
        secret: G::ScalarField,
        threshold: ShareId,
        total: ShareId,
        schnorr_proof_ctx: &[u8],
        pk_gen: impl Into<&'a G> + Clone,
    ) -> Result<(Self, Round1Msg<G>), SSError> {
        if id == 0 || id > total {
            return Err(SSError::InvalidParticipantId(id));
        }
        // Create shares of the secret and commit to it
        let (shares, commitments, _) =
            feldman_vss::deal_secret::<R, G>(rng, secret, threshold, total, pk_gen.clone())?;
        let mut coeff_comms = BTreeMap::new();
        coeff_comms.insert(id, commitments.clone());

        let pk_gen = pk_gen.into();
        // Create the proof of knowledge for the secret key
        let blinding = G::ScalarField::rand(rng);
        let schnorr = PokDiscreteLogProtocol::init(secret, blinding, pk_gen);
        let mut challenge_bytes = vec![];
        schnorr
            .challenge_contribution(
                pk_gen,
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
    pub fn add_received_message<'a, D: Digest>(
        &mut self,
        msg: Round1Msg<G>,
        schnorr_proof_ctx: &[u8],
        pk_gen: impl Into<&'a G>,
    ) -> Result<(), SSError> {
        if msg.sender_id == self.id {
            return Err(SSError::SenderIdSameAsReceiver(msg.sender_id, self.id));
        }
        if !msg.comm_coeffs.supports_threshold(self.threshold) {
            return Err(SSError::DoesNotSupportThreshold(self.threshold));
        }
        if self.coeff_comms.contains_key(&msg.sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(msg.sender_id));
        }

        let pk_gen = pk_gen.into();
        // Verify Schnorr proof
        let mut challenge_bytes = vec![];
        msg.schnorr_proof
            .challenge_contribution(
                pk_gen,
                msg.comm_coeffs.commitment_to_secret(),
                &mut challenge_bytes,
            )
            .map_err(SSError::SchnorrError)?;
        challenge_bytes.extend_from_slice(schnorr_proof_ctx);
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !msg
            .schnorr_proof
            .verify(msg.comm_coeffs.commitment_to_secret(), pk_gen, &challenge)
        {
            return Err(SSError::InvalidProofOfSecretKeyKnowledge);
        }

        // Store commitments
        self.coeff_comms.insert(msg.sender_id, msg.comm_coeffs);
        Ok(())
    }

    /// Participant finishes Round 1 and starts Round 2.
    pub fn finish(self) -> Result<(Round2State<G>, Shares<G::ScalarField>), SSError> {
        // Check that sufficient shares present
        let len = self.shares.0.len() as ShareId;
        if self.threshold > (len + 1) {
            // + 1 because its own share will be added later
            return Err(SSError::BelowThreshold(self.threshold, len));
        }
        let mut shares = BTreeMap::new();
        shares.insert(self.id, self.shares.0[self.id as usize - 1].clone());
        Ok((
            Round2State {
                id: self.id,
                threshold: self.threshold,
                shares,
                coeff_comms: self.coeff_comms,
            },
            self.shares,
        ))
    }

    pub fn total_participants(&self) -> usize {
        self.coeff_comms.len()
    }
}

impl<G: AffineRepr> Round2State<G> {
    /// Called by a participant when it receives its share during Round 1
    pub fn add_received_share<'a>(
        &mut self,
        sender_id: ShareId,
        share: Share<G::ScalarField>,
        pk_gen: impl Into<&'a G>,
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
            share.verify(comm, pk_gen.into())?;
            self.shares.insert(sender_id, share);
            Ok(())
        } else {
            Err(SSError::ParticipantNotAllowedInPhase2(sender_id))
        }
    }

    /// Participant finishes Round 1 and outputs final share that contains its own secret key, its own
    /// public key and the threshold public key
    pub fn finish<'a>(
        self,
        pk_gen: impl Into<&'a G>,
    ) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        feldman_dvss_dkg::SharesAccumulator::gen_final_share_and_public_key(
            self.id,
            self.threshold,
            self.shares,
            self.coeff_comms,
            pk_gen.into(),
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};
    use test_utils::{test_serialization, G1, G2};

    #[test]
    fn distributed_key_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, pub_key_base: &G) {
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
                let mut all_round1_states = vec![];
                let mut all_round1_msgs = vec![];
                let mut all_round2_states = vec![];
                let mut all_shares = vec![];
                let mut secrets = vec![];
                let schnorr_ctx = b"test-ctx";

                println!("For {}-of-{}", threshold, total);
                let mut round1_time = Duration::default();
                let mut round2_time = Duration::default();

                // Each participant starts Round 1
                for i in 1..=total {
                    let start = Instant::now();
                    let (round1_state, round1_msg) =
                        Round1State::start_with_random_secret::<StdRng, Blake2b512>(
                            rng,
                            i as ParticipantId,
                            threshold as ShareId,
                            total as ShareId,
                            schnorr_ctx,
                            pub_key_base,
                        )
                        .unwrap();
                    round1_time += start.elapsed();

                    secrets.push(round1_state.secret.clone());
                    all_round1_states.push(round1_state);
                    all_round1_msgs.push(round1_msg);
                }

                if !checked_serialization {
                    test_serialization!(Round1State<G>, all_round1_states[0].clone());
                    test_serialization!(Round1Msg<G>, all_round1_msgs[0].clone());
                }

                // Each participant receives message during Round 1
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            // Reject invalid message
                            let mut msg_with_wrong_id = all_round1_msgs[j].clone();
                            msg_with_wrong_id.sender_id = i as ShareId + 1;
                            assert!(all_round1_states[i]
                                .add_received_message::<Blake2b512>(
                                    msg_with_wrong_id,
                                    schnorr_ctx,
                                    pub_key_base,
                                )
                                .is_err());

                            let mut comms = all_round1_msgs[j].clone();
                            comms.comm_coeffs.0.remove(0);
                            assert!(all_round1_states[i]
                                .add_received_message::<Blake2b512>(
                                    comms,
                                    schnorr_ctx,
                                    pub_key_base,
                                )
                                .is_err());

                            assert!(all_round1_states[i]
                                .add_received_message::<Blake2b512>(
                                    all_round1_msgs[j].clone(),
                                    b"another-ctx",
                                    pub_key_base,
                                )
                                .is_err());

                            let start = Instant::now();
                            // Process valid message
                            all_round1_states[i]
                                .add_received_message::<Blake2b512>(
                                    all_round1_msgs[j].clone(),
                                    schnorr_ctx,
                                    pub_key_base,
                                )
                                .unwrap();
                            round1_time += start.elapsed();
                        }
                    }

                    if !checked_serialization {
                        test_serialization!(Round1State<G>, all_round1_states[i].clone());
                    }
                }

                // Each participant ends Round 1 and begins Round 2
                for i in 0..total {
                    assert_eq!(all_round1_states[i].total_participants(), total);
                    let start = Instant::now();
                    let (round2, shares) = all_round1_states[i].clone().finish().unwrap();
                    round1_time += start.elapsed();
                    all_round2_states.push(round2);
                    all_shares.push(shares);
                }

                if !checked_serialization {
                    test_serialization!(Round2State<G>, all_round2_states[0].clone());
                }

                // Each participant receives shares and commitments during Round2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            // Participant rejects invalid received shares
                            let mut share_with_wrong_id = all_shares[j].0[i].clone();
                            share_with_wrong_id.id = share_with_wrong_id.id + 1;
                            assert!(all_round2_states[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_id,
                                    pub_key_base,
                                )
                                .is_err());

                            let mut share_with_wrong_threshold = all_shares[j].0[i].clone();
                            share_with_wrong_threshold.threshold =
                                share_with_wrong_threshold.threshold + 1;
                            assert!(all_round2_states[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_threshold,
                                    pub_key_base,
                                )
                                .is_err());

                            let mut share_with_wrong_value = all_shares[j].0[i].clone();
                            share_with_wrong_value.share =
                                share_with_wrong_value.share + G::ScalarField::from(10u64);
                            assert!(all_round2_states[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    share_with_wrong_value,
                                    pub_key_base,
                                )
                                .is_err());

                            // Sender id same as participant
                            assert!(all_round2_states[i]
                                .add_received_share(
                                    (i + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    pub_key_base,
                                )
                                .is_err());

                            let start = Instant::now();
                            all_round2_states[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    pub_key_base,
                                )
                                .unwrap();
                            round2_time += start.elapsed();

                            // Adding duplicate share not allowed
                            assert!(all_round2_states[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    pub_key_base,
                                )
                                .is_err());
                        }
                    }

                    // Cannot create the final share when having shares from less than threshold number of participants
                    if (all_round2_states[i].shares.len() as ShareId) < threshold {
                        assert!(all_round2_states[i].clone().finish(pub_key_base).is_err());
                    }

                    if !checked_serialization {
                        test_serialization!(Round2State<G>, all_round2_states[i].clone());
                    }
                }

                // Each participant ends Round2
                let mut tk = None;
                let mut all_pk = vec![];
                let mut final_shares = vec![];
                for i in 0..total {
                    let start = Instant::now();
                    let (share, pk, t_pk) =
                        all_round2_states[i].clone().finish(pub_key_base).unwrap();
                    round2_time += start.elapsed();
                    assert_eq!(
                        pub_key_base
                            .mul_bigint(share.share.into_bigint())
                            .into_affine(),
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
                checked_serialization = true;

                println!("Time taken for round 1 {:?}", round1_time);
                println!("Time taken for round 2 {:?}", round2_time);
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
