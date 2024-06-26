//! Distributed Key Generation protocol as described in Fig. 4 of the paper [VSS from Distributed ZK Proofs and Applications](https://eprint.iacr.org/2023/992.pdf)

#![allow(non_snake_case)]

use crate::{
    common::{ParticipantId, ShareId},
    error::SSError,
    shamir_ss,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, collections::BTreeMap, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, expect_equality, serde_utils::ArkObjectBytes,
};
use schnorr_pok::compute_random_oracle_challenge;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Share of the secret generated by a party
#[serde_as]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct VerifiableShare<F: PrimeField> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[serde_as(as = "ArkObjectBytes")]
    pub share: F,
    pub blinding: F,
    pub blinding_prime: F,
}

/// State of a party in Round 1.
/// CMG is the group where commitments reside and PKG is the group of the public key
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round1<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>> {
    pub id: ParticipantId,
    pub threshold: ShareId,
    pub secret: PKG::ScalarField,
    pub h: PKG,
    pub shares: Vec<VerifiableShare<PKG::ScalarField>>,
    pub y_0: PKG::ScalarField,
    pub y_0_prime: PKG::ScalarField,
    /// Stores broadcast messages received from other parties in this round
    pub received_msgs: BTreeMap<ParticipantId, Round1Msg<CMG, PKG>>,
}

/// Message broadcasted by a party in Round 1
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round1Msg<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>> {
    pub sender_id: ParticipantId,
    pub C: Vec<CMG>,
    pub C_prime: Vec<CMG>,
    pub C_0: PKG,
    pub C_0_prime: PKG,
    pub resp: DensePolynomial<CMG::ScalarField>,
}

/// State of a party in Round 1.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round2<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>> {
    pub round1_state: Round1<CMG, PKG>,
    /// Stores broadcast messages received from other parties in this round
    pub received_msgs: BTreeMap<ParticipantId, Round2Msg<PKG>>,
    /// Stores shares received from other parties in this round
    pub received_shares: BTreeMap<ParticipantId, VerifiableShare<PKG::ScalarField>>,
}

/// Message broadcasted by a party in Round 2
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Round2Msg<PKG: AffineRepr> {
    pub sender_id: ParticipantId,
    pub h: PKG,
    pub y_0: PKG::ScalarField,
    pub y_0_prime: PKG::ScalarField,
}

impl<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>> Round1<CMG, PKG> {
    pub fn start<'a, R: RngCore, D: Digest>(
        rng: &mut R,
        participant_id: ParticipantId,
        threshold: ShareId,
        total: ShareId,
        comm_key: &PedersenCommitmentKey<CMG>,
        pk_gen: impl Into<&'a PKG> + Clone,
    ) -> Result<(Self, Round1Msg<CMG, PKG>), SSError> {
        if participant_id == 0 || participant_id > total {
            return Err(SSError::InvalidParticipantId(participant_id));
        }
        let secret = PKG::ScalarField::rand(rng);
        let (shares, f) = shamir_ss::deal_secret(rng, secret, threshold, total)?;
        let b = <DensePolynomial<PKG::ScalarField> as DenseUVPolynomial<PKG::ScalarField>>::rand(
            threshold as usize - 1,
            rng,
        );
        debug_assert_eq!(f.degree(), b.degree());
        let b_evals = cfg_into_iter!(1..=total)
            .map(|i| b.evaluate(&PKG::ScalarField::from(i)))
            .collect::<Vec<_>>();
        let b_0 = b.coeffs[0];
        let y = (0..total)
            .map(|_| PKG::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let y_prime = (0..total)
            .map(|_| PKG::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let y_0 = PKG::ScalarField::rand(rng);
        let y_0_prime = PKG::ScalarField::rand(rng);
        let pk_gen = pk_gen.into().into_group();
        let h = pk_gen * secret;
        let C_0 = (pk_gen * (b_0 * y_0)).into_affine();
        let C_0_prime = ((pk_gen + h) * y_0_prime).into_affine();
        let C = CMG::Group::normalize_batch(
            &cfg_into_iter!(0..total as usize)
                .map(|i| comm_key.commit_as_projective(&b_evals[i], &y[i]))
                .collect::<Vec<_>>(),
        );
        let C_prime = CMG::Group::normalize_batch(
            &cfg_into_iter!(0..total as usize)
                .map(|i| comm_key.commit_as_projective(&shares.0[i].share, &y_prime[i]))
                .collect::<Vec<_>>(),
        );

        let mut chal_bytes = vec![];
        comm_key.g.serialize_compressed(&mut chal_bytes)?;
        comm_key.h.serialize_compressed(&mut chal_bytes)?;
        C_0.serialize_compressed(&mut chal_bytes)?;
        C_0_prime.serialize_compressed(&mut chal_bytes)?;
        for i in 0..C.len() {
            C[i].serialize_compressed(&mut chal_bytes)?;
            C_prime[i].serialize_compressed(&mut chal_bytes)?;
        }
        let d = compute_random_oracle_challenge::<PKG::ScalarField, D>(&chal_bytes);
        let r = &b - &(&f * d);
        let msg = Round1Msg {
            sender_id: participant_id,
            C,
            C_prime,
            C_0,
            C_0_prime,
            resp: r,
        };
        let shares = cfg_into_iter!(shares.0)
            .zip(cfg_into_iter!(y))
            .zip(cfg_into_iter!(y_prime))
            .map(|((s, y_i), y_i_prime)| VerifiableShare {
                id: s.id,
                threshold,
                share: s.share,
                blinding: y_i,
                blinding_prime: y_i_prime,
            })
            .collect::<Vec<_>>();
        let state = Round1 {
            id: participant_id,
            threshold,
            secret,
            h: h.into_affine(),
            shares,
            y_0,
            y_0_prime,
            received_msgs: BTreeMap::new(),
        };
        Ok((state, msg))
    }

    pub fn add_received_message(&mut self, msg: Round1Msg<CMG, PKG>) -> Result<(), SSError> {
        if msg.sender_id == self.id {
            return Err(SSError::SenderIdSameAsReceiver(msg.sender_id, self.id));
        }
        if self.received_msgs.contains_key(&msg.sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(msg.sender_id));
        }
        if msg.resp.degree() != self.threshold as usize - 1 {
            return Err(SSError::DoesNotSupportThreshold(self.threshold));
        }
        expect_equality!(
            msg.C.len(),
            msg.C_prime.len(),
            SSError::InvalidNoOfCommitments
        );
        expect_equality!(
            msg.C.len(),
            self.shares.len(),
            SSError::InvalidNoOfCommitments
        );
        self.received_msgs.insert(msg.sender_id, msg);
        Ok(())
    }

    /// This should be called after "sufficient" messages have been received.
    /// "sufficient" might be just the threshold or greater depending on the number of faults to be
    /// tolerated.
    pub fn finish(self) -> Result<(Round2<CMG, PKG>, Round2Msg<PKG>), SSError> {
        // +1 because `self.received_msgs` does not contain message from itself
        if self.threshold > (self.received_msgs.len() as ParticipantId + 1) {
            return Err(SSError::BelowThreshold(
                self.threshold,
                self.received_msgs.len() as ParticipantId,
            ));
        }
        let round1_state = self.clone();
        let msg = Round2Msg {
            sender_id: self.id,
            h: self.h,
            y_0: self.y_0,
            y_0_prime: self.y_0_prime,
        };
        let round2 = Round2 {
            round1_state,
            received_msgs: BTreeMap::new(),
            received_shares: BTreeMap::new(),
        };
        Ok((round2, msg))
    }
}

impl<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>> Round2<CMG, PKG> {
    pub fn add_received_message(&mut self, msg: Round2Msg<PKG>) -> Result<(), SSError> {
        if self.round1_state.id == msg.sender_id {
            return Err(SSError::SenderIdSameAsReceiver(
                self.round1_state.id,
                msg.sender_id,
            ));
        }
        if self.received_msgs.contains_key(&msg.sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(msg.sender_id));
        }
        if !self.round1_state.received_msgs.contains_key(&msg.sender_id) {
            return Err(SSError::ParticipantNotAllowedInPhase2(msg.sender_id));
        }
        self.received_msgs.insert(msg.sender_id, msg);
        Ok(())
    }

    pub fn add_received_share<'a, D: Digest>(
        &mut self,
        sender_id: ParticipantId,
        share: VerifiableShare<PKG::ScalarField>,
        comm_key: &PedersenCommitmentKey<CMG>,
        pk_gen: impl Into<&'a PKG> + Clone,
    ) -> Result<(), SSError> {
        if self.round1_state.id == sender_id {
            return Err(SSError::SenderIdSameAsReceiver(
                self.round1_state.id,
                sender_id,
            ));
        }
        if self.round1_state.id != share.id {
            return Err(SSError::UnequalParticipantAndShareId(
                self.round1_state.id,
                share.id,
            ));
        }
        if self.received_shares.contains_key(&sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(sender_id));
        }
        self.verify_share::<D>(sender_id, &share, comm_key, pk_gen)?;
        self.received_shares.insert(sender_id, share);
        Ok(())
    }

    pub fn finish(self) -> Result<(PKG::ScalarField, PKG, PKG), SSError> {
        // +1 because `self.received_msgs` does not contain message from itself
        if self.round1_state.threshold > (self.received_msgs.len() as ParticipantId + 1) {
            return Err(SSError::BelowThreshold(
                self.round1_state.threshold,
                self.received_msgs.len() as ParticipantId,
            ));
        }
        if self.received_shares.len() != self.round1_state.received_msgs.len() {
            return Err(SSError::MissingSomeParticipants(
                (self.received_shares.len() - self.received_msgs.len()) as ParticipantId,
            ));
        }
        let tpk =
            self.received_msgs.values().map(|m| m.h).sum::<PKG::Group>() + self.round1_state.h;
        Ok((
            self.round1_state.secret,
            self.round1_state.h,
            tpk.into_affine(),
        ))
    }

    /// Verify a received share. Used during normal operation or in processing complaints
    pub fn verify_share<'a, D: Digest>(
        &self,
        sender_id: ParticipantId,
        share: &VerifiableShare<PKG::ScalarField>,
        comm_key: &PedersenCommitmentKey<CMG>,
        pk_gen: impl Into<&'a PKG> + Clone,
    ) -> Result<(), SSError> {
        let round1_msg = self
            .round1_state
            .received_msgs
            .get(&sender_id)
            .ok_or(SSError::ParticipantNotAllowedInPhase2(sender_id))?;
        let round2_msg = self
            .received_msgs
            .get(&sender_id)
            .ok_or(SSError::MissingRound2MessageFrom(sender_id))?;
        let self_idx = self.round1_state.id as usize - 1;
        if comm_key.commit_as_projective(&share.share, &share.blinding_prime)
            != round1_msg.C_prime[self_idx].into_group()
        {
            return Err(SSError::InvalidShare);
        }
        let pk_gen = *pk_gen.into();
        if (pk_gen + round2_msg.h) * round2_msg.y_0_prime != round1_msg.C_0_prime.into_group() {
            return Err(SSError::InvalidShare);
        }
        let mut chal_bytes = vec![];
        comm_key.g.serialize_compressed(&mut chal_bytes)?;
        comm_key.h.serialize_compressed(&mut chal_bytes)?;
        round1_msg.C_0.serialize_compressed(&mut chal_bytes)?;
        round1_msg.C_0_prime.serialize_compressed(&mut chal_bytes)?;
        for i in 0..round1_msg.C.len() {
            round1_msg.C[i].serialize_compressed(&mut chal_bytes)?;
            round1_msg.C_prime[i].serialize_compressed(&mut chal_bytes)?;
        }
        let d = compute_random_oracle_challenge::<PKG::ScalarField, D>(&chal_bytes);
        let h_prime = pk_gen * round1_msg.resp.coeffs[0] + round2_msg.h * d;
        if round1_msg.C_0.into_group() != h_prime * round2_msg.y_0 {
            return Err(SSError::InvalidShare);
        }
        if comm_key.commit_as_projective(
            &(round1_msg
                .resp
                .evaluate(&CMG::ScalarField::from(self.round1_state.id))
                + share.share * d),
            &share.blinding,
        ) != round1_msg.C[self_idx].into_group()
        {
            return Err(SSError::InvalidShare);
        }
        Ok(())
    }

    /// Called when got >= `threshold` complaints for `participant_id` and disqualifying a participant
    pub fn remove_participant(&mut self, participant_id: ParticipantId) -> Result<(), SSError> {
        if self.round1_state.id == participant_id {
            return Err(SSError::CannotRemoveSelf(participant_id));
        }
        self.received_shares.remove(&participant_id);
        self.round1_state.received_msgs.remove(&participant_id);
        Ok(())
    }

    /// Get share given by party with id `id`.
    pub fn get_share_of_party(
        &self,
        id: ParticipantId,
    ) -> Option<&VerifiableShare<CMG::ScalarField>> {
        self.received_shares.get(&id)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};

    #[test]
    fn distributed_key_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ped_comm_key = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");
        let pk_gen_g1 = G1Affine::rand(&mut rng);
        let pk_gen_g2 = G2Affine::rand(&mut rng);

        fn check<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>>(
            rng: &mut StdRng,
            ped_comm_key: &PedersenCommitmentKey<CMG>,
            pk_gen: &PKG,
        ) {
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
                let mut all_round1s = vec![];
                let mut all_round2s = vec![];
                let mut all_secrets = vec![];
                let mut all_round1_msgs = vec![];
                let mut all_round2_msgs = vec![];

                println!("For {}-of-{}", threshold, total);
                let mut round1_time = Duration::default();
                let mut round2_time = Duration::default();

                // Each participant starts Round1
                for i in 1..=total {
                    let start = Instant::now();
                    let (round1, msgs) = Round1::start::<_, Blake2b512>(
                        rng,
                        i as ParticipantId,
                        threshold as ShareId,
                        total as ShareId,
                        ped_comm_key,
                        pk_gen,
                    )
                    .unwrap();
                    round1_time += start.elapsed();

                    all_secrets.push(round1.secret.clone());
                    all_round1s.push(round1);
                    all_round1_msgs.push(msgs);
                }

                let start = Instant::now();
                // Each participant receives messages during Round1
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            all_round1s[i]
                                .add_received_message(all_round1_msgs[j].clone())
                                .unwrap();
                        }
                    }
                }

                // Each participant ends round1 and begins Round 2
                for i in 0..total {
                    let (round2, msgs) = all_round1s[i].clone().finish().unwrap();
                    all_round2s.push(round2);
                    all_round2_msgs.push(msgs);
                }
                round1_time += start.elapsed();

                let start = Instant::now();
                // Each participant receives messages during Round2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            all_round2s[i]
                                .add_received_message(all_round2_msgs[j].clone())
                                .unwrap();
                        }
                    }
                }
                round2_time += start.elapsed();

                let start = Instant::now();
                // Each participant receives shares during Round2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            let share = all_round2s[j].round1_state.shares[i].clone();
                            all_round2s[i]
                                .add_received_share::<Blake2b512>(
                                    (j + 1) as ParticipantId,
                                    share,
                                    ped_comm_key,
                                    pk_gen,
                                )
                                .unwrap();
                        }
                    }
                }
                round2_time += start.elapsed();

                for i in 0..total {
                    assert_eq!(all_round2s[i].received_msgs.len(), total - 1);
                    assert_eq!(all_round2s[i].received_shares.len(), total - 1);
                }

                // Each participant ends Round2 and ends up with his own keys and the threshold public key
                let mut tk = None;
                for i in 0..total {
                    let start = Instant::now();
                    let (own_sk, own_pk, threshold_pk) = all_round2s[i].clone().finish().unwrap();
                    round2_time += start.elapsed();
                    assert_eq!(own_sk, all_secrets[i]);
                    assert_eq!(
                        own_pk,
                        pk_gen.mul_bigint(own_sk.into_bigint()).into_affine()
                    );
                    if tk.is_none() {
                        tk = Some(threshold_pk);
                    } else {
                        // All generate the same threshold key
                        assert_eq!(tk, Some(threshold_pk))
                    }
                }

                assert_eq!(
                    tk.unwrap(),
                    (*pk_gen * all_secrets.into_iter().sum::<PKG::ScalarField>()).into_affine()
                );

                println!("Time taken for round 1 {:?}", round1_time);
                println!("Time taken for round 2 {:?}", round2_time);
            }
        }

        check(&mut rng, &ped_comm_key, &pk_gen_g1);
        check(&mut rng, &ped_comm_key, &pk_gen_g2);
    }
}
