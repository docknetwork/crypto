//! Based on the paper [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf)
//! Scheme is defined in Fig 2. The protocol is run in 2 phases: Phase1 where all participants generate a
//! secret and share it using Pedersen VSS and in Phase 2 participants distribute commitments as per
//! Feldman VSS and generate the public key at the end. The public key is assumed to be of the form
//! `G*x` where `x` is the secret key and `G` is the group generator.
//!

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::commitment::PedersenCommitmentKey;

use crate::{
    common::{
        CommitmentToCoefficients, ParticipantId, Share, ShareId, VerifiableShare, VerifiableShares,
    },
    error::SSError,
    feldman_vss, pedersen_dvss, pedersen_vss,
};

/// In Phase 1, each participant runs Pedersen VSS
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<G: AffineRepr> {
    /// `z_i` from the paper
    pub secret: G::ScalarField,
    pub accumulator: pedersen_dvss::SharesAccumulator<G>,
    pub poly: DensePolynomial<G::ScalarField>,
    /// This is kept to reply to a malicious complaining party, i.e. for step 1.c from the protocol
    pub blinding_poly: DensePolynomial<G::ScalarField>,
}

/// In phase 2, Each participant runs Feldman VSS (only partly) over the same secret and polynomial
/// used in Phase 1 where it distributes the commitments to other participants
/// The commitments created during Phase1 and Phase2 could be in different groups for efficiency like when
/// the public key is supposed to be in group G2, but the commitments in Phase1 can still be in group G1.
/// Thus CMG is the commitment group from Phase 1 and PKG is the public key group Phase 2.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<PKG: AffineRepr<ScalarField = CMG::ScalarField>, CMG: AffineRepr> {
    pub id: ParticipantId,
    pub secret: PKG::ScalarField,
    /// Shares from Phase 1. Only participants which submitted shares in Phase 1 will be allowed in
    /// Phase 2. This is the set "QUAL" from the paper
    pub shares_phase_1: BTreeMap<ParticipantId, VerifiableShare<CMG::ScalarField>>,
    pub final_share: VerifiableShare<PKG::ScalarField>,
    /// Commitment to coefficients of the polynomial created during Phase 1.
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<PKG>>,
}

impl<CMG: AffineRepr> Phase1<CMG> {
    /// Start Phase 1 with a randomly generated secret.
    pub fn start_with_random_secret<R: RngCore>(
        rng: &mut R,
        participant_id: ParticipantId,
        threshold: ShareId,
        total: ShareId,
        comm_key: &PedersenCommitmentKey<CMG>,
    ) -> Result<
        (
            Self,
            VerifiableShares<CMG::ScalarField>,
            CommitmentToCoefficients<CMG>,
        ),
        SSError,
    > {
        let secret = CMG::ScalarField::rand(rng);
        Self::start_with_given_secret(rng, participant_id, secret, threshold, total, comm_key)
    }

    /// Start Phase 1 with a given secret.
    pub fn start_with_given_secret<R: RngCore>(
        rng: &mut R,
        participant_id: ParticipantId,
        secret: CMG::ScalarField,
        threshold: ShareId,
        total: ShareId,
        comm_key: &PedersenCommitmentKey<CMG>,
    ) -> Result<
        (
            Self,
            VerifiableShares<CMG::ScalarField>,
            CommitmentToCoefficients<CMG>,
        ),
        SSError,
    > {
        let (_, shares, commitments, poly, blinding_poly) =
            pedersen_vss::deal_secret::<_, CMG>(rng, secret, threshold, total, comm_key)?;
        let mut accumulator = pedersen_dvss::SharesAccumulator::new(participant_id, threshold);
        accumulator.add_self_share(
            shares.0[(participant_id as usize) - 1].clone(),
            commitments.clone(),
        );
        Ok((
            Self {
                secret,
                accumulator,
                poly,
                blinding_poly,
            },
            shares,
            commitments,
        ))
    }

    /// Called by a participant when it receives a share from others.
    pub fn add_received_share(
        &mut self,
        sender_id: ParticipantId,
        share: VerifiableShare<CMG::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<CMG>,
        comm_key: &PedersenCommitmentKey<CMG>,
    ) -> Result<(), SSError> {
        self.accumulator
            .add_received_share(sender_id, share, commitment_coeffs, comm_key)?;
        Ok(())
    }

    /// Called when got >= `threshold` complaints for `participant_id` and disqualifying a participant
    pub fn remove_participant(&mut self, participant_id: ParticipantId) -> Result<(), SSError> {
        if self.self_id() == participant_id {
            return Err(SSError::CannotRemoveSelf(participant_id));
        }
        self.accumulator.shares.remove(&participant_id);
        self.accumulator.coeff_comms.remove(&participant_id);
        Ok(())
    }

    /// Mark Phase 1 as over and initialize Phase 2. Call this only when confident that no more complaints
    /// will be received or need to be processed. Its assumed that all participants in `self.accumulator`
    /// are honest by now
    pub fn finish<PKG: AffineRepr<ScalarField = CMG::ScalarField>>(
        self,
        ped_comm_key: &PedersenCommitmentKey<CMG>,
        fel_comm_key: &PKG,
    ) -> Result<(Phase2<PKG, CMG>, CommitmentToCoefficients<PKG>), SSError> {
        let id = self.self_id();
        let shares_phase_1 = self.accumulator.shares.clone();
        let final_share = self.accumulator.finalize(ped_comm_key)?;

        // If `CMG` and `PKG` are same, an optimization to avoid computing `commitments` could be to not do an MSM in `Phase1::start..` and
        // preserve the computation `g*a_i` where `a_i` are the coefficients of the polynomial
        let commitments: CommitmentToCoefficients<PKG> =
            feldman_vss::commit_to_poly(&self.poly, fel_comm_key).into();
        let mut coeff_comms = BTreeMap::new();
        coeff_comms.insert(id, commitments.clone());
        Ok((
            Phase2 {
                id,
                secret: self.secret,
                final_share,
                shares_phase_1,
                coeff_comms,
            },
            commitments,
        ))
    }

    /// Called by the participant to respond to complaint by the participant with id `participant_id`
    pub fn generate_share_for_participant(
        &self,
        participant_id: ParticipantId,
    ) -> Result<VerifiableShare<CMG::ScalarField>, SSError> {
        if self.self_id() == participant_id {
            return Err(SSError::SenderIdSameAsReceiver(
                self.self_id(),
                participant_id,
            ));
        }
        if participant_id == 0 {
            return Err(SSError::InvalidParticipantId(0));
        }
        let id = CMG::ScalarField::from(participant_id);
        let share = VerifiableShare {
            id: participant_id,
            threshold: self.poly.degree() as u16 + 1,
            secret_share: self.poly.evaluate(&id),
            blinding_share: self.blinding_poly.evaluate(&id),
        };
        Ok(share)
    }

    pub fn self_id(&self) -> ParticipantId {
        self.accumulator.participant_id
    }
}

impl<PKG: AffineRepr<ScalarField = CMG::ScalarField>, CMG: AffineRepr> Phase2<PKG, CMG> {
    /// Called by a participant when it receives commitments from others.
    pub fn add_received_commitments(
        &mut self,
        sender_id: ParticipantId,
        commitment_coeffs: CommitmentToCoefficients<PKG>,
        ck: &PKG,
    ) -> Result<(), SSError> {
        if self.id == sender_id {
            return Err(SSError::SenderIdSameAsReceiver(sender_id, self.id));
        }
        if !self.shares_phase_1.contains_key(&sender_id) {
            return Err(SSError::ParticipantNotAllowedInPhase2(sender_id));
        }
        if self.coeff_comms.contains_key(&sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(sender_id));
        }
        let v_share = self.shares_phase_1.get(&sender_id).unwrap();
        let share = Share {
            id: v_share.id,
            threshold: v_share.threshold,
            share: v_share.secret_share,
        };
        share.verify(&commitment_coeffs, ck)?;
        self.coeff_comms.insert(sender_id, commitment_coeffs);
        Ok(())
    }

    /// Mark this phase as complete and returns its own secret and public key and the group's key
    pub fn finish(self) -> Result<(PKG::ScalarField, PKG, PKG), SSError> {
        if self.coeff_comms.len() != self.shares_phase_1.len() {
            return Err(SSError::MissingSomeParticipants(
                (self.shares_phase_1.len() - self.coeff_comms.len()) as ParticipantId,
            ));
        }
        Ok((
            self.secret,
            *self
                .coeff_comms
                .get(&self.id)
                .unwrap()
                .commitment_to_secret(),
            self.coeff_comms
                .values()
                .fold(PKG::Group::zero(), |acc, v| acc + *v.commitment_to_secret())
                .into_affine(),
        ))
    }

    /// Get share given by party with id `id` in phase 1.
    pub fn get_phase_1_share_of_party(
        &self,
        id: ParticipantId,
    ) -> Option<&VerifiableShare<CMG::ScalarField>> {
        self.shares_phase_1.get(&id)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::PrimeField;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};

    type G1 = <Bls12_381 as Pairing>::G1Affine;

    #[test]
    fn distributed_key_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ped_comm_key = PedersenCommitmentKey::<G1>::new::<Blake2b512>(b"test");
        let feld_comm_key = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let feld_comm_key_g2 = <Bls12_381 as Pairing>::G2Affine::rand(&mut rng);

        fn check<CMG: AffineRepr, PKG: AffineRepr<ScalarField = CMG::ScalarField>>(
            rng: &mut StdRng,
            ped_comm_key: &PedersenCommitmentKey<CMG>,
            feld_comm_key: &PKG,
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
                let mut all_phase1s = vec![];
                let mut all_phase2s = vec![];
                let mut all_secrets = vec![];
                let mut all_shares = vec![];
                let mut all_comms1 = vec![];
                let mut all_comms2 = vec![];

                println!("For {}-of-{}", threshold, total);
                let mut phase1_time = Duration::default();
                let mut phase2_time = Duration::default();

                // Each participant starts Phase1
                for i in 1..=total {
                    let start = Instant::now();
                    let (phase1, shares, comms) = Phase1::start_with_random_secret(
                        rng,
                        i as ParticipantId,
                        threshold as ShareId,
                        total as ShareId,
                        ped_comm_key,
                    )
                    .unwrap();
                    phase1_time += start.elapsed();

                    for s in &shares.0 {
                        if i as ShareId != s.id {
                            assert_eq!(*s, phase1.generate_share_for_participant(s.id).unwrap());
                        } else {
                            assert!(phase1.generate_share_for_participant(s.id).is_err());
                        }
                    }
                    assert!(phase1.generate_share_for_participant(0).is_err());

                    all_secrets.push(phase1.secret.clone());
                    all_phase1s.push(phase1);
                    all_shares.push(shares);
                    all_comms1.push(comms);
                }

                let start = Instant::now();
                // Each participant receives shares and commitments during Phase1
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            all_phase1s[i]
                                .add_received_share(
                                    (j + 1) as ParticipantId,
                                    all_shares[j].0[i].clone(),
                                    all_comms1[j].clone(),
                                    ped_comm_key,
                                )
                                .unwrap();
                        }
                    }
                }

                // Each participant ends Phase1 and begins Phase 2
                for i in 0..total {
                    let (phase2, comms) = all_phase1s[i]
                        .clone()
                        .finish(ped_comm_key, feld_comm_key)
                        .unwrap();
                    all_phase2s.push(phase2);
                    all_comms2.push(comms);
                }
                phase1_time += start.elapsed();

                let start = Instant::now();
                // Each participant receives shares and commitments during Phase2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            all_phase2s[i]
                                .add_received_commitments(
                                    (j + 1) as ParticipantId,
                                    all_comms2[j].clone(),
                                    feld_comm_key,
                                )
                                .unwrap();
                        }
                    }
                }
                phase2_time += start.elapsed();

                // Each participant ends Phase2 and ends up with his own keys and the threshold public key
                let mut tk = None;
                for i in 0..total {
                    let start = Instant::now();
                    let (own_sk, own_pk, threshold_pk) = all_phase2s[i].clone().finish().unwrap();
                    phase2_time += start.elapsed();
                    assert_eq!(own_sk, all_secrets[i]);
                    assert_eq!(
                        own_pk,
                        feld_comm_key.mul_bigint(own_sk.into_bigint()).into_affine()
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
                    (*feld_comm_key * all_secrets.into_iter().sum::<PKG::ScalarField>())
                        .into_affine()
                );

                println!("Time taken for phase 1 {:?}", phase1_time);
                println!("Time taken for phase 2 {:?}", phase2_time);
            }
        }

        // When both Pedersen VSS and Feldman VSS have commitments in group G1
        check(&mut rng, &ped_comm_key, &feld_comm_key);
        // When both Pedersen VSS has commitments in group G1 and Feldman VSS in G2
        check(&mut rng, &ped_comm_key, &feld_comm_key_g2);
    }

    #[test]
    fn distributed_key_generation_with_failures() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ped_comm_key = PedersenCommitmentKey::<G1>::new::<Blake2b512>(b"test");
        let feld_comm_key = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        let threshold = 5;
        let total = 10;

        let faulty_phase_1_id: ParticipantId = 2;
        let faulty_phase_2_id: ParticipantId = 3;

        let mut all_phase1s = vec![];
        let mut all_phase2s = BTreeMap::new();
        let mut all_secrets = vec![];
        let mut all_shares = vec![];
        let mut all_comms1 = vec![];
        let mut all_comms2 = BTreeMap::new();

        // Each participant starts Phase1
        for i in 1..=total {
            let (phase1, shares, comms) = Phase1::start_with_random_secret(
                &mut rng,
                i as ParticipantId,
                threshold as ShareId,
                total as ShareId,
                &ped_comm_key,
            )
            .unwrap();

            all_secrets.push(phase1.secret.clone());
            all_phase1s.push(phase1);
            all_shares.push(shares);
            all_comms1.push(comms);
        }

        // Each participant receives shares and commitments during Phase1
        for i in 0..total {
            for j in 0..total {
                if i != j {
                    all_phase1s[i]
                        .add_received_share(
                            (j + 1) as ParticipantId,
                            all_shares[j].0[i].clone(),
                            all_comms1[j].clone(),
                            &ped_comm_key,
                        )
                        .unwrap();
                }
            }
        }

        // `threshold` number of complaints received against 1 party, so all others remove him. For step 1.c from the protocol
        for i in 1..=total {
            if i != faulty_phase_1_id as usize {
                all_phase1s[i - 1]
                    .remove_participant(faulty_phase_1_id)
                    .unwrap();
                let (phase2, comms) = all_phase1s[i - 1]
                    .clone()
                    .finish(&ped_comm_key, &feld_comm_key)
                    .unwrap();
                all_phase2s.insert(i as ParticipantId, phase2);
                all_comms2.insert(i as ParticipantId, comms);
            }
        }

        // Each participant receives shares and commitments during Phase2
        for i in 1..=total {
            if i == faulty_phase_1_id as usize {
                continue;
            }
            for j in 1..=total {
                if j == faulty_phase_1_id as usize {
                    continue;
                }
                if i != j {
                    let p_2 = all_phase2s.get_mut(&(i as ParticipantId)).unwrap();
                    let c_2 = all_comms2.get(&(j as ParticipantId)).unwrap();
                    p_2.add_received_commitments(j as ParticipantId, c_2.clone(), &feld_comm_key)
                        .unwrap();
                }
            }
        }

        // Say a party misbehaves in phase 2, i.e. check in 4.b fails, then others should be able to recover
        // its secret
        let mut faulty_party_shares = vec![];
        let faulty_party = &all_phase1s[faulty_phase_2_id as usize - 1];
        for i in 1..=total {
            if i == faulty_phase_1_id as usize || i == faulty_phase_2_id as usize {
                continue;
            }
            let p_2 = all_phase2s.get(&(i as ParticipantId)).unwrap();
            let share = p_2.get_phase_1_share_of_party(faulty_phase_2_id).unwrap();
            faulty_party_shares.push(share.clone());
        }
        let malicious_party_shares = VerifiableShares(faulty_party_shares);
        assert_eq!(
            malicious_party_shares.reconstruct_secret().unwrap(),
            (
                faulty_party.poly.evaluate(&Fr::zero()),
                faulty_party.blinding_poly.evaluate(&Fr::zero())
            )
        );

        // Each participant ends Phase2 and ends up with his own keys and the threshold public key
        let mut tk = None;
        for i in 1..=total {
            if i == faulty_phase_1_id as usize || i == faulty_phase_2_id as usize {
                continue;
            }
            let p_2 = all_phase2s.get_mut(&(i as ParticipantId)).unwrap();
            let (own_sk, own_pk, threshold_pk) = p_2.clone().finish().unwrap();
            assert_eq!(own_sk, all_secrets[i - 1]);
            assert_eq!(
                own_pk,
                feld_comm_key.mul_bigint(own_sk.into_bigint()).into_affine()
            );
            if tk.is_none() {
                tk = Some(threshold_pk);
            } else {
                // All generate the same threshold key
                assert_eq!(tk, Some(threshold_pk))
            }
        }
    }
}
