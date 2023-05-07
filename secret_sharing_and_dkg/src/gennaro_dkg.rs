//! Based on the paper [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf)
//! Scheme is defined in Fig 2. The protocol is run in 2 phases: Phase1 where all participants generate a
//! secret and share it using Pedersen VSS and in Phase 2 participants distribute commitments as per
//! Feldman VSS and generate the public key at the end. The public key is assumed to be of the form
//! `G*x` where `x` is the secret key and `G` is the group generator.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, rand::RngCore, vec::Vec, UniformRand};

use crate::{
    common::{
        CommitmentToCoefficients, ParticipantId, Share, ShareId, VerifiableShare, VerifiableShares,
    },
    error::SSError,
    feldman_vss, pedersen_dvss, pedersen_vss,
    pedersen_vss::CommitmentKey,
};

/// In Phase 1, each participant runs Pedersen VSS
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<G: AffineRepr> {
    /// `z_i` from the paper
    pub secret: G::ScalarField,
    pub accumulator: pedersen_dvss::SharesAccumulator<G>,
    pub poly: DensePolynomial<G::ScalarField>,
}

/// In phase 2, Each participant runs Feldman VSS (only partly) over the same secret and polynomial
/// used in Phase 1 where it distributes the commitments to other participants
/// The commitments created during Phase1 and Phase2 could be in different groups for efficiency like when
/// the public key is supposed to be in group G2, but the commitments in Phase1 can still be in group G1.
/// Thus GP1 is the commitment group from Phase 1 and GP2 is in Phase 2.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<GP2: AffineRepr<ScalarField = GP1::ScalarField>, GP1: AffineRepr> {
    pub id: ParticipantId,
    pub secret: GP2::ScalarField,
    /// Shares from Phase 1. Only participants which submitted shares in Phase 1 will be allowed in
    /// Phase 2. This is the set "QUAL" from the paper
    pub shares_phase_1: BTreeMap<ParticipantId, VerifiableShare<GP1::ScalarField>>,
    pub final_share: VerifiableShare<GP2::ScalarField>,
    /// Commitment to coefficients of the polynomial created during Phase 1.
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<GP2>>,
}

impl<GP1: AffineRepr> Phase1<GP1> {
    /// Start Phase 1 with a randomly generated secret.
    pub fn start_with_random_secret<R: RngCore>(
        rng: &mut R,
        participant_id: ParticipantId,
        threshold: ShareId,
        total: ShareId,
        comm_key: &CommitmentKey<GP1>,
    ) -> Result<
        (
            Self,
            VerifiableShares<GP1::ScalarField>,
            CommitmentToCoefficients<GP1>,
        ),
        SSError,
    > {
        let secret = GP1::ScalarField::rand(rng);
        Self::start_with_given_secret(rng, participant_id, secret, threshold, total, comm_key)
    }

    /// Start Phase 1 with a given secret.
    pub fn start_with_given_secret<R: RngCore>(
        rng: &mut R,
        participant_id: ParticipantId,
        secret: GP1::ScalarField,
        threshold: ShareId,
        total: ShareId,
        comm_key: &CommitmentKey<GP1>,
    ) -> Result<
        (
            Self,
            VerifiableShares<GP1::ScalarField>,
            CommitmentToCoefficients<GP1>,
        ),
        SSError,
    > {
        let (_, shares, commitments, poly, _) =
            pedersen_vss::deal_secret::<_, GP1>(rng, secret, threshold, total, comm_key)?;
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
            },
            shares,
            commitments,
        ))
    }

    /// Called by a participant when it receives a share from others.
    pub fn add_received_share(
        &mut self,
        sender_id: ParticipantId,
        share: VerifiableShare<GP1::ScalarField>,
        commitment_coeffs: CommitmentToCoefficients<GP1>,
        comm_key: &CommitmentKey<GP1>,
    ) -> Result<(), SSError> {
        self.accumulator
            .add_received_share(sender_id, share, commitment_coeffs, comm_key)?;
        Ok(())
    }

    /// Called when got >= `threshold` complaints for `participant_id`
    pub fn remove_participant(&mut self, participant_id: ParticipantId) -> Result<(), SSError> {
        if self.self_id() == participant_id {
            return Err(SSError::CannotRemoveSelf(participant_id));
        }
        self.accumulator.shares.remove(&participant_id);
        self.accumulator.coeff_comms.remove(&participant_id);
        Ok(())
    }

    /// Mark Phase 1 as over and initialize Phase 2.
    pub fn finish<GP2: AffineRepr<ScalarField = GP1::ScalarField>>(
        self,
        ped_comm_key: &CommitmentKey<GP1>,
        fel_comm_key: &GP2,
    ) -> Result<(Phase2<GP2, GP1>, CommitmentToCoefficients<GP2>), SSError> {
        let id = self.self_id();
        let shares_phase_1 = self.accumulator.shares.clone();
        let final_share = self.accumulator.finalize(ped_comm_key)?;

        // If `GP1` and `GP2`, An optimization to avoid computing `commitments` could be to not do an MSM in `Phase1::start..` and
        // preserve the computation `g*a_i` where `a_i` are the coefficients of the polynomial
        let commitments: CommitmentToCoefficients<GP2> =
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

    pub fn self_id(&self) -> ParticipantId {
        self.accumulator.participant_id
    }
}

impl<GP2: AffineRepr<ScalarField = GP1::ScalarField>, GP1: AffineRepr> Phase2<GP2, GP1> {
    /// Called by a participant when it receives commitments from others.
    pub fn add_received_commitments(
        &mut self,
        sender_id: ParticipantId,
        commitment_coeffs: CommitmentToCoefficients<GP2>,
        ck: &GP2,
    ) -> Result<(), SSError> {
        if self.id == sender_id {
            return Err(SSError::SenderIdSameAsReceiver(sender_id, self.id));
        }
        if !self.shares_phase_1.contains_key(&sender_id) {
            return Err(SSError::ParticipantNotAllowedInPhase2(sender_id));
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
    pub fn finish(self) -> Result<(GP2::ScalarField, GP2, GP2), SSError> {
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
                .fold(GP2::Group::zero(), |acc, v| acc + *v.commitment_to_secret())
                .into_affine(),
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::pedersen_vss::CommitmentKey;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::PrimeField;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type G1 = <Bls12_381 as Pairing>::G1Affine;

    #[test]
    fn gennaro_distributed_key_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ped_comm_key = CommitmentKey::<G1>::new::<Blake2b512>(b"test");
        let fed_comm_key = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let fed_comm_key_g2 = <Bls12_381 as Pairing>::G2Affine::rand(&mut rng);

        fn check<GP1: AffineRepr, GP2: AffineRepr<ScalarField = GP1::ScalarField>>(
            rng: &mut StdRng,
            ped_comm_key: &CommitmentKey<GP1>,
            fed_comm_key: &GP2,
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

                // Each participant starts Phase1
                for i in 1..=total {
                    let (phase1, shares, comms) = Phase1::start_with_random_secret(
                        rng,
                        i as ParticipantId,
                        threshold as ShareId,
                        total as ShareId,
                        ped_comm_key,
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
                        .finish(ped_comm_key, fed_comm_key)
                        .unwrap();
                    all_phase2s.push(phase2);
                    all_comms2.push(comms);
                }

                // Each participant receives shares and commitments during Phase2
                for i in 0..total {
                    for j in 0..total {
                        if i != j {
                            all_phase2s[i]
                                .add_received_commitments(
                                    (j + 1) as ParticipantId,
                                    all_comms2[j].clone(),
                                    fed_comm_key,
                                )
                                .unwrap();
                        }
                    }
                }

                // Each participant ends Phase2 and ends up with his own keys and the threshold public key
                let mut tk = None;
                for i in 0..total {
                    let (own_sk, own_pk, threshold_pk) = all_phase2s[i].clone().finish().unwrap();
                    assert_eq!(own_sk, all_secrets[i]);
                    assert_eq!(
                        own_pk,
                        fed_comm_key.mul_bigint(own_sk.into_bigint()).into_affine()
                    );
                    if i == 0 {
                        tk = Some(threshold_pk);
                    } else {
                        // All generate the same threshold key
                        assert_eq!(tk, Some(threshold_pk))
                    }
                }
            }
        }

        // When both Pedersen VSS and Feldman VSS have commitments in group G1
        check(&mut rng, &ped_comm_key, &fed_comm_key);
        // When both Pedersen VSS has commitments in group G1 and Feldman VSS in G2
        check(&mut rng, &ped_comm_key, &fed_comm_key_g2);
    }
}
