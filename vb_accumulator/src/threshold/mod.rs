//! Accumulator update, witness generation and updated witness generation in a threshold setting, i.e. where the
//! accumulator secret key `alpha` is split among many accumulator managers using Shamir secret sharing. The general idea is:
//! 1. Accumulator value post deletion: Say the current accumulator value is `V` and the deleted element is `y`,
//! then each manager creates shares `R_i = r_i * V` and `u_i = < share of r_i * (y + l_i * alpha_i)>` and sends to the user who
//! then computes `\sum_i{V_i} * 1 / \sum_i{u_i}` to get `V * 1/(y + alpha)`. This also gives the membership witness of `y`.
//! 2. Witness generation: Say the current accumulator value is `V` and the user wants witness of `y` but does not want to
//! reveal `y` to any manager. It gives shares of `y` to the managers such that each manager has `y_i` and `\sum_i{l_i * y_i} = y`.
//! Now each manager shares `R_i = r_i * V` and `u_i = < share of r_i * l_i * (y_i + alpha_i)>` and sends to the user who
//! then computes `\sum_i{V_i} * 1 / \sum_i{u_i}` to get `V * 1/(y + alpha)`. But here the user also needs to prove to each
//! manager that share `y_i` is a valid share of `y` and this `y` is a member of the accumulator `V`.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use digest::DynDigest;
use oblivious_transfer_protocols::{
    cointoss::Commitments, error::OTError,
    ot_based_multiplication::batch_mul_multi_party::ParticipantOutput as MultOut, zero_sharing,
    ParticipantId,
};
use secret_sharing_and_dkg::error::SSError;

use crate::error::VBAccumulatorError;

/// Share created by a manager when `V * 1/ (y + alpha)` needs to computed and each manager knows `y` but
/// only a share of `alpha`
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShareOfKnownMember<G: AffineRepr> {
    pub id: ParticipantId,
    pub u: G::ScalarField,
    pub R: G,
}

/// Share created by a manager when `V * 1/ (y + alpha)` needs to computed and no manager knows `y` but
/// only a share of `y` and `alpha`
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShareOfSharedMember<G: AffineRepr> {
    pub id: ParticipantId,
    pub u: G::ScalarField,
    pub R: G,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<F: PrimeField, const SALT_SIZE: usize> {
    pub id: ParticipantId,
    pub r: F,
    /// Protocols to generate shares of 0s.
    pub zero_sharing_protocol: zero_sharing::Party<F, SALT_SIZE>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Output<F: PrimeField> {
    pub id: ParticipantId,
    pub r: F,
    pub masked_signing_key_shares: F,
    pub masked_rs: F,
    pub others: Vec<ParticipantId>,
}

impl<F: PrimeField, const SALT_SIZE: usize> Phase1<F, SALT_SIZE> {
    pub fn get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(
        &self,
        other_id: &ParticipantId,
    ) -> Vec<(F, [u8; SALT_SIZE])> {
        // TODO: Remove unwrap
        self.zero_sharing_protocol
            .cointoss_protocols
            .get(other_id)
            .unwrap()
            .own_shares_and_salts
            .clone()
    }

    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        comm_zero_share: Commitments,
    ) -> Result<(), VBAccumulatorError> {
        self.zero_sharing_protocol
            .receive_commitment(sender_id, comm_zero_share)?;
        Ok(())
    }

    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        zero_shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), VBAccumulatorError> {
        self.zero_sharing_protocol
            .receive_shares(sender_id, zero_shares)?;
        Ok(())
    }

    pub fn compute_randomness_and_arguments_for_multiplication<D: Default + DynDigest + Clone>(
        self,
        signing_key: &F,
    ) -> Result<(Vec<ParticipantId>, F, F), VBAccumulatorError> {
        let others = self
            .zero_sharing_protocol
            .cointoss_protocols
            .keys()
            .map(|p| *p)
            .collect::<Vec<_>>();
        let zero_shares = self.zero_sharing_protocol.compute_zero_shares::<D>()?;
        let (masked_signing_key_share, masked_r) = compute_masked_arguments_to_multiply(
            signing_key,
            self.r,
            zero_shares,
            self.id,
            &others,
        )?;
        Ok((others, masked_signing_key_share, masked_r))
    }

    pub fn ready_to_compute_randomness_and_arguments_for_multiplication(&self) -> bool {
        self.zero_sharing_protocol
            .has_shares_from_all_who_committed()
    }
}

impl<F: PrimeField, const SALT_SIZE: usize> Phase1<F, SALT_SIZE> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        protocol_id: Vec<u8>,
    ) -> Result<(Self, BTreeMap<ParticipantId, Commitments>), VBAccumulatorError> {
        if others.contains(&id) {
            let e = OTError::ParticipantCannotBePresentInOthers(id);
            return Err(VBAccumulatorError::OTError(e));
        }
        let r = F::rand(rng);
        let (zero_sharing_protocol, comm_zero_share) =
            zero_sharing::Party::init(rng, id, 2, others, protocol_id);
        Ok((
            Self {
                id,
                r,
                zero_sharing_protocol,
            },
            comm_zero_share,
        ))
    }

    pub fn finish<D: Default + DynDigest + Clone>(
        self,
        signing_key: &F,
    ) -> Result<Phase1Output<F>, VBAccumulatorError> {
        // TODO: Ensure every one has participated in both protocols
        let id = self.id;
        let r = self.r.clone();
        let (others, masked_signing_key_share, masked_r) =
            self.compute_randomness_and_arguments_for_multiplication::<D>(signing_key)?;
        Ok(Phase1Output {
            id,
            r,
            masked_signing_key_shares: masked_signing_key_share,
            masked_rs: masked_r,
            others,
        })
    }
}

impl<G: AffineRepr> ShareOfKnownMember<G> {
    pub fn new(
        y: &G::ScalarField,
        accum: &G,
        phase1: &Phase1Output<G::ScalarField>,
        phase2: &MultOut<G::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (R, u) = Self::compute_R_and_u(
            accum,
            y,
            &phase1.r,
            &phase1.masked_rs,
            &phase1.masked_signing_key_shares,
            phase2,
        );
        Ok(Self {
            id: phase1.id,
            u,
            R,
        })
    }

    pub fn aggregate(shares: Vec<Self>) -> G {
        let mut sum_R = G::Group::zero();
        let mut sum_u = G::ScalarField::zero();
        for share in shares.into_iter() {
            sum_u += share.u;
            sum_R += share.R;
        }
        return (sum_R * sum_u.inverse().unwrap()).into_affine();
    }

    fn compute_R_and_u(
        base: &G,
        y: &G::ScalarField,
        r: &G::ScalarField,
        masked_r: &G::ScalarField,
        masked_signing_key_share: &G::ScalarField,
        phase2: &MultOut<G::ScalarField>,
    ) -> (G, G::ScalarField) {
        let R = base.mul(r).into_affine();
        let mut u = *masked_r * (*y + masked_signing_key_share);
        for (_, (a, b)) in &phase2.z_A {
            u += a[0];
            u += b[0];
        }
        for (_, (a, b)) in &phase2.z_B {
            u += a[0];
            u += b[0];
        }
        (R, u)
    }
}

impl<G: AffineRepr> ShareOfSharedMember<G> {
    pub fn new(
        accum: &G,
        phase1: &Phase1Output<G::ScalarField>,
        phase2: &MultOut<G::ScalarField>,
    ) -> Result<Self, VBAccumulatorError> {
        let (R, u) = Self::compute_R_and_u(
            accum,
            &phase1.r,
            &phase1.masked_rs,
            &phase1.masked_signing_key_shares,
            phase2,
        );
        Ok(Self {
            id: phase1.id,
            u,
            R,
        })
    }

    pub fn aggregate(shares: Vec<Self>) -> G {
        let mut sum_R = G::Group::zero();
        let mut sum_u = G::ScalarField::zero();
        for share in shares.into_iter() {
            sum_u += share.u;
            sum_R += share.R;
        }
        return (sum_R * sum_u.inverse().unwrap()).into_affine();
    }

    fn compute_R_and_u(
        base: &G,
        r: &G::ScalarField,
        masked_r: &G::ScalarField,
        masked_signing_key_share: &G::ScalarField,
        phase2: &MultOut<G::ScalarField>,
    ) -> (G, G::ScalarField) {
        let R = base.mul(r).into_affine();
        let mut u = *masked_r * masked_signing_key_share;
        for (_, (a, b)) in &phase2.z_A {
            u += a[0];
            u += b[0];
        }
        for (_, (a, b)) in &phase2.z_B {
            u += a[0];
            u += b[0];
        }
        (R, u)
    }
}

pub fn compute_masked_arguments_to_multiply<F: PrimeField>(
    signing_key: &F,
    r: F,
    mut zero_shares: Vec<F>,
    self_id: ParticipantId,
    others: &[ParticipantId],
) -> Result<(F, F), SSError> {
    let beta = zero_shares.pop().unwrap();
    let alpha = zero_shares.pop().unwrap();
    let lambda = secret_sharing_and_dkg::common::lagrange_basis_at_0::<F>(&others, self_id)?;
    Ok((alpha + (lambda * signing_key), beta + r))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Zero;
    use std::time::Instant;

    use crate::{
        persistence::test::InMemoryState,
        positive::{Accumulator, PositiveAccumulator},
        prelude::SetupParams,
        setup::{PublicKey, SecretKey},
    };
    use ark_std::{
        cfg_iter,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        batch_mul_multi_party::Participant as MultParty, dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::{deal_random_secret, deal_secret};
    use test_utils::ot::do_pairwise_base_ot;

    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    pub fn trusted_party_keygen<R: RngCore, F: PrimeField>(
        rng: &mut R,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (F, Vec<F>) {
        let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
        (secret, shares.0.into_iter().map(|s| s.share).collect())
    }

    #[test]
    fn accumulator_on_deletion() {
        let mut rng = StdRng::seed_from_u64(0u64);
        const BASE_OT_KEY_SIZE: u16 = 128;
        const KAPPA: u16 = 256;
        const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        let protocol_id = b"test".to_vec();

        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let mut accumulator = PositiveAccumulator::<Bls12_381>::initialize(&params);
        let mut state = InMemoryState::new();
        let secret_key = SecretKey(sk);
        let secret_key_shares = cfg_iter!(sk_shares)
            .map(|s| SecretKey(*s))
            .collect::<Vec<_>>();

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            ote_params.num_base_ot(),
            total_signers,
            all_party_set.clone(),
        );

        let count = 10;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator.add(elem, &secret_key, &mut state).unwrap();
            elems.push(elem);
        }

        let remove_element = &elems[5];
        let expected_new = accumulator.compute_new_post_remove(remove_element, &secret_key);

        let mut round1s = vec![];
        let mut commitments_zero_share = vec![];
        let mut round1outs = vec![];

        // Signers initiate round-1 and each signer sends commitments to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm_zero) =
                Phase1::<Fr, 256>::init(&mut rng, i, others, protocol_id.clone()).unwrap();
            round1s.push(round1);
            commitments_zero_share.push(comm_zero);
        }

        // Signers process round-1 commitments received from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    round1s[i as usize - 1]
                        .receive_commitment(
                            j,
                            commitments_zero_share[j as usize - 1]
                                .get(&i)
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                }
            }
        }

        // Signers create round-1 shares once they have the required commitments from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    let zero_share = round1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    round1s[i as usize - 1]
                        .receive_shares(j, zero_share)
                        .unwrap();
                }
            }
        }

        // Signers finish round-1 to generate the output
        let mut expected_sk = Fr::zero();
        for (i, round1) in round1s.into_iter().enumerate() {
            let out = round1
                .finish::<Blake2b512>(&secret_key_shares[i].0)
                .unwrap();
            expected_sk += out.masked_signing_key_shares;
            round1outs.push(out);
        }
        println!("Phase 1 took {:?}", start.elapsed());

        assert_eq!(expected_sk, sk);

        let mut round2s = vec![];
        let mut all_msg_1s = vec![];

        let label = b"test";

        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (phase, U) = MultParty::init(
                &mut rng,
                i,
                vec![round1outs[i as usize - 1].masked_signing_key_shares],
                vec![round1outs[i as usize - 1].masked_rs],
                base_ot_outputs[i as usize - 1].clone(),
                others,
                ote_params,
                &gadget_vector,
                label,
            )
            .unwrap();
            round2s.push(phase);
            all_msg_1s.push((i, U));
        }

        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = round2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            round2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());

        // Check that multiplication phase ran successfully, i.e. each signer has an additive share of
        // a multiplication with every other signer
        for i in 1..=threshold_signers {
            for (j, z_A) in &round2_outputs[i as usize - 1].z_A {
                let z_B = round2_outputs[*j as usize - 1].z_B.get(&i).unwrap();
                assert_eq!(
                    z_A.0[0] + z_B.0[0],
                    round1outs[i as usize - 1].masked_signing_key_shares
                        * round1outs[*j as usize - 1].masked_rs
                );
                assert_eq!(
                    z_A.1[0] + z_B.1[0],
                    round1outs[i as usize - 1].masked_rs
                        * round1outs[*j as usize - 1].masked_signing_key_shares
                );
            }
        }

        let mut shares = vec![];
        let start = Instant::now();
        for i in 0..threshold_signers as usize {
            let share = ShareOfKnownMember::new(
                remove_element,
                accumulator.value(),
                &round1outs[i],
                &round2_outputs[i],
            )
            .unwrap();
            shares.push(share);
        }
        println!(
            "Creating {} new shares took {:?}",
            threshold_signers,
            start.elapsed()
        );

        let start = Instant::now();
        let updated_accum = ShareOfKnownMember::aggregate(shares);
        println!(
            "Aggregating {} shares took {:?}",
            threshold_signers,
            start.elapsed()
        );
        assert_eq!(updated_accum, expected_new);

        accumulator = accumulator
            .remove(remove_element, &secret_key, &mut state)
            .unwrap();
        assert_eq!(expected_new, *accumulator.value());
    }

    #[test]
    fn witness_generation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        const BASE_OT_KEY_SIZE: u16 = 128;
        const KAPPA: u16 = 256;
        const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        let protocol_id = b"test".to_vec();

        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let mut accumulator = PositiveAccumulator::<Bls12_381>::initialize(&params);
        let mut state = InMemoryState::new();
        let secret_key = SecretKey(sk);
        let secret_key_shares = cfg_iter!(sk_shares)
            .map(|s| SecretKey(*s))
            .collect::<Vec<_>>();
        let public_key = PublicKey::new_from_secret_key(&secret_key, &params);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            ote_params.num_base_ot(),
            total_signers,
            all_party_set.clone(),
        );

        let count = 10;
        let mut elems = vec![];
        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator.add(elem, &secret_key, &mut state).unwrap();
            elems.push(elem);
        }

        let member = &elems[1];
        let expected_wit = accumulator
            .get_membership_witness(&member, &secret_key, &mut state)
            .unwrap();
        assert!(accumulator.verify_membership(member, &expected_wit, &public_key, &params));

        let (member_shares, _) =
            deal_secret::<StdRng, Fr>(&mut rng, *member, threshold_signers, total_signers).unwrap();

        let mut round1s = vec![];
        let mut commitments_zero_share = vec![];
        let mut round1outs = vec![];

        // Signers initiate round-1 and each signer sends commitments to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm_zero) =
                Phase1::<Fr, 256>::init(&mut rng, i, others, protocol_id.clone()).unwrap();
            round1s.push(round1);
            commitments_zero_share.push(comm_zero);
        }

        // Signers process round-1 commitments received from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    round1s[i as usize - 1]
                        .receive_commitment(
                            j,
                            commitments_zero_share[j as usize - 1]
                                .get(&i)
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                }
            }
        }

        // Signers create round-1 shares once they have the required commitments from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    let zero_share = round1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    round1s[i as usize - 1]
                        .receive_shares(j, zero_share)
                        .unwrap();
                }
            }
        }

        // Signers finish round-1 to generate the output
        let mut expected_sum = Fr::zero();
        for (i, round1) in round1s.into_iter().enumerate() {
            let out = round1
                .finish::<Blake2b512>(&(secret_key_shares[i].0 + member_shares.0[i].share))
                .unwrap();
            expected_sum += out.masked_signing_key_shares;
            round1outs.push(out);
        }
        println!("Phase 1 took {:?}", start.elapsed());

        assert_eq!(expected_sum, sk + member);

        let label = b"test";

        let mut round2s = vec![];
        let mut all_msg_1s = vec![];

        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (phase, U) = MultParty::init(
                &mut rng,
                i,
                vec![round1outs[i as usize - 1].masked_signing_key_shares],
                vec![round1outs[i as usize - 1].masked_rs],
                base_ot_outputs[i as usize - 1].clone(),
                others,
                ote_params,
                &gadget_vector,
                label,
            )
            .unwrap();
            round2s.push(phase);
            all_msg_1s.push((i, U));
        }

        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = round2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            round2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());

        // Check that multiplication phase ran successfully, i.e. each signer has an additive share of
        // a multiplication with every other signer
        for i in 1..=threshold_signers {
            for (j, z_A) in &round2_outputs[i as usize - 1].z_A {
                let z_B = round2_outputs[*j as usize - 1].z_B.get(&i).unwrap();
                assert_eq!(
                    z_A.0[0] + z_B.0[0],
                    round1outs[i as usize - 1].masked_signing_key_shares
                        * round1outs[*j as usize - 1].masked_rs
                );
                assert_eq!(
                    z_A.1[0] + z_B.1[0],
                    round1outs[i as usize - 1].masked_rs
                        * round1outs[*j as usize - 1].masked_signing_key_shares
                );
            }
        }

        let mut shares = vec![];
        let start = Instant::now();
        for i in 0..threshold_signers as usize {
            let share =
                ShareOfSharedMember::new(accumulator.value(), &round1outs[i], &round2_outputs[i])
                    .unwrap();
            shares.push(share);
        }
        println!(
            "Creating {} new shares took {:?}",
            threshold_signers,
            start.elapsed()
        );

        let start = Instant::now();
        let witness = ShareOfSharedMember::aggregate(shares);
        println!(
            "Aggregating {} shares took {:?}",
            threshold_signers,
            start.elapsed()
        );

        assert_eq!(witness, expected_wit.0);
    }
}
