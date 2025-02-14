//! Accumulator update, witness generation and updated witness generation in a threshold setting, i.e. where the
//! accumulator secret key `alpha` is split among many accumulator managers using Shamir secret sharing. The general idea is:
//!
//! 1. Accumulator value post deletion: Say the current accumulator value is `V` and the deleted element is `y`,
//! then each manager creates shares `R_i = r_i * V` and `u_i = < share of r_i * (y + l_i * alpha_i)>` and sends to the user who
//! then computes `\sum_i{V_i} * 1 / \sum_i{u_i}` to get `V * 1/(y + alpha)`. This also gives the membership witness of `y`.
//!
//! 2. Witness generation: Say the current accumulator value is `V` and the user wants witness of `y` but does not want to
//! reveal `y` to any manager. It gives shares of `y` to the managers such that each manager has `y_i` and `\sum_i{l_i * y_i} = y`.
//! Now each manager shares `R_i = r_i * V` and `u_i = < share of r_i * l_i * (y_i + alpha_i)>` and sends to the user who
//! then computes `\sum_i{V_i} * 1 / \sum_i{u_i}` to get `V * 1/(y + alpha)`. But here the user also needs to prove to each
//! manager that share `y_i` is a valid share of `y` and this `y` is a member of the accumulator `V`.

#[cfg(test)]
pub mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ff::{PrimeField, Zero};
    use ark_std::{collections::BTreeSet, rand::RngCore, vec::Vec};
    use oblivious_transfer_protocols::ParticipantId;
    use std::time::Instant;

    use crate::{
        persistence::test::InMemoryState,
        positive::{Accumulator, PositiveAccumulator},
        prelude::SetupParams,
        setup::{PublicKey, SecretKey},
    };
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput, dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::{deal_random_secret, deal_secret};
    use sha3::Shake256;
    use short_group_sig::threshold_weak_bb_sig::{Phase2, SigShare};
    use test_utils::ot::do_pairwise_base_ot;

    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
    const OTE_PARAMS: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER> =
        MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

    pub fn trusted_party_keygen<R: RngCore, F: PrimeField>(
        rng: &mut R,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (F, Vec<F>) {
        let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
        (secret, shares.0.into_iter().map(|s| s.share).collect())
    }

    fn do_phase1(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        protocol_id: Vec<u8>,
    ) -> Vec<short_group_sig::threshold_weak_bb_sig::Phase1Output<Fr>> {
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

        let mut phase1s = vec![];
        let mut commitments_zero_share = vec![];

        // Signers initiate round-1 and each signer sends commitments to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm_zero) =
                short_group_sig::threshold_weak_bb_sig::Phase1::<Fr, 256>::init::<_, Blake2b512>(
                    rng,
                    i,
                    others,
                    protocol_id.clone(),
                )
                .unwrap();
            phase1s.push(round1);
            commitments_zero_share.push(comm_zero);
        }

        // Signers process round-1 commitments received from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    phase1s[i as usize - 1]
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
                    let zero_share = phase1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    phase1s[i as usize - 1]
                        .receive_shares::<Blake2b512>(j, zero_share)
                        .unwrap();
                }
            }
        }

        // Signers finish round-1 to generate the output
        let phase1_outputs = phase1s
            .into_iter()
            .map(|p| p.finish::<Blake2b512>().unwrap())
            .collect::<Vec<_>>();
        println!("Phase 1 took {:?}", start.elapsed());
        phase1_outputs
    }

    fn do_phase2(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        pk_gen: &G1Affine,
        base_ot_outputs: &[BaseOTOutput],
        phase1_outs: &[short_group_sig::threshold_weak_bb_sig::Phase1Output<Fr>],
        expected_sk_term: Fr,
        secret_key_shares: &[Fr],
        full_element: Option<Fr>,
        element_shares: Option<Vec<Fr>>,
    ) -> Vec<SigShare<G1Affine>> {
        let mut phase2s = vec![];
        let mut all_msg_1s = vec![];

        let label = b"test";

        // Only one of them should be set
        assert!(full_element.is_some() ^ element_shares.is_some());
        let known_element = full_element.is_some();
        let full_element = full_element.unwrap_or_default();
        let element_shares = element_shares.unwrap_or_default();

        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let (phase, msgs) = if known_element {
                Phase2::init_for_known_message::<_, Shake256>(
                    rng,
                    i,
                    secret_key_shares[i as usize - 1],
                    full_element,
                    phase1_outs[i as usize - 1].clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    OTE_PARAMS,
                    &gadget_vector,
                    label,
                )
                .unwrap()
            } else {
                Phase2::init_for_shared_message::<_, Shake256>(
                    rng,
                    i,
                    secret_key_shares[i as usize - 1],
                    element_shares[i as usize - 1],
                    phase1_outs[i as usize - 1].clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    OTE_PARAMS,
                    &gadget_vector,
                    label,
                )
                .unwrap()
            };
            phase2s.push(phase);
            all_msg_1s.push((i, msgs));
        }

        let mut sk_term = Fr::zero();
        for p in &phase2s {
            sk_term += p.masked_sk_term_share
        }
        assert_eq!(expected_sk_term, sk_term);

        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = phase2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512, Shake256>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            phase2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let shares = phase2s
            .into_iter()
            .map(|p| p.finish(pk_gen))
            .collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());
        shares
    }

    #[test]
    fn accumulator_on_deletion() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let mut accumulator = PositiveAccumulator::<G1Affine>::initialize(&params);
        let mut state = InMemoryState::new();
        let secret_key = SecretKey(sk);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            OTE_PARAMS.num_base_ot(),
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

        let protocol_id = b"test".to_vec();

        let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

        let shares = do_phase2(
            &mut rng,
            threshold_signers,
            &gadget_vector,
            &accumulator.value(),
            &base_ot_outputs,
            &phase1_outs,
            sk,
            &sk_shares,
            Some(remove_element.clone()),
            None,
        );

        let start = Instant::now();
        let updated_accum = SigShare::aggregate(shares);
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
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        let protocol_id = b"test".to_vec();

        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        let mut accumulator = PositiveAccumulator::<G1Affine>::initialize(&params);
        let mut state = InMemoryState::new();
        let secret_key = SecretKey(sk);
        let public_key = PublicKey::new_from_secret_key(&secret_key, &params);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            OTE_PARAMS.num_base_ot(),
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
            .get_membership_witness(member, &secret_key, &mut state)
            .unwrap();
        assert!(accumulator.verify_membership(member, &expected_wit, &public_key, &params));

        let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

        let (member_shares, _) =
            deal_secret::<StdRng, Fr>(&mut rng, *member, threshold_signers, total_signers).unwrap();

        let shares = do_phase2(
            &mut rng,
            threshold_signers,
            &gadget_vector,
            &accumulator.value(),
            &base_ot_outputs,
            &phase1_outs,
            sk + member,
            &sk_shares,
            None,
            Some(
                member_shares
                    .0
                    .into_iter()
                    .map(|share| share.share)
                    .collect(),
            ),
        );

        let start = Instant::now();
        let witness = SigShare::aggregate(shares);
        println!(
            "Aggregating {} shares took {:?}",
            threshold_signers,
            start.elapsed()
        );

        assert_eq!(witness, expected_wit.0);
    }
}
