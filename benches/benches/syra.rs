use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ff::Zero;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::{
    collections::BTreeSet,
    rand::{prelude::StdRng, SeedableRng},
};
use benches::ot::do_pairwise_base_ot;
use blake2::Blake2b512;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use oblivious_transfer_protocols::ot_based_multiplication::{
    base_ot_multi_party_pairwise::BaseOTOutput, dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::GadgetVector,
};
use schnorr_pok::compute_random_oracle_challenge;
use secret_sharing_and_dkg::{common::ParticipantId, shamir_ss::deal_random_secret};
use sha3::Shake256;
use syra::{
    pseudonym::PseudonymGenProtocol,
    setup::{
        IssuerPublicKey, IssuerSecretKey, PreparedIssuerPublicKey, PreparedSetupParams,
        SetupParams, UserSecretKey,
    },
    threshold_issuance::{Phase1, Phase1Output, Phase2, UserSecretKeyShare},
};
use test_utils::statistics::statistics;

const BASE_OT_KEY_SIZE: u16 = 128;
const KAPPA: u16 = 256;
const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
const OTE_PARAMS: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER> =
    MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

pub fn trusted_party_keygen(
    rng: &mut StdRng,
    threshold: ParticipantId,
    total: ParticipantId,
) -> (Fr, Vec<Fr>) {
    let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
    (secret, shares.0.into_iter().map(|s| s.share).collect())
}

fn do_phase1(
    rng: &mut StdRng,
    threshold_signers: ParticipantId,
    protocol_id: Vec<u8>,
) -> Vec<Phase1Output<Fr>> {
    let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

    let mut phase1s = vec![];
    let mut commitments_zero_share = vec![];

    // Signers initiate round-1 and each signer sends commitments to others
    for i in 1..=threshold_signers {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (round1, comm_zero) =
            Phase1::<Fr, 256>::init::<_, Blake2b512>(rng, i, others, protocol_id.clone()).unwrap();
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
    phase1_outputs
}

fn do_phase2(
    rng: &mut StdRng,
    threshold_signers: ParticipantId,
    gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    params: impl Into<PreparedSetupParams<Bls12_381>>,
    base_ot_outputs: &[BaseOTOutput],
    phase1_outs: &[Phase1Output<Fr>],
    expected_sk_term: Fr,
    secret_key_shares: &[IssuerSecretKey<Fr>],
    user_id: Option<Fr>,
    user_id_shares: Option<Vec<Fr>>,
) -> Vec<UserSecretKeyShare<Bls12_381>> {
    let mut phase2s = vec![];
    let mut all_msg_1s = vec![];

    let label = b"test";

    let known_id = user_id.is_some();
    let user_id = user_id.unwrap_or_default();
    let user_id_shares = user_id_shares.unwrap_or_default();

    // Signers initiate round-2 and each signer sends messages to others
    for i in 1..=threshold_signers {
        let (phase, msgs) = if known_id {
            Phase2::init_for_user_id::<_, Shake256>(
                rng,
                i,
                &secret_key_shares[i as usize - 1],
                user_id,
                phase1_outs[i as usize - 1].clone(),
                base_ot_outputs[i as usize - 1].clone(),
                OTE_PARAMS,
                &gadget_vector,
                label,
            )
            .unwrap()
        } else {
            Phase2::init_for_shared_user_id::<_, Shake256>(
                rng,
                i,
                &secret_key_shares[i as usize - 1],
                user_id_shares[i as usize - 1],
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
        sk_term += p.0.masked_sk_term_share
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

    let params = params.into();
    let usk_shares = phase2s
        .into_iter()
        .map(|p| p.finish::<Bls12_381>(params.clone()))
        .collect::<Vec<_>>();
    usk_shares
}

fn threshold_issuance_with_known_user_id(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
    let prepared_params = PreparedSetupParams::<Bls12_381>::from(params.clone());

    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        OTE_PARAMS,
        b"test-gadget-vector",
    );

    // for (threshold_signers, total_signers) in [(5, 10), (15, 30), (30, 60), (50, 100), (70, 140)] {
    for (threshold_signers, total_signers) in [
        (5, 10),
        (10, 20),
        (15, 30),
        (20, 40),
        (25, 50),
        (30, 60),
        (35, 70),
        (40, 80),
        (45, 90),
        (50, 100),
        (55, 110),
        (60, 120),
        (65, 130),
        (70, 140),
    ] {
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) = trusted_party_keygen(&mut rng, threshold_signers, total_signers);
        let isk_shares = sk_shares
            .into_iter()
            .map(|s| IssuerSecretKey(s))
            .collect::<Vec<_>>();
        // Public key created by the trusted party using the secret key directly. In practice, this will be a result of a DKG
        let threshold_ipk = IssuerPublicKey::new(&mut rng, &IssuerSecretKey(sk), &params);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            OTE_PARAMS.num_base_ot(),
            total_signers,
            all_party_set.clone(),
        );

        // Signing starts
        let protocol_id = b"test".to_vec();

        c.bench_with_input(
            BenchmarkId::new("Phase1", threshold_signers),
            &threshold_signers,
            |b, &threshold_signers| {
                b.iter(|| {
                    black_box(do_phase1(
                        &mut rng,
                        black_box(threshold_signers),
                        black_box(protocol_id.clone()),
                    ))
                })
            },
        );

        let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

        // Signer creates user secret key
        let user_id = compute_random_oracle_challenge::<Fr, Blake2b512>(b"low entropy user-id");

        c.bench_with_input(
            BenchmarkId::new("Phase2", threshold_signers),
            &threshold_signers,
            |b, &threshold_signers| {
                b.iter(|| {
                    black_box(do_phase2(
                        &mut rng,
                        black_box(threshold_signers),
                        black_box(&gadget_vector),
                        black_box(prepared_params.clone()),
                        black_box(&base_ot_outputs),
                        black_box(&phase1_outs),
                        black_box(sk),
                        black_box(&isk_shares),
                        black_box(Some(user_id)),
                        black_box(None),
                    ))
                })
            },
        );

        let usk_shares = do_phase2(
            &mut rng,
            threshold_signers,
            &gadget_vector,
            prepared_params.clone(),
            &base_ot_outputs,
            &phase1_outs,
            sk,
            &isk_shares,
            Some(user_id),
            None,
        );

        c.bench_with_input(
            BenchmarkId::new("Aggregation", threshold_signers),
            &threshold_signers,
            |b, &_threshold_signers| {
                b.iter(|| {
                    black_box(UserSecretKeyShare::aggregate(
                        black_box(usk_shares.clone()),
                        black_box(prepared_params.clone()),
                    ))
                })
            },
        );

        let usk = UserSecretKeyShare::aggregate(usk_shares, prepared_params.clone());

        usk.verify(user_id, &threshold_ipk, prepared_params.clone())
            .unwrap();
    }
}

fn pseudonym(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
    let prepared_params = PreparedSetupParams::<Bls12_381>::from(params.clone());

    // Signer's setup
    let isk = IssuerSecretKey::new(&mut rng);
    let ipk = IssuerPublicKey::new(&mut rng, &isk, &params);
    let prepared_ipk = PreparedIssuerPublicKey::new(ipk.clone(), params.clone());

    // Signer creates user secret key
    let user_id = compute_random_oracle_challenge::<Fr, Blake2b512>(b"low entropy user-id");

    c.bench_function("User secret key generation", |b| {
        b.iter(|| black_box(UserSecretKey::new(user_id, &isk, prepared_params.clone())))
    });

    let usk = UserSecretKey::new(user_id, &isk, prepared_params.clone());

    c.bench_function("User secret key verification", |b| {
        b.iter(|| black_box(usk.verify(user_id, &ipk, prepared_params.clone()).unwrap()))
    });

    usk.verify(user_id, &ipk, prepared_params.clone()).unwrap();

    // Verifier gives message and context to user
    let context = b"test-context";
    let msg = b"test-message";

    // Generate Z from context
    let Z = affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(context);

    c.bench_function("User creates pseudonym and corresponding proof", |b| {
        b.iter(|| {
            black_box({
                let protocol = PseudonymGenProtocol::init(
                    &mut rng,
                    Z.clone(),
                    user_id.clone(),
                    None,
                    &usk,
                    prepared_ipk.clone(),
                    prepared_params.clone(),
                );
                let mut chal_bytes = vec![];
                protocol
                    .challenge_contribution(&Z, &mut chal_bytes)
                    .unwrap();
                // Add message to the transcript (message contributes to challenge)
                chal_bytes.extend_from_slice(msg);
                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                protocol.gen_proof(&challenge_prover);
            })
        })
    });

    let protocol = PseudonymGenProtocol::init(
        &mut rng,
        Z.clone(),
        user_id.clone(),
        None,
        &usk,
        prepared_ipk.clone(),
        prepared_params.clone(),
    );
    let mut chal_bytes = vec![];
    protocol
        .challenge_contribution(&Z, &mut chal_bytes)
        .unwrap();
    // Add message to the transcript (message contributes to challenge)
    chal_bytes.extend_from_slice(msg);
    let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
    let proof = protocol.gen_proof(&challenge_prover);

    c.bench_function("Verifier checks proof", |b| {
        b.iter(|| {
            black_box({
                // Verifier checks the correctness of the pseudonym
                let mut chal_bytes = vec![];
                proof.challenge_contribution(&Z, &mut chal_bytes).unwrap();
                // Add message to the transcript (message contributes to challenge)
                chal_bytes.extend_from_slice(msg);
                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
                proof
                    .verify(
                        &challenge_verifier,
                        Z,
                        prepared_ipk.clone(),
                        prepared_params.clone(),
                    )
                    .unwrap();
            })
        })
    });
}

// criterion_group!(benches, threshold_issuance_with_known_user_id, pseudonym);
// criterion_main!(benches);

fn main() {
    use std::time::Instant;
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
    let prepared_params = PreparedSetupParams::<Bls12_381>::from(params.clone());

    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        OTE_PARAMS,
        b"test-gadget-vector",
    );

    const NUM_ITERATIONS: usize = 10;
    // let ps = [(5, 10), (10, 20)];
    // let ps = [(5, 10), (10, 20), (15, 30), (20, 40), (25, 50), (30, 60), (35, 70), (40, 80), (45, 90), (50, 100), (55, 110), (60, 120), (65, 130), (70, 140)];
    let ps = [(350, 700)];
    let max = ps.iter().map(|(t, _)| *t).max().unwrap();
    let start = Instant::now();
    // The signers run OT protocol instances. This is also a one time setup.
    let base_ot_outputs = test_utils::ot::do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng,
        OTE_PARAMS.num_base_ot(),
        max,
        (1..=max).into_iter().collect::<BTreeSet<_>>(),
    );
    println!("Time taken for {} base OT {:.2?}", max, start.elapsed());
    println!(
        "Uncompressed size of base OT {}",
        base_ot_outputs.serialized_size(Compress::No)
    );
    println!(
        "Compressed size of base OT {}",
        base_ot_outputs.serialized_size(Compress::Yes)
    );

    for (threshold_signers, total_signers) in ps {
        println!(
            "\nRunning {} iterations for {}-of-{}",
            NUM_ITERATIONS, threshold_signers, total_signers
        );
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) = trusted_party_keygen(&mut rng, threshold_signers, total_signers);
        let isk_shares = sk_shares
            .into_iter()
            .map(|s| IssuerSecretKey(s))
            .collect::<Vec<_>>();
        // Public key created by the trusted party using the secret key directly. In practice, this will be a result of a DKG
        let threshold_ipk = IssuerPublicKey::new(&mut rng, &IssuerSecretKey(sk), &params);

        // // The signers run OT protocol instances. This is also a one time setup.
        // let base_ot_outputs = test_utils::ot::do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        //     &mut rng,
        //     OTE_PARAMS.num_base_ot(),
        //     total_signers,
        //     all_party_set.clone(),
        // );

        let mut phase1_time = vec![];
        let mut phase2_time = vec![];
        let mut aggr_time = vec![];

        for _ in 0..NUM_ITERATIONS {
            // Signing starts
            let protocol_id = b"test".to_vec();

            let start = Instant::now();
            let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());
            phase1_time.push(start.elapsed());

            // Signer creates user secret key
            let user_id = compute_random_oracle_challenge::<Fr, Blake2b512>(b"low entropy user-id");

            let start = Instant::now();
            let usk_shares = do_phase2(
                &mut rng,
                threshold_signers,
                &gadget_vector,
                prepared_params.clone(),
                &base_ot_outputs,
                &phase1_outs,
                sk,
                &isk_shares,
                Some(user_id),
                None,
            );
            phase2_time.push(start.elapsed());

            let start = Instant::now();
            let usk = UserSecretKeyShare::aggregate(usk_shares, prepared_params.clone());
            aggr_time.push(start.elapsed());

            usk.verify(user_id, &threshold_ipk, prepared_params.clone())
                .unwrap();
        }
        println!("Phase1 time: {:?}", statistics(phase1_time));
        println!("Phase2 time: {:?}", statistics(phase2_time));
        println!("Aggregation time: {:?}", statistics(aggr_time));
    }
}
