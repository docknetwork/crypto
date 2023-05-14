use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use benches::ot::do_1_of_2_base_ot;
use blake2::Blake2b512;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dock_crypto_utils::transcript::new_merlin_transcript;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams,
    dkls19_batch_mul_2p::{GadgetVector, Party1, Party2},
};

fn batch_multiplication(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let b = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

    const KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const SSP: u16 = 80;
    let ote_params = MultiplicationOTEParams::<KAPPA, SSP> {};
    let gadget_vector =
        GadgetVector::<Fr, KAPPA, SSP>::new::<Blake2b512>(ote_params, b"test-gadget-vector");

    let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
        do_1_of_2_base_ot::<KEY_SIZE>(&mut rng, ote_params.num_base_ot(), &b);
    let base_ot_choices = base_ot_choices
        .into_iter()
        .map(|b| b % 2 != 0)
        .collect::<Vec<_>>();

    let batch_sizes = [2, 4, 8, 16, 32];

    for batch_size in batch_sizes {
        let alpha = (0..batch_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let beta = (0..batch_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let otc = format!("for batch size {}", batch_size);

        let mut party1_transcript = new_merlin_transcript(b"test-multiplication");
        let mut party2_transcript = new_merlin_transcript(b"test-multiplication");

        c.bench_function(format!("Party1 init {}", otc).as_str(), |b| {
            b.iter(|| {
                Party1::new::<StdRng>(
                    &mut rng,
                    black_box(alpha.clone()),
                    black_box(base_ot_choices.clone()),
                    black_box(base_ot_receiver_keys.clone()),
                    black_box(ote_params),
                )
                .unwrap()
            })
        });

        c.bench_function(format!("Party2 init {}", otc).as_str(), |b| {
            b.iter(|| {
                Party2::new(
                    &mut rng,
                    black_box(beta.clone()),
                    black_box(base_ot_sender_keys.clone()),
                    &mut party2_transcript,
                    black_box(ote_params),
                    &gadget_vector,
                )
                .unwrap()
            })
        });

        let party1 = Party1::new::<StdRng>(
            &mut rng,
            alpha,
            base_ot_choices.clone(),
            base_ot_receiver_keys.clone(),
            ote_params,
        )
        .unwrap();

        let (party2, U, kos_rlc, gamma_b) = Party2::new(
            &mut rng,
            beta.clone(),
            base_ot_sender_keys.clone(),
            &mut party2_transcript,
            ote_params,
            &gadget_vector,
        )
        .unwrap();

        c.bench_function(format!("Party1 creates shares for {}", otc).as_str(), |b| {
            b.iter(|| {
                party1
                    .clone()
                    .receive::<Blake2b512>(
                        black_box(U.clone()),
                        black_box(kos_rlc.clone()),
                        black_box(gamma_b.clone()),
                        &mut party1_transcript,
                        &gadget_vector,
                    )
                    .unwrap()
            })
        });

        let (_, tau, rlc, gamma_a) = party1
            .receive::<Blake2b512>(U, kos_rlc, gamma_b, &mut party1_transcript, &gadget_vector)
            .unwrap();

        c.bench_function(format!("Party2 creates shares for {}", otc).as_str(), |b| {
            b.iter(|| {
                party2
                    .clone()
                    .receive::<Blake2b512>(
                        black_box(tau.clone()),
                        black_box(rlc.clone()),
                        black_box(gamma_a.clone()),
                        &mut party2_transcript,
                        &gadget_vector,
                    )
                    .unwrap()
            })
        });
    }
}

criterion_group!(benches, batch_multiplication);
criterion_main!(benches);
