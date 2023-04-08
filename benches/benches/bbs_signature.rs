use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::{
    setup::{KeypairG2, PreparedPublicKeyG2, PreparedSignatureParams23G1, SignatureParams23G1},
    signature_23::Signature23G1,
};
use benches::setup_bbs_plus;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn sig_g1_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    setup_bbs_plus!(
        SignatureParams23G1,
        KeypairG2,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range,
        generate_using_rng_and_bbs23_params
    );

    let mut sign_group = c.benchmark_group("BBS signing");
    for (i, count) in message_count_range.iter().enumerate() {
        sign_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
            b.iter(|| {
                Signature23G1::<Bls12_381>::new(
                    &mut rng,
                    black_box(&messages_range[i]),
                    black_box(&keypair_range[i].secret_key),
                    black_box(&params_range[i]),
                )
                .unwrap()
            });
        });
    }
    sign_group.finish();

    let sigs_range = (0..message_count_range.len())
        .map(|i| {
            Signature23G1::<Bls12_381>::new(
                &mut rng,
                &messages_range[i],
                &keypair_range[i].secret_key,
                &params_range[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let prepared_params_range = params_range
        .iter()
        .map(|p| PreparedSignatureParams23G1::from(p.clone()))
        .collect::<Vec<_>>();
    let prepared_key_range = keypair_range
        .iter()
        .map(|kp| PreparedPublicKeyG2::from(kp.public_key.clone()))
        .collect::<Vec<_>>();

    let mut verify_group = c.benchmark_group("BBS verifying");
    for (i, count) in message_count_range.iter().enumerate() {
        verify_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
            b.iter(|| {
                sigs_range[i]
                    .verify(
                        black_box(&messages_range[i]),
                        black_box(prepared_key_range[i].clone()),
                        black_box(prepared_params_range[i].clone()),
                    )
                    .unwrap()
            });
        });
    }
    verify_group.finish();
}

criterion_group!(benches, sig_g1_benchmark);
criterion_main!(benches);
