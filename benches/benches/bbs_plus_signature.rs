use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::setup::{KeypairG1, KeypairG2, SignatureParamsG1, SignatureParamsG2};
use bbs_plus::signature::{SignatureG1, SignatureG2};
use benches::setup_bbs_plus;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

type Fr = <Bls12_381 as Pairing>::ScalarField;

macro_rules! sign_verify {
    ($sig_params:ident, $keypair: ident, $rng: ident, $message_count_range: ident, $messages_range: ident, $params_range: ident, $keypair_range: ident, $c: ident, $sig_group: ident) => {
        let mut sign_group = $c.benchmark_group("BBS+ signing");
        for (i, count) in $message_count_range.iter().enumerate() {
            sign_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    $sig_group::<Bls12_381>::new(
                        &mut $rng,
                        black_box(&$messages_range[i]),
                        black_box(&$keypair_range[i].secret_key),
                        black_box(&$params_range[i]),
                    )
                    .unwrap()
                });
            });
        }
        sign_group.finish();

        let sigs_range = (0..$message_count_range.len())
            .map(|i| {
                $sig_group::<Bls12_381>::new(
                    &mut $rng,
                    &$messages_range[i],
                    &$keypair_range[i].secret_key,
                    &$params_range[i],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut verify_group = $c.benchmark_group("BBS+ verifying");
        for (i, count) in $message_count_range.iter().enumerate() {
            verify_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    sigs_range[i]
                        .verify(
                            black_box(&$messages_range[i]),
                            black_box(&$keypair_range[i].public_key),
                            black_box(&$params_range[i]),
                        )
                        .unwrap()
                });
            });
        }
        verify_group.finish();
    };
}

fn sig_g1_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_bbs_plus!(
        SignatureParamsG1,
        KeypairG2,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range
    );
    sign_verify!(
        SignatureParamsG1,
        KeypairG2,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range,
        c,
        SignatureG1
    );
}

fn sig_g2_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_bbs_plus!(
        SignatureParamsG2,
        KeypairG1,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range
    );
    sign_verify!(
        SignatureParamsG2,
        KeypairG1,
        rng,
        message_count_range,
        messages_range,
        params_range,
        keypair_range,
        c,
        SignatureG2
    );
}

criterion_group!(benches, sig_g1_benchmark, sig_g2_benchmark);
criterion_main!(benches);
