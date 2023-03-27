use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use benches::setup_ps;
use coconut_crypto::{setup::*, Signature};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

type Fr = <Bls12_381 as Pairing>::ScalarField;

macro_rules! sign_verify {
    ($sig_params:ident, $keypair: ident, $rng: ident, $message_count_range: ident, $messages_range: ident, $params_range: ident, $secret_range: ident, $c: ident, $sig_group: ident) => {
        let mut sign_group = $c.benchmark_group("PS signing");
        for (i, count) in $message_count_range.iter().enumerate() {
            sign_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    $sig_group::<Bls12_381>::new(
                        &mut $rng,
                        black_box(&$messages_range[i]),
                        black_box(&$secret_range[i]),
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
                    &$secret_range[i],
                    &$params_range[i],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut verify_group = $c.benchmark_group("PS verifying");
        for (i, count) in $message_count_range.iter().enumerate() {
            verify_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &i| {
                b.iter(|| {
                    sigs_range[i]
                        .verify(
                            black_box(&$messages_range[i]),
                            black_box(&PublicKey::new(&$secret_range[i], &$params_range[i])),
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
    setup_ps!(
        SignatureParams,
        SecretKey,
        rng,
        message_count_range,
        messages_range,
        params_range,
        secret_range
    );
    sign_verify!(
        SignatureParams,
        KeypairG2,
        rng,
        message_count_range,
        messages_range,
        params_range,
        secret_range,
        c,
        Signature
    );
}

fn sig_g2_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_ps!(
        SignatureParams,
        SecretKey,
        rng,
        message_count_range,
        messages_range,
        params_range,
        secret_range
    );
    sign_verify!(
        SignatureParams,
        SecretKey,
        rng,
        message_count_range,
        messages_range,
        params_range,
        secret_range,
        c,
        Signature
    );
}

criterion_group!(benches, sig_g1_benchmark, sig_g2_benchmark);
criterion_main!(benches);
