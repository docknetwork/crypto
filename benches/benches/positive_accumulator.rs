use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use std::time::Instant;
use test_utils::accumulators::setup_positive_accum;
use vb_accumulator::positive::Accumulator;

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn batch(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let (_, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);
    let mut accumulator_1 = accumulator.clone();
    let mut state_1 = state.clone();
    let mut accumulator_2 = accumulator.clone();
    let mut state_2 = state.clone();

    let batch_sizes = [10, 20, 40, 60, 100, 200];

    for batch_size in batch_sizes {
        c.bench_function(
            format!("Add batches of size {}", batch_size).as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let elems_batches = (0..iters)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();
                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            accumulator = accumulator
                                .add_batch(
                                    elems_batches[i].clone(),
                                    &keypair.secret_key,
                                    &mut state,
                                )
                                .unwrap();
                        })
                    }
                    start.elapsed()
                })
            },
        );
    }

    for batch_size in batch_sizes {
        c.bench_function(
            format!("Removing batches of size {}", batch_size).as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let elems_batches = (0..iters)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();
                    for i in 0..iters as usize {
                        accumulator_1 = accumulator_1
                            .add_batch(elems_batches[i].clone(), &keypair.secret_key, &mut state_1)
                            .unwrap();
                    }
                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            accumulator_1 = accumulator_1
                                .remove_batch(&elems_batches[i], &keypair.secret_key, &mut state_1)
                                .unwrap();
                        })
                    }
                    start.elapsed()
                })
            },
        );
    }

    for batch_size in batch_sizes {
        c.bench_function(
            format!("Adding and removing batches, each of size {}", batch_size).as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let existing_elems_batches = (0..iters)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();
                    for i in 0..iters as usize {
                        accumulator_2 = accumulator_2
                            .add_batch(
                                existing_elems_batches[i].clone(),
                                &keypair.secret_key,
                                &mut state_2,
                            )
                            .unwrap();
                    }
                    let new_elems_batches = (0..iters)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();
                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            accumulator_2 = accumulator_2
                                .batch_updates(
                                    new_elems_batches[i].clone(),
                                    &existing_elems_batches[i],
                                    &keypair.secret_key,
                                    &mut state_2,
                                )
                                .unwrap();
                        })
                    }
                    start.elapsed()
                })
            },
        );
    }

    for batch_size in batch_sizes {
        c.bench_function(
            format!(
                "Membership witnesses using secret key for batch of size {}",
                batch_size
            )
            .as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let elems_batches = (0..iters)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();
                    for i in 0..iters as usize {
                        accumulator = accumulator
                            .add_batch(elems_batches[i].clone(), &keypair.secret_key, &mut state)
                            .unwrap();
                    }
                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            accumulator
                                .get_membership_witnesses_for_batch(
                                    &elems_batches[i],
                                    &keypair.secret_key,
                                    &mut state,
                                )
                                .unwrap();
                        })
                    }
                    start.elapsed()
                })
            },
        );
    }
}

fn single(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

    let mut accumulator_1 = accumulator.clone();
    let mut state_1 = state.clone();
    let mut accumulator_2 = accumulator.clone();
    let mut state_2 = state.clone();
    let mut accumulator_3 = accumulator.clone();
    let mut state_3 = state.clone();

    c.bench_function("Add single element", |b| {
        b.iter_batched(
            || Fr::rand(&mut rng),
            |elem| {
                accumulator = accumulator
                    .add(elem, &keypair.secret_key, &mut state)
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("Remove single element", |b| {
        b.iter_custom(|iters| {
            let elems = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            for elem in &elems {
                accumulator_1 = accumulator_1
                    .add(*elem, &keypair.secret_key, &mut state_1)
                    .unwrap();
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box({
                    accumulator_1 = accumulator_1
                        .remove(&elems[i], &keypair.secret_key, &mut state_1)
                        .unwrap();
                });
            }
            start.elapsed()
        })
    });

    c.bench_function("Membership witness for single element", |b| {
        b.iter_custom(|iters| {
            let elems = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            for elem in &elems {
                accumulator_2 = accumulator_2
                    .add(*elem, &keypair.secret_key, &mut state_2)
                    .unwrap();
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box(
                    accumulator_2
                        .get_membership_witness(&elems[i], &keypair.secret_key, &state_2)
                        .unwrap(),
                );
            }
            start.elapsed()
        })
    });

    c.bench_function("Verify membership for single element", |b| {
        b.iter_custom(|iters| {
            let elems = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let mut wits = Vec::with_capacity(iters as usize);
            for elem in &elems {
                accumulator_3 = accumulator_3
                    .add(*elem, &keypair.secret_key, &mut state_3)
                    .unwrap();
            }
            for i in 0..iters as usize {
                wits.push(
                    accumulator_3
                        .get_membership_witness(&elems[i], &keypair.secret_key, &state_3)
                        .unwrap(),
                );
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box(accumulator_3.verify_membership(
                    &elems[i],
                    &wits[i],
                    &keypair.public_key,
                    &params,
                ));
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, single, batch);
criterion_main!(benches);
