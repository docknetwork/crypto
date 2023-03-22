use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Instant;
use test_utils::accumulators::setup_universal_accum;

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn batch(c: &mut Criterion) {
    // Increase `max` if adding bigger batches or getting `AccumulatorFull` errors
    let max = 1024000;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, mut accumulator, initial_elements, mut state) =
        setup_universal_accum(&mut rng, max);

    let mut accumulator_1 = accumulator.clone();
    let mut state_1 = state.clone();
    let mut accumulator_2 = accumulator.clone();
    let mut state_2 = state.clone();
    let mut accumulator_3 = accumulator.clone();
    let mut state_3 = state.clone();

    let batch_sizes = [10, 20, 40, 60, 100];

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
                                    &initial_elements,
                                    &mut state,
                                )
                                .unwrap();
                        })
                    }
                    let duration = start.elapsed();
                    // To prevent creating a large accumulator as cost of creating a universal accumulator depends on max size
                    for batch in &elems_batches {
                        accumulator = accumulator
                            .remove_batch(batch, &keypair.secret_key, &initial_elements, &mut state)
                            .unwrap();
                    }
                    duration
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
                            .add_batch(
                                elems_batches[i].clone(),
                                &keypair.secret_key,
                                &initial_elements,
                                &mut state_1,
                            )
                            .unwrap();
                    }
                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            accumulator_1 = accumulator_1
                                .remove_batch(
                                    &elems_batches[i],
                                    &keypair.secret_key,
                                    &initial_elements,
                                    &mut state_1,
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
                                &initial_elements,
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
                                    &initial_elements,
                                    &mut state_2,
                                )
                                .unwrap();
                        })
                    }
                    let duration = start.elapsed();
                    // To prevent creating a large accumulator as cost of creating a universal accumulator depends on max size
                    for batch in &new_elems_batches {
                        accumulator_2 = accumulator_2
                            .remove_batch(
                                batch,
                                &keypair.secret_key,
                                &initial_elements,
                                &mut state_2,
                            )
                            .unwrap();
                    }
                    duration
                })
            },
        );
    }

    for accum_size in [100, 200, 400, 800, 1600] {
        let members = (0..accum_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<Fr>>();
        accumulator_3 = accumulator_3
            .add_batch(
                members.clone(),
                &keypair.secret_key,
                &initial_elements,
                &mut state_3,
            )
            .unwrap();

        for batch_size in batch_sizes {
            c.bench_function(
                format!(
                    "Non-membership witnesses using secret key for batch of size {}, in accumulator of size {} ",
                    batch_size, accum_size
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
                        let start = Instant::now();
                        for i in 0..iters as usize {
                            black_box({
                                accumulator_3
                                    .get_non_membership_witnesses_for_batch(
                                        &elems_batches[i],
                                        &keypair.secret_key,
                                        &mut state_3,
                                        &params,
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
}

fn single(c: &mut Criterion) {
    // Increase `max` if getting `AccumulatorFull` errors
    let max = 8200;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, mut accumulator, initial_elements, mut state) =
        setup_universal_accum(&mut rng, max);

    let mut accumulator_1 = accumulator.clone();
    let mut state_1 = state.clone();
    let mut accumulator_2 = accumulator.clone();
    let mut state_2 = state.clone();
    let mut accumulator_3 = accumulator.clone();
    let mut state_3 = state.clone();
    let accumulator_4 = accumulator.clone();
    let state_4 = state.clone();

    c.bench_function("Add single element", |b| {
        b.iter_custom(|iters| {
            let elems = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let start = Instant::now();
            for i in 0..iters as usize {
                black_box({
                    accumulator = accumulator
                        .add(elems[i], &keypair.secret_key, &initial_elements, &mut state)
                        .unwrap();
                });
            }
            let duration = start.elapsed();
            // To prevent creating a large accumulator as cost of creating a universal accumulator depends on max size
            accumulator = accumulator
                .remove_batch(&elems, &keypair.secret_key, &initial_elements, &mut state)
                .unwrap();
            duration
        })
    });

    c.bench_function("Remove single element", |b| {
        b.iter_custom(|iters| {
            let elems = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            for elem in &elems {
                accumulator_1 = accumulator_1
                    .add(*elem, &keypair.secret_key, &initial_elements, &mut state_1)
                    .unwrap();
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box({
                    accumulator_1 = accumulator_1
                        .remove(
                            &elems[i],
                            &keypair.secret_key,
                            &initial_elements,
                            &mut state_1,
                        )
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
                    .add(*elem, &keypair.secret_key, &initial_elements, &mut state_2)
                    .unwrap();
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                use vb_accumulator::positive::Accumulator;

                black_box(
                    accumulator_2
                        .get_membership_witness(&elems[i], &keypair.secret_key, &state_2)
                        .unwrap(),
                );
            }
            let duration = start.elapsed();
            // To prevent creating a large accumulator
            accumulator_2 = accumulator_2
                .remove_batch(&elems, &keypair.secret_key, &initial_elements, &mut state_2)
                .unwrap();
            duration
        })
    });

    for accum_size in [100, 200, 400, 1000, 2000, 4000] {
        c.bench_function(
            format!(
                "Non-membership witness for single element in accumulator of size {}",
                accum_size
            )
            .as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let elems = (0..accum_size)
                        .map(|_| Fr::rand(&mut rng))
                        .collect::<Vec<_>>();
                    for elem in &elems {
                        accumulator_3 = accumulator_3
                            .add(*elem, &keypair.secret_key, &initial_elements, &mut state_3)
                            .unwrap();
                    }

                    let non_members = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box(
                            accumulator_3
                                .get_non_membership_witness(
                                    &non_members[i],
                                    &keypair.secret_key,
                                    &state_3,
                                    &params,
                                )
                                .unwrap(),
                        );
                    }
                    let duration = start.elapsed();
                    // To prevent creating a large accumulator
                    accumulator_3 = accumulator_3
                        .remove_batch(&elems, &keypair.secret_key, &initial_elements, &mut state_3)
                        .unwrap();
                    duration
                })
            },
        );
    }

    c.bench_function("Verify non-membership for single element", |b| {
        b.iter_custom(|iters| {
            let non_members = (0..iters).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let mut wits = Vec::with_capacity(iters as usize);

            for i in 0..iters as usize {
                wits.push(
                    accumulator_4
                        .get_non_membership_witness(
                            &non_members[i],
                            &keypair.secret_key,
                            &state_4,
                            &params,
                        )
                        .unwrap(),
                );
            }
            let start = Instant::now();
            for i in 0..iters as usize {
                black_box(accumulator_4.verify_non_membership(
                    &non_members[i],
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
