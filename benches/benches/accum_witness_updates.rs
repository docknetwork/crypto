use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::{collections::HashSet, time::Instant};
use test_utils::accumulators::{setup_positive_accum, setup_universal_accum};
use vb_accumulator::{
    batch_utils::Omega,
    positive::Accumulator,
    witness::{MembershipWitness, NonMembershipWitness},
};

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn get_member_counts(batch_size: u32) -> HashSet<u32> {
    let mut member_counts = HashSet::new();
    member_counts.insert(5);
    member_counts.insert(10);
    member_counts.insert(batch_size / 4);
    member_counts.insert(batch_size / 2);
    member_counts.insert(batch_size);
    member_counts
}

fn non_membership_update_batch_using_public_info(c: &mut Criterion) {
    let max = 1000000;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, mut accumulator, initial_elements, mut state) =
        setup_universal_accum(&mut rng, max);

    // Size of each batch that is updated (added or removed from accumulator)
    let update_batch_sizes = [20, 40, 80, 160, 320, 660];

    for batch_size in update_batch_sizes {
        c.bench_function(
            format!(
                "Updating non-membership witness after adding batches of size {}",
                batch_size
            )
            .as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let elems_batches = (0..iters + 1)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();

                    accumulator = accumulator
                        .add_batch(
                            elems_batches[0].clone(),
                            &keypair.secret_key,
                            &initial_elements,
                            &mut state,
                        )
                        .unwrap();

                    let non_member = Fr::rand(&mut rng);
                    let mut old_wit = accumulator
                        .get_non_membership_witness(
                            &non_member,
                            &keypair.secret_key,
                            &mut state,
                            &params,
                        )
                        .unwrap();

                    let mut old_accums = Vec::with_capacity(iters as usize);
                    let mut omegas = Vec::with_capacity(iters as usize);
                    old_accums.push(*accumulator.value());

                    for i in 0..iters as usize {
                        accumulator = accumulator
                            .batch_updates(
                                elems_batches[i + 1].clone(),
                                &elems_batches[i],
                                &keypair.secret_key,
                                &initial_elements,
                                &mut state,
                            )
                            .unwrap();
                        if i < (iters - 1) as usize {
                            old_accums.push(*accumulator.value());
                            let omega = Omega::new(
                                &elems_batches[i + 1],
                                &elems_batches[i],
                                accumulator.value(),
                                &keypair.secret_key,
                            );
                            omegas.push(omega);
                        }
                    }

                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            old_wit = old_wit
                                .update_using_public_info_after_batch_updates(
                                    &elems_batches[i + 1],
                                    &elems_batches[i],
                                    &omegas[i],
                                    &non_member,
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

// Only benchmarking positive accumulator as for membership witnesses, the universal accumulator just
// has 1 field element multiplication more so the performance will be very similar
fn membership_update_batch_using_public_info(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let (_, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);

    // Size of each batch that is updated (added or removed from accumulator)
    let update_batch_sizes = [20, 40, 80, 160, 320, 660];

    for batch_size in update_batch_sizes {
        c.bench_function(
            format!(
                "Updating membership witness after adding and removing batches, each of size {}",
                batch_size
            )
            .as_str(),
            |b| {
                b.iter_custom(|iters| {
                    let member = Fr::rand(&mut rng);
                    accumulator = accumulator
                        .add(member, &keypair.secret_key, &mut state)
                        .unwrap();

                    let elems_batches = (0..iters + 1)
                        .map(|_| {
                            (0..batch_size)
                                .map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>()
                        })
                        .collect::<Vec<_>>();

                    accumulator = accumulator
                        .add_batch(elems_batches[0].clone(), &keypair.secret_key, &mut state)
                        .unwrap();

                    let mut old_wit = accumulator
                        .get_membership_witness(&member, &keypair.secret_key, &mut state)
                        .unwrap();

                    let mut old_accums = Vec::with_capacity(iters as usize);
                    let mut omegas = Vec::with_capacity(iters as usize);
                    old_accums.push(*accumulator.value());

                    for i in 0..iters as usize {
                        accumulator = accumulator
                            .batch_updates(
                                elems_batches[i + 1].clone(),
                                &elems_batches[i],
                                &keypair.secret_key,
                                &mut state,
                            )
                            .unwrap();
                        if i < (iters - 1) as usize {
                            old_accums.push(*accumulator.value());
                        }
                        let omega = Omega::new(
                            &elems_batches[i + 1],
                            &elems_batches[i],
                            &old_accums[i],
                            &keypair.secret_key,
                        );
                        omegas.push(omega);
                    }

                    let start = Instant::now();
                    for i in 0..iters as usize {
                        black_box({
                            old_wit = old_wit
                                .update_using_public_info_after_batch_updates(
                                    &elems_batches[i + 1],
                                    &elems_batches[i],
                                    &omegas[i],
                                    &member,
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

fn non_membership_update_batch_using_secret_key(c: &mut Criterion) {
    let max = 1000000;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, mut accumulator, initial_elements, mut state) =
        setup_universal_accum(&mut rng, max);

    // Size of each batch that is updated (added or removed from accumulator)
    let update_batch_sizes = [20, 40, 80, 160, 320, 660];

    for batch_size in update_batch_sizes {
        let non_member_counts = get_member_counts(batch_size);

        for member_count in non_member_counts {
            c.bench_function(
                format!("Updating non-membership witness of {} elements after adding batches of size {}", member_count, batch_size).as_str(),
                |b| {
                    b.iter_custom(|iters| {
                        let non_members = (0..member_count).map(|_| Fr::rand(&mut rng))
                            .collect::<Vec<Fr>>();
                        let mut old_wits = accumulator
                            .get_non_membership_witnesses_for_batch(
                                &non_members,
                                &keypair.secret_key,
                                &mut state,
                                &params
                            )
                            .unwrap();

                        let elems_batches = (0..iters)
                            .map(|_| {
                                (0..batch_size)
                                    .map(|_| Fr::rand(&mut rng))
                                    .collect::<Vec<Fr>>()
                            })
                            .collect::<Vec<_>>();

                        let mut old_accums = Vec::with_capacity(iters as usize);
                        old_accums.push(*accumulator.value());
                        for i in 0..iters as usize {
                            accumulator = accumulator
                                .add_batch(elems_batches[i].clone(), &keypair.secret_key, &initial_elements, &mut state)
                                .unwrap();
                            if i < (iters - 1) as usize {
                                old_accums.push(*accumulator.value());
                            }
                        }

                        let start = Instant::now();
                        for i in 0..iters as usize {
                            black_box({
                                old_wits = NonMembershipWitness::update_using_secret_key_after_batch_additions(
                                    &elems_batches[i],
                                    &non_members,
                                    &old_wits,
                                    &old_accums[i],
                                    &keypair.secret_key,
                                )
                                    .unwrap();
                            })
                        }
                        start.elapsed()
                    })
                },
            );
        }

        for batch_size in update_batch_sizes {
            let member_counts = get_member_counts(batch_size);

            for member_count in member_counts {
                c.bench_function(
                    format!("Updating non-membership witness of {} elements after removing batches of size {}", member_count, batch_size).as_str(),
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
                                    .add_batch(elems_batches[i].clone(), &keypair.secret_key, &initial_elements, &mut state)
                                    .unwrap();
                            }

                            let non_members = (0..member_count).map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>();
                            let mut old_wits = accumulator
                                .get_non_membership_witnesses_for_batch(
                                    &non_members,
                                    &keypair.secret_key,
                                    &mut state,
                                    &params
                                )
                                .unwrap();

                            let mut new_accums = Vec::with_capacity(iters as usize);
                            for i in 0..iters as usize {
                                accumulator = accumulator
                                    .remove_batch(&elems_batches[i], &keypair.secret_key, &initial_elements, &mut state)
                                    .unwrap();
                                new_accums.push(*accumulator.value());
                            }

                            let start = Instant::now();
                            for i in 0..iters as usize {
                                black_box({
                                    old_wits = NonMembershipWitness::update_using_secret_key_after_batch_removals(
                                        &elems_batches[i],
                                        &non_members,
                                        &old_wits,
                                        &new_accums[i],
                                        &keypair.secret_key,
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

        for batch_size in update_batch_sizes {
            let member_counts = get_member_counts(batch_size);

            for member_count in member_counts {
                c.bench_function(
                    format!("Updating non-membership witness of {} elements after adding and removing batches, each of size {}", member_count, batch_size).as_str(),
                    |b| {
                        b.iter_custom(|iters| {
                            let elems_batches = (0..iters+1)
                                .map(|_| {
                                    (0..batch_size)
                                        .map(|_| Fr::rand(&mut rng))
                                        .collect::<Vec<Fr>>()
                                })
                                .collect::<Vec<_>>();

                            accumulator = accumulator
                                .add_batch(elems_batches[0].clone(), &keypair.secret_key, &initial_elements, &mut state)
                                .unwrap();

                            let non_members = (0..member_count).map(|_| Fr::rand(&mut rng))
                                .collect::<Vec<Fr>>();
                            let mut old_wits = accumulator
                                .get_non_membership_witnesses_for_batch(
                                    &non_members,
                                    &keypair.secret_key,
                                    &mut state,
                                    &params
                                )
                                .unwrap();

                            let mut old_accums = Vec::with_capacity(iters as usize);
                            old_accums.push(*accumulator.value());

                            for i in 0..iters as usize {
                                accumulator = accumulator
                                    .batch_updates(elems_batches[i+1].clone(), &elems_batches[i], &keypair.secret_key, &initial_elements, &mut state)
                                    .unwrap();
                                if i < (iters - 1) as usize {
                                    old_accums.push(*accumulator.value());
                                }
                            }

                            let start = Instant::now();
                            for i in 0..iters as usize {
                                black_box({
                                    old_wits = NonMembershipWitness::update_using_secret_key_after_batch_updates(
                                        &elems_batches[i+1],
                                        &elems_batches[i],
                                        &non_members,
                                        &old_wits,
                                        &old_accums[i],
                                        &keypair.secret_key,
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
}

// Only benchmarking positive accumulator as for membership witnesses, the universal accumulator just
// has 1 field element multiplication more per witness so the performance will be very similar
fn membership_update_batch_using_secret_key(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let (_, pos_keypair, pos_accumulator, mut pos_state) = setup_positive_accum(&mut rng);

    // Size of each batch that is updated (added or removed from accumulator)
    let update_batch_sizes = [20, 40, 80, 160, 320, 660];

    for batch_size in update_batch_sizes {
        let member_counts = get_member_counts(batch_size);

        for member_count in member_counts {
            c.bench_function(
                format!("Updating membership witness of {} elements after adding batches of size {}", member_count, batch_size).as_str(),
                |b| {
                    b.iter_custom(|iters| {
                        let members = (0..member_count).map(|_| Fr::rand(&mut rng))
                            .collect::<Vec<Fr>>();
                        let mut pos_accumulator_1 = pos_accumulator
                            .add_batch(members.clone(), &pos_keypair.secret_key, &mut pos_state)
                            .unwrap();
                        let mut old_wits = pos_accumulator_1
                            .get_membership_witnesses_for_batch(
                                &members,
                                &pos_keypair.secret_key,
                                &mut pos_state,
                            )
                            .unwrap();

                        let elems_batches = (0..iters)
                            .map(|_| {
                                (0..batch_size)
                                    .map(|_| Fr::rand(&mut rng))
                                    .collect::<Vec<Fr>>()
                            })
                            .collect::<Vec<_>>();

                        let mut old_accums = Vec::with_capacity(iters as usize);
                        old_accums.push(*pos_accumulator_1.value());
                        for i in 0..iters as usize {
                            pos_accumulator_1 = pos_accumulator_1
                                .add_batch(elems_batches[i].clone(), &pos_keypair.secret_key, &mut pos_state)
                                .unwrap();
                            if i < (iters - 1) as usize {
                                old_accums.push(*pos_accumulator_1.value());
                            }
                        }

                        let start = Instant::now();
                        for i in 0..iters as usize {
                            black_box({
                                old_wits = MembershipWitness::update_using_secret_key_after_batch_additions(
                                    &elems_batches[i],
                                    &members,
                                    &old_wits,
                                    &old_accums[i],
                                    &pos_keypair.secret_key,
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

    for batch_size in update_batch_sizes {
        let member_counts = get_member_counts(batch_size);

        for member_count in member_counts {
            c.bench_function(
                format!("Updating membership witness of {} elements after removing batches of size {}", member_count, batch_size).as_str(),
                |b| {
                    b.iter_custom(|iters| {
                        let members = (0..member_count).map(|_| Fr::rand(&mut rng))
                            .collect::<Vec<Fr>>();
                        let mut pos_accumulator_1 = pos_accumulator
                            .add_batch(members.clone(), &pos_keypair.secret_key, &mut pos_state)
                            .unwrap();
                        let mut old_wits = pos_accumulator_1
                            .get_membership_witnesses_for_batch(
                                &members,
                                &pos_keypair.secret_key,
                                &mut pos_state,
                            )
                            .unwrap();

                        let elems_batches = (0..iters)
                            .map(|_| {
                                (0..batch_size)
                                    .map(|_| Fr::rand(&mut rng))
                                    .collect::<Vec<Fr>>()
                            })
                            .collect::<Vec<_>>();

                        for i in 0..iters as usize {
                            pos_accumulator_1 = pos_accumulator_1
                                .add_batch(elems_batches[i].clone(), &pos_keypair.secret_key, &mut pos_state)
                                .unwrap();
                        }

                        let mut new_accums = Vec::with_capacity(iters as usize);
                        for i in 0..iters as usize {
                            pos_accumulator_1 = pos_accumulator_1
                                .remove_batch(&elems_batches[i], &pos_keypair.secret_key, &mut pos_state)
                                .unwrap();
                            new_accums.push(*pos_accumulator_1.value());
                        }

                        let start = Instant::now();
                        for i in 0..iters as usize {
                            black_box({
                                old_wits = MembershipWitness::update_using_secret_key_after_batch_removals(
                                    &elems_batches[i],
                                    &members,
                                    &old_wits,
                                    &new_accums[i],
                                    &pos_keypair.secret_key,
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

    for batch_size in update_batch_sizes {
        let member_counts = get_member_counts(batch_size);

        for member_count in member_counts {
            c.bench_function(
                format!("Updating membership witness of {} elements after adding and removing batches, each of size {}", member_count, batch_size).as_str(),
                |b| {
                    b.iter_custom(|iters| {
                        let members = (0..member_count).map(|_| Fr::rand(&mut rng))
                            .collect::<Vec<Fr>>();
                        let mut pos_accumulator_1 = pos_accumulator
                            .add_batch(members.clone(), &pos_keypair.secret_key, &mut pos_state)
                            .unwrap();

                        let elems_batches = (0..iters+1)
                            .map(|_| {
                                (0..batch_size)
                                    .map(|_| Fr::rand(&mut rng))
                                    .collect::<Vec<Fr>>()
                            })
                            .collect::<Vec<_>>();

                        pos_accumulator_1 = pos_accumulator_1
                            .add_batch(elems_batches[0].clone(), &pos_keypair.secret_key, &mut pos_state)
                            .unwrap();

                        let mut old_wits = pos_accumulator_1
                            .get_membership_witnesses_for_batch(
                                &members,
                                &pos_keypair.secret_key,
                                &mut pos_state,
                            )
                            .unwrap();

                        let mut old_accums = Vec::with_capacity(iters as usize);
                        old_accums.push(*pos_accumulator_1.value());

                        for i in 0..iters as usize {
                            pos_accumulator_1 = pos_accumulator_1
                                .batch_updates(elems_batches[i+1].clone(), &elems_batches[i], &pos_keypair.secret_key, &mut pos_state)
                                .unwrap();
                            if i < (iters - 1) as usize {
                                old_accums.push(*pos_accumulator_1.value());
                            }
                        }

                        let start = Instant::now();
                        for i in 0..iters as usize {
                            black_box({
                                old_wits = MembershipWitness::update_using_secret_key_after_batch_updates(
                                    &elems_batches[i+1],
                                    &elems_batches[i],
                                    &members,
                                    &old_wits,
                                    &old_accums[i],
                                    &pos_keypair.secret_key,
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

fn membership_update_single(c: &mut Criterion) {
    let max = 1000000;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (_, pos_keypair, pos_accumulator, mut pos_state) = setup_positive_accum(&mut rng);
    let (_, uni_keypair, uni_accumulator, initial_elements, mut uni_state) =
        setup_universal_accum(&mut rng, max);

    let elem = Fr::rand(&mut rng);
    let pos_accumulator_1 = pos_accumulator
        .add(elem, &pos_keypair.secret_key, &mut pos_state)
        .unwrap();
    let uni_accumulator_1 = uni_accumulator
        .add(
            elem,
            &uni_keypair.secret_key,
            &initial_elements,
            &mut uni_state,
        )
        .unwrap();

    let elem_to_update_with = Fr::rand(&mut rng);
    let pos_accumulator_2 = pos_accumulator_1
        .add(elem_to_update_with, &pos_keypair.secret_key, &mut pos_state)
        .unwrap();
    let uni_accumulator_2 = uni_accumulator_1
        .add(
            elem_to_update_with,
            &uni_keypair.secret_key,
            &initial_elements,
            &mut uni_state,
        )
        .unwrap();

    let pos_accumulator_3 = pos_accumulator_2
        .remove(
            &elem_to_update_with,
            &pos_keypair.secret_key,
            &mut pos_state,
        )
        .unwrap();
    let uni_accumulator_3 = uni_accumulator_2
        .remove(
            &elem_to_update_with,
            &uni_keypair.secret_key,
            &initial_elements,
            &mut uni_state,
        )
        .unwrap();

    macro_rules! wit_update_add_remove {
        ($bench_name_add:expr, $bench_name_rem:expr, $accum_1: ident, $accum_2: ident, $accum_3: ident, $keypair: ident, $state: ident, $elem: ident, $elem_to_update_with: ident, $c: ident) => {
            // Getting membership witness doesn't depend on the current state so getting both witness with same state.
            let wit_1 = $accum_1
                .get_membership_witness(&$elem, &$keypair.secret_key, &$state)
                .unwrap();
            let wit_2 = $accum_2
                .get_membership_witness(&$elem, &$keypair.secret_key, &$state)
                .unwrap();

            $c.bench_function(
                $bench_name_add,
                |b| {
                    b.iter(|| {
                        wit_1.update_after_addition(
                            black_box(&$elem),
                            black_box(&$elem_to_update_with),
                            black_box(&$accum_1.value()),
                        );
                    })
                },
            );

            $c.bench_function(
                $bench_name_rem,
                |b| {
                    b.iter(|| {
                        wit_2.update_after_removal(
                            black_box(&$elem),
                            black_box(&$elem_to_update_with),
                            black_box(&$accum_3.value()),
                        ).unwrap();
                    })
                },
            );
        }
    }

    wit_update_add_remove!(
        "Membership witness update in positive accumulator after adding single element",
        "Membership witness update in positive accumulator after removing single element",
        pos_accumulator_1,
        pos_accumulator_2,
        pos_accumulator_3,
        pos_keypair,
        pos_state,
        elem,
        elem_to_update_with,
        c
    );

    wit_update_add_remove!(
        "Membership witness update in universal accumulator after adding single element",
        "Membership witness update in universal accumulator after removing single element",
        uni_accumulator_1,
        uni_accumulator_2,
        uni_accumulator_3,
        uni_keypair,
        uni_state,
        elem,
        elem_to_update_with,
        c
    );
}

fn non_membership_update_single(c: &mut Criterion) {
    let max = 10000;
    let mut rng = StdRng::seed_from_u64(0u64);

    let (params, keypair, accumulator, initial_elements, mut state) =
        setup_universal_accum(&mut rng, max);

    let non_member = Fr::rand(&mut rng);
    let wit_1 = accumulator
        .get_non_membership_witness(&non_member, &keypair.secret_key, &state, &params)
        .unwrap();

    let elem_to_update_with = Fr::rand(&mut rng);
    let accumulator_1 = accumulator
        .add(
            elem_to_update_with,
            &keypair.secret_key,
            &initial_elements,
            &mut state,
        )
        .unwrap();

    c.bench_function(
        "Non-membership witness update in universal accumulator after adding single element",
        |b| {
            b.iter(|| {
                wit_1.update_after_addition(
                    black_box(&non_member),
                    black_box(&elem_to_update_with),
                    black_box(accumulator.value()),
                );
            })
        },
    );

    let wit_2 = accumulator_1
        .get_non_membership_witness(&non_member, &keypair.secret_key, &state, &params)
        .unwrap();

    let accumulator_2 = accumulator_1
        .remove(
            &elem_to_update_with,
            &keypair.secret_key,
            &initial_elements,
            &mut state,
        )
        .unwrap();

    c.bench_function(
        "Non-membership witness update in universal accumulator after removing single element",
        |b| {
            b.iter(|| {
                wit_2
                    .update_after_removal(
                        black_box(&non_member),
                        black_box(&elem_to_update_with),
                        black_box(accumulator_2.value()),
                    )
                    .unwrap();
            })
        },
    );
}

criterion_group!(
    benches,
    membership_update_single,
    non_membership_update_single,
    membership_update_batch_using_secret_key,
    non_membership_update_batch_using_secret_key,
    membership_update_batch_using_public_info,
    non_membership_update_batch_using_public_info,
);
criterion_main!(benches);
