use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{prelude::StdRng, RngCore, SeedableRng},
    UniformRand,
};
use benches::ot::do_1_of_2_base_ot;
use blake2::Blake2b512;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oblivious_transfer_protocols::{
    configs::OTEConfig,
    ot_extensions::kos_ote::{OTExtensionReceiverSetup, OTExtensionSenderSetup},
};
use sha3::Shake256;

fn kos_ote(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let b = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
    let ot_counts = [(128, 1024), (192, 4096), (200, 8192)];
    let message_size = 512;
    const KEY_SIZE: u16 = 128;
    const SSP: u16 = 80;

    for (base_ot_count, extended_ot_count) in ot_counts {
        let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
            do_1_of_2_base_ot::<KEY_SIZE>(&mut rng, base_ot_count, &b);
        let ot_ext_choices = (0..extended_ot_count)
            .map(|_| u8::rand(&mut rng) % 2 != 0)
            .collect::<Vec<_>>();
        let messages = (0..extended_ot_count)
            .map(|_| {
                (
                    {
                        let mut bytes = vec![0u8; message_size];
                        rng.fill_bytes(&mut bytes);
                        bytes
                    },
                    {
                        let mut bytes = vec![0u8; message_size];
                        rng.fill_bytes(&mut bytes);
                        bytes
                    },
                )
            })
            .collect::<Vec<_>>();

        let ote_config = OTEConfig::new(base_ot_count, extended_ot_count).unwrap();

        let otc = format!(
            "for base {} OTs and {} extended OTs",
            base_ot_count, extended_ot_count
        );

        c.bench_function(
            format!("OT extension receiver setup {}", otc).as_str(),
            |b| {
                b.iter(|| {
                    let r = OTExtensionReceiverSetup::new::<_, Shake256, SSP>(
                        &mut rng,
                        black_box(ote_config),
                        black_box(ot_ext_choices.clone()),
                        black_box(base_ot_sender_keys.clone()),
                    )
                    .unwrap();
                    black_box(r)
                })
            },
        );

        let (ext_receiver_setup, u, rlc) = OTExtensionReceiverSetup::new::<_, Shake256, SSP>(
            &mut rng,
            ote_config,
            ot_ext_choices.clone(),
            base_ot_sender_keys,
        )
        .unwrap();
        let base_ot_choices = base_ot_choices
            .into_iter()
            .map(|b| b % 2 != 0)
            .collect::<Vec<_>>();

        c.bench_function(
            format!("OT extension receiver setup {}", otc).as_str(),
            |b| {
                b.iter(|| {
                    let r = OTExtensionSenderSetup::new::<Shake256, SSP>(
                        black_box(ote_config),
                        black_box(u.clone()),
                        black_box(rlc.clone()),
                        black_box(base_ot_choices.clone()),
                        black_box(base_ot_receiver_keys.clone()),
                    )
                    .unwrap();
                    black_box(r)
                })
            },
        );

        let ext_sender_setup = OTExtensionSenderSetup::new::<Shake256, SSP>(
            ote_config,
            u,
            rlc,
            base_ot_choices,
            base_ot_receiver_keys,
        )
        .unwrap();

        c.bench_function(format!("Encrypt chosen messages {}", otc).as_str(), |b| {
            b.iter(|| {
                let r = ext_sender_setup
                    .clone()
                    .encrypt::<Shake256>(
                        black_box(messages.clone()),
                        black_box(message_size as u32),
                    )
                    .unwrap();
                black_box(r)
            })
        });

        let encryptions = ext_sender_setup
            .encrypt::<Shake256>(messages.clone(), message_size as u32)
            .unwrap();

        c.bench_function(format!("Decrypt chosen messages {}", otc).as_str(), |b| {
            b.iter(|| {
                let r = ext_receiver_setup
                    .clone()
                    .decrypt::<Shake256>(
                        black_box(encryptions.clone()),
                        black_box(message_size as u32),
                    )
                    .unwrap();
                black_box(r)
            })
        });

        let alpha = (0..extended_ot_count)
            .map(|_| (Fr::rand(&mut rng), Fr::rand(&mut rng)))
            .collect::<Vec<_>>();

        c.bench_function(format!("Encrypt correlations {}", otc).as_str(), |b| {
            b.iter(|| {
                let r = ext_sender_setup
                    .transfer::<Fr, Blake2b512>(alpha.clone())
                    .unwrap();
                black_box(r)
            })
        });

        let (_, tau) = ext_sender_setup
            .transfer::<Fr, Blake2b512>(alpha.clone())
            .unwrap();

        c.bench_function(format!("Decrypt correlations {}", otc).as_str(), |b| {
            b.iter(|| {
                let r = ext_receiver_setup
                    .receive::<Fr, Blake2b512>(black_box(tau.clone()))
                    .unwrap();
                black_box(r)
            })
        });
    }
}

criterion_group!(benches, kos_ote);
criterion_main!(benches);
