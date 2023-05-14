use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{rand::prelude::StdRng, UniformRand};
use oblivious_transfer_protocols::{
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys, ROTSenderSetup},
    configs::OTConfig,
};

pub fn do_1_of_2_base_ot<const KEY_SIZE: u16>(
    rng: &mut StdRng,
    base_ot_count: u16,
    b: &<Bls12_381 as Pairing>::G1Affine,
) -> (Vec<u16>, OneOfTwoROTSenderKeys, ROTReceiverKeys) {
    let ot_config = OTConfig::new_2_message(base_ot_count).unwrap();

    let (base_ot_sender_setup, s) = ROTSenderSetup::new(rng, ot_config, b);

    let base_ot_choices = (0..base_ot_count)
        .map(|_| u16::rand(rng) % 2)
        .collect::<Vec<_>>();
    let (base_ot_receiver_keys, r) =
        ROTReceiverKeys::new::<_, _, KEY_SIZE>(rng, ot_config, base_ot_choices.clone(), s, b)
            .unwrap();

    let base_ot_sender_keys =
        OneOfTwoROTSenderKeys::try_from(base_ot_sender_setup.derive_keys::<KEY_SIZE>(r).unwrap())
            .unwrap();
    (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys)
}
