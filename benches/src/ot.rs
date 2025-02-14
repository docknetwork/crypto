use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    cfg_into_iter,
    collections::{BTreeMap, BTreeSet},
    rand::prelude::StdRng,
    UniformRand,
};
use blake2::Blake2b512;
use oblivious_transfer_protocols::{
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys, ROTSenderSetup},
    configs::OTConfig,
    ot_based_multiplication::base_ot_multi_party_pairwise::{
        BaseOTOutput, Participant as BaseOTParty,
    },
    Bit, ParticipantId,
};
use sha3::Shake256;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn check_base_ot_keys(
    choices: &[Bit],
    receiver_keys: &ROTReceiverKeys,
    sender_keys: &OneOfTwoROTSenderKeys,
) {
    for i in 0..sender_keys.len() {
        if choices[i] {
            assert_eq!(sender_keys.0[i].1, receiver_keys.0[i]);
        } else {
            assert_eq!(sender_keys.0[i].0, receiver_keys.0[i]);
        }
    }
}

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
    let (base_ot_receiver_keys, r) = ROTReceiverKeys::new::<_, _, Shake256, KEY_SIZE>(
        rng,
        ot_config,
        base_ot_choices.clone(),
        s,
        b,
    )
    .unwrap();

    let base_ot_sender_keys = OneOfTwoROTSenderKeys::try_from(
        base_ot_sender_setup
            .derive_keys::<Shake256, KEY_SIZE>(r)
            .unwrap(),
    )
    .unwrap();
    (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys)
}

pub fn do_pairwise_base_ot<const KEY_SIZE: u16>(
    rng: &mut StdRng,
    num_base_ot: u16,
    num_parties: u16,
    all_party_set: BTreeSet<ParticipantId>,
) -> Vec<BaseOTOutput> {
    #[allow(non_snake_case)]
    let B = <Bls12_381 as Pairing>::G1Affine::rand(rng);
    let mut base_ots = vec![];
    let mut sender_pks = BTreeMap::new();
    let mut receiver_pks = BTreeMap::new();

    for i in 1..=num_parties {
        let mut others = all_party_set.clone();
        others.remove(&i);
        let (base_ot, sender_pk_and_proof) =
            BaseOTParty::init::<_, Blake2b512>(rng, i, others, num_base_ot, &B).unwrap();
        base_ots.push(base_ot);
        sender_pks.insert(i, sender_pk_and_proof);
    }

    for (sender_id, pks) in sender_pks {
        for (id, pk) in pks {
            let recv_pk = base_ots[id as usize - 1]
                .receive_sender_pubkey::<_, Blake2b512, Shake256, KEY_SIZE>(rng, sender_id, pk, &B)
                .unwrap();
            receiver_pks.insert((id, sender_id), recv_pk);
        }
    }

    let mut challenges = BTreeMap::new();
    let mut responses = BTreeMap::new();
    let mut hashed_keys = BTreeMap::new();

    for ((sender, receiver), pk) in receiver_pks {
        let chal = base_ots[receiver as usize - 1]
            .receive_receiver_pubkey::<Blake2b512, Shake256, KEY_SIZE>(sender, pk)
            .unwrap();
        challenges.insert((receiver, sender), chal);
    }
    // let challenges = cfg_into_iter!(receiver_pks).map(|((sender, receiver), pk)| {
    //     let chal = base_ots[receiver as usize - 1]
    //         .receive_receiver_pubkey::<KEY_SIZE>(sender, pk)
    //         .unwrap();
    //     ((receiver, sender), chal)
    // }).collect::<BTreeMap<_, _>>();

    for ((sender, receiver), chal) in challenges {
        let resp = base_ots[receiver as usize - 1]
            .receive_challenges::<Blake2b512>(sender, chal)
            .unwrap();
        responses.insert((receiver, sender), resp);
    }
    // let responses = cfg_into_iter!(challenges).map(|((sender, receiver), chal)| {
    //     let resp = base_ots[receiver as usize - 1]
    //         .receive_challenges(sender, chal)
    //         .unwrap();
    //     ((receiver, sender), resp)
    // }).collect::<BTreeMap<_, _>>();

    for ((sender, receiver), resp) in responses {
        let hk = base_ots[receiver as usize - 1]
            .receive_responses(sender, resp)
            .unwrap();
        hashed_keys.insert((receiver, sender), hk);
    }
    // let hashed_keys = cfg_into_iter!(responses).map(|((sender, receiver), resp)| {
    //     let hk = base_ots[receiver as usize - 1]
    //         .receive_responses(sender, resp)
    //         .unwrap();
    //     ((receiver, sender), hk)
    // }).collect::<BTreeMap<_, _>>();

    for ((sender, receiver), hk) in hashed_keys {
        base_ots[receiver as usize - 1]
            .receive_hashed_keys::<Blake2b512>(sender, hk)
            .unwrap()
    }
    // cfg_into_iter!(hashed_keys).for_each(|((sender, receiver), hk)| {
    //     base_ots[receiver as usize - 1]
    //         .receive_hashed_keys(sender, hk)
    //         .unwrap()
    // });

    let mut base_ot_outputs = vec![];
    for b in base_ots {
        base_ot_outputs.push(b.finish());
    }

    for base_ot in &base_ot_outputs {
        for (other, sender_keys) in &base_ot.sender_keys {
            let (choices, rec_keys) = base_ot_outputs[*other as usize - 1]
                .receiver
                .get(&base_ot.id)
                .unwrap();
            assert_eq!(rec_keys.len(), sender_keys.len());
            check_base_ot_keys(&choices, &rec_keys, &sender_keys);
        }
    }
    base_ot_outputs
}
