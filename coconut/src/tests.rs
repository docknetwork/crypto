use alloc::vec;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::UniformRand;
use ark_std::{
    cfg_into_iter,
    rand::{rngs::StdRng, SeedableRng},
};
use blake2::Blake2b512;

type G1 = <Bls12_381 as Pairing>::G1;

use schnorr_pok::compute_random_oracle_challenge;

use crate::{
    setup::test_setup, BlindSignature, CommitMessage, CommitmentOrMessage, MessagesPoKGenerator,
    SignaturePoKGenerator,
};

/// https://eprint.iacr.org/2022/011.pdf chapter 7
#[test]
fn construction_pac_workflow() {
    cfg_into_iter!(2..10).for_each(|message_count| {
        cfg_into_iter!(1..=message_count).for_each(|blind_message_count| {
            // https://eprint.iacr.org/2022/011.pdf 7.1
            let mut rng = StdRng::seed_from_u64(0u64);
            let h = G1::rand(&mut rng).into_affine();
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

            // https://eprint.iacr.org/2022/011.pdf 7.2
            let (blind_msgs, reveal_msgs) = msgs.split_at(blind_message_count as usize);
            let comms = blind_msgs
                .iter()
                .copied()
                .map(CommitMessage::BlindMessageRandomly)
                .chain(reveal_msgs.iter().map(|_| CommitMessage::RevealMessage));
            let blind_indices = 0..blind_msgs.len();
            let revealed_indices = blind_msgs.len()..blind_msgs.len() + reveal_msgs.len();

            let com_pok = MessagesPoKGenerator::init(&mut rng, comms.clone(), &params, &h).unwrap();

            let mut chal_bytes_prover = vec![];
            com_pok
                .challenge_contribution(&mut chal_bytes_prover, &params, &h)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
            let proof = com_pok.gen_proof(&challenge_prover).unwrap();
            let blindings = com_pok.blindings();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(&mut chal_bytes_verifier, &params, &h)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            assert_eq!(chal_bytes_verifier, chal_bytes_prover);
            proof
                .verify(&challenge_verifier, revealed_indices.clone(), &params, &h)
                .unwrap();

            // https://eprint.iacr.org/2022/011.pdf 7.3
            let m_comms = proof
                .commitments()
                .copied()
                .map(CommitmentOrMessage::BlindedMessage)
                .chain(
                    reveal_msgs
                        .iter()
                        .copied()
                        .map(CommitmentOrMessage::RevealedMessage),
                );
            let blind_signature = BlindSignature::new(m_comms, &sk, &h).unwrap();

            let sig = blind_signature
                .unblind(blind_indices.zip(blindings), &pk, &h)
                .unwrap();
            sig.verify(&msgs, &pk, &params).unwrap();

            // https://eprint.iacr.org/2022/011.pdf 7.4
            let sig_pok =
                SignaturePoKGenerator::init(&mut rng, comms.clone(), &sig, &pk, &params).unwrap();

            let mut chal_bytes_prover = vec![];
            sig_pok
                .challenge_contribution(&mut chal_bytes_prover, &pk, &params)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
            let proof = sig_pok.clone().gen_proof(&challenge_prover).unwrap();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(&mut chal_bytes_verifier, &pk, &params)
                .unwrap();
            assert_eq!(chal_bytes_verifier, chal_bytes_prover);
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

            proof
                .verify(
                    &challenge_verifier,
                    revealed_indices.zip(reveal_msgs.iter()),
                    &pk,
                    &params,
                )
                .unwrap();
        })
    })
}

mod helpers {
    use crate::helpers::{OwnedPairs, Pairs};
    #[test]
    fn pairs() {
        assert_eq!(Pairs::new(&[1], &[1, 2]), None);
        assert_eq!(Pairs::new(&[1, 2], &[1]), None);
        assert!(Pairs::new(&[1, 2], &[1, 2]).is_some());
        assert!(Pairs::new(&[1, 2], &[1, 2]).is_some());
    }

    #[test]
    fn owned_pairs() {
        assert_eq!(OwnedPairs::new(vec![1], vec![1, 2]), None);
        assert_eq!(OwnedPairs::new(vec![1, 2], vec![1]), None);
        assert!(OwnedPairs::new(vec![1, 2], vec![1, 2]).is_some());
        assert!(OwnedPairs::new(vec![1, 2], vec![1, 2]).is_some());

        let from_iter: OwnedPairs<_, _> = [(1, 2), (3, 4)].into_iter().collect();
        assert_eq!(from_iter.split(), (vec![1, 3], vec![2, 4]));

        let (left_ext, right_ext): (OwnedPairs<_, _>, OwnedPairs<_, _>) =
            [((1, 2), (3, 4)), ((5, 6), (7, 8))].into_iter().unzip();
        assert_eq!(left_ext.split(), (vec![1, 5], vec![2, 6]));
        assert_eq!(right_ext.split(), (vec![3, 7], vec![4, 8]));
    }
}
