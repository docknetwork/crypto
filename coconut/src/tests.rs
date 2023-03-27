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
            let (blind_msgs, reveal_msgs) = msgs.split_at(blind_message_count);
            let comms = blind_msgs
                .iter()
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
                .map(CommitmentOrMessage::BlindedMessage)
                .chain(reveal_msgs.iter().map(CommitmentOrMessage::RevealedMessage));
            let blind_signature = BlindSignature::new(m_comms, &sk, &h).unwrap();

            let sig = blind_signature
                .unblind(blind_indices.zip(blindings), &pk)
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
    use crate::helpers::{
        is_lt, pluck_missed, take_while_pairs_satisfy, ExtendSome, OwnedPairs, Pairs,
    };
    use alloc::{vec, vec::Vec};

    #[test]
    fn valid_take_while_unique_sorted() {
        let mut opt = None;
        let values: Vec<_> = take_while_pairs_satisfy(1..10, is_lt, &mut opt).collect();

        assert_eq!(values, (1..10).collect::<Vec<_>>());
        assert_eq!(opt, None);

        let values: Vec<_> = take_while_pairs_satisfy([2, 8, 9], is_lt, &mut opt).collect();
        assert_eq!(values, [2, 8, 9]);
        assert_eq!(opt, None);
    }

    #[test]
    fn invalid_take_while_unique_sorted() {
        let mut opt = None;
        let values: Vec<_> =
            take_while_pairs_satisfy([5, 6, 7, 9, 10, 8], is_lt, &mut opt).collect();

        assert_eq!(values, vec![5, 6, 7, 9, 10]);
        assert_eq!(opt, Some((10, 8)));

        let values: Vec<_> = take_while_pairs_satisfy([100, 0], is_lt, &mut opt).collect();
        assert_eq!(values, [100]);
        assert_eq!(opt, Some((100, 0)));
    }

    #[test]
    fn check_pluck_missed() {
        assert_eq!(
            pluck_missed([1, 3], [0, 1, 2]).collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(
            pluck_missed([3, 5], 0..10).collect::<Vec<_>>(),
            [0, 1, 2, 4, 6, 7, 8, 9]
        );
    }

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

    #[test]
    fn extend_some() {
        let ExtendSome::<Vec<_>>(arr) = [Some(1), Some(2), None, Some(4)].into_iter().collect();

        assert_eq!(arr, [1, 2, 4]);

        let (ExtendSome::<Vec<_>>(even), ExtendSome::<Vec<_>>(odd)) =
            [Some(1), Some(2), None, Some(4), Some(5), None]
                .into_iter()
                .partition(|v| v.map_or(false, |idx| idx % 2 == 0));

        assert_eq!(even, vec![2, 4]);
        assert_eq!(odd, vec![1, 5])
    }
}
