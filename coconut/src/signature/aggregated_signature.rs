use alloc::vec::Vec;
use ark_ff::PrimeField;
use itertools::{process_results, Itertools};
use secret_sharing_and_dkg::common::ParticipantId;
use serde::{Deserialize, Serialize};

use ark_ec::pairing::Pairing;

use ark_serialize::*;
use ark_std::cfg_iter;
use utils::iter::validate;

use super::{error::AggregatedPSError, ps_signature::Signature};
use crate::helpers::{lagrange_basis_at_0, seq_pairs_satisfy, CheckLeft};
use utils::owned_pairs;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type Result<T, E = AggregatedPSError> = core::result::Result<T, E>;

/// Signature produced by combining several Pointcheval-Sanders signatures together.
/// This signature can be verified using the verification key.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AggregatedSignature<E: Pairing>(Signature<E>);
utils::impl_deref! { AggregatedSignature<E: Pairing>(Signature<E>) }

impl<E: Pairing> AggregatedSignature<E> {
    /// Creates new `AggregatedSignature` using supplied signatures which must be provided
    /// along with the corresponding unique `ParticipantId`s sorted in increasing order.
    /// This signature can be verified using the verification key.
    pub fn new<'a, SI>(participant_signatures: SI, &h: &E::G1Affine) -> Result<Self>
    where
        SI: IntoIterator<Item = (ParticipantId, &'a Signature<E>)>,
    {
        let validator = (
            |(idx, sig): &(u16, &Signature<E>)| {
                (sig.sigma_1 != h).then_some(AggregatedPSError::InvalidSigma1For(*idx))
            },
            CheckLeft(seq_pairs_satisfy(|a, b| a < b)),
        );

        let (participant_ids, s): (Vec<_>, Vec<_>) = process_results(
            validate(participant_signatures, validator).map_ok(|(id, sig)| (id, sig.sigma_2)),
            |iter| iter.unzip(),
        )?;
        if s.is_empty() {
            Err(AggregatedPSError::NoSignatures)?
        }
        if cfg_iter!(participant_ids).any(|p| *p == 0) {
            return Err(AggregatedPSError::ParticipantIdCantBeZero);
        }
        let l = lagrange_basis_at_0(participant_ids)
            .map(<E::ScalarField as PrimeField>::into_bigint)
            .collect();
        let s_mul_l = owned_pairs!(s, l).msm_bigint();

        Ok(Self(Signature::combine(h, s_mul_l)))
    }
}

#[cfg(test)]
mod aggregated_signature_tests {
    use alloc::vec::Vec;
    use ark_bls12_381::Bls12_381;
    type G1 = <Bls12_381 as Pairing>::G1;
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::{
        cfg_into_iter,
        rand::{rngs::StdRng, SeedableRng},
    };
    use blake2::Blake2b512;

    use itertools::Itertools;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use crate::{
        helpers::n_rand,
        setup::test_setup,
        signature::{aggregated_signature::AggregatedSignature, error::AggregatedPSError},
        BlindSignature, CommitmentOrMessage, MessageCommitment, Signature,
    };

    #[test]
    fn basic_workflow() {
        cfg_into_iter!(2..5).for_each(|message_count| {
            cfg_into_iter!(1..message_count).for_each(|blind_message_count| {
                cfg_into_iter!(1..8).for_each(|authority_count| {
                    // https://eprint.iacr.org/2022/011.pdf 7.1
                    let mut rng = StdRng::seed_from_u64(0u64);
                    let h = G1::rand(&mut rng).into_affine();
                    let (sk, pk, params, msgs) =
                        test_setup::<Bls12_381, Blake2b512, _>(&mut rng, message_count);

                    // https://eprint.iacr.org/2022/011.pdf 7.2
                    let (blind_msgs, reveal_msgs) = msgs.split_at(blind_message_count as usize);
                    let blind_indices = 0..blind_msgs.len();

                    let blindings: Vec<_> = n_rand(&mut rng, blind_msgs.len()).collect();
                    let o_m_pairs = utils::pairs!(blindings, blind_msgs);

                    let m_comms: Vec<_> =
                        MessageCommitment::new_iter(o_m_pairs, &h, &params).collect();
                    let comms = m_comms
                        .iter()
                        .copied()
                        .map(CommitmentOrMessage::BlindedMessage)
                        .chain(
                            reveal_msgs
                                .iter()
                                .copied()
                                .map(CommitmentOrMessage::RevealedMessage),
                        );

                    let sigs = (1..=authority_count)
                        .map(|_| {
                            let blind_signature =
                                BlindSignature::new(comms.clone(), &sk, &h).unwrap();

                            let sig = blind_signature
                                .unblind(blind_indices.clone().zip(blindings.iter()), &pk, &h)
                                .unwrap();

                            sig.verify(&msgs, &pk, &params).unwrap();

                            sig
                        })
                        .collect_vec();

                    let aggregated = AggregatedSignature::new(
                        sigs.iter()
                            .enumerate()
                            .map(|(idx, sig)| (idx as u16 + 1, sig)),
                        &h,
                    )
                    .unwrap();
                    aggregated.verify(&msgs, &pk, &params).unwrap();
                })
            })
        });
    }

    #[test]
    fn invalid_sigma_1() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let h = G1::rand(&mut rng).into_affine();
        let sigma_1 = G1::rand(&mut rng).into_affine();
        let sigma_2 = G1::rand(&mut rng).into_affine();

        assert_eq!(
            AggregatedSignature::new(
                Some(Signature::<Bls12_381>::combine(sigma_1, sigma_2))
                    .iter()
                    .enumerate()
                    .map(|(idx, v)| (idx as u16 + 1, v)),
                &h
            ),
            Err(AggregatedPSError::InvalidSigma1For(1))
        )
    }

    #[test]
    fn empty_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let h = G1::rand(&mut rng).into_affine();

        assert_eq!(
            AggregatedSignature::<Bls12_381>::new(None, &h),
            Err(AggregatedPSError::NoSignatures)
        );
    }

    #[test]
    fn zero_participant_id() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let h = G1::rand(&mut rng).into_affine();

        let sig1 = Signature::<Bls12_381>::combine(h.clone(), G1::rand(&mut rng).into_affine());
        let sig2 = Signature::<Bls12_381>::combine(h.clone(), G1::rand(&mut rng).into_affine());
        let aggr_sigs = vec![(0, &sig1), (1, &sig2)];
        assert_eq!(
            AggregatedSignature::new(aggr_sigs, &h),
            Err(AggregatedPSError::ParticipantIdCantBeZero)
        )
    }
}
