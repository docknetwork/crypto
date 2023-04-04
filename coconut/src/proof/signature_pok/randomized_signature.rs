//! Randomized Pointcheval-Sanders signature used in `SignaturePoK` verification.
//! This signature can be verified without revealing the actual signed data.

use alloc::vec::Vec;
use ark_ec::{pairing::Pairing, AffineRepr, Group};
use ark_ff::PrimeField;
use ark_serialize::*;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use utils::join;

use crate::{
    helpers::{pair_valid_items_with_slice, seq_pairs_satisfy, CheckLeft, OwnedPairs},
    setup::{PreparedSignatureParams, PublicKey, SignatureParams},
    signature_pok::K,
    PSError, Signature,
};

type Result<T, E = PSError> = core::result::Result<T, E>;

/// Randomized Pointcheval-Sanders signature used in `SignaturePoK` verification.
/// This signature can be verified without revealing the actual signed data.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct RandomizedSignature<E: Pairing>(Signature<E>);

impl<E: Pairing> RandomizedSignature<E> {
    /// Randomizes provided signature using supplied scalars.
    pub fn new(signature: &Signature<E>, r: &E::ScalarField, r_bar: &E::ScalarField) -> Self {
        let (h, s) = signature.split();
        let (r, r_bar) = join!(r.into_bigint(), r_bar.into_bigint());

        // h` = h * r`
        let h_bar = h.mul_bigint(r_bar);
        // s` = s * r` + h` * r
        let s_bar = s.mul_bigint(r_bar) + h_bar.mul_bigint(r);

        Self(Signature::combine(h_bar, s_bar))
    }

    /// Verifies randomized signature.
    /// Supplied messages should be indexed same way they were used in the `SignaturePoK`.
    /// `indexed_revealed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
    /// an error will be returned.
    pub fn verify<'a, I>(
        &self,
        indexed_revealed_messages_sorted_by_index: I,
        k: &K<E>,
        pk: &PublicKey<E>,
        params: &SignatureParams<E>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = (usize, &'a E::ScalarField)>,
    {
        Self::prepare_pairing_values(indexed_revealed_messages_sorted_by_index, k, pk, params)
            .and_then(|(p1, p2)| self.0.verify_pairing(p1, p2))
    }

    /// Calculates values used in pairing check.
    pub(crate) fn prepare_pairing_values<'a, I>(
        indexed_revealed_messages_sorted_by_index: I,
        &k: &K<E>,
        PublicKey {
            alpha_tilde,
            beta_tilde,
            ..
        }: &PublicKey<E>,
        PreparedSignatureParams { g_tilde, .. }: &PreparedSignatureParams<E>,
    ) -> Result<(E::G2Prepared, E::G2Prepared)>
    where
        I: IntoIterator<Item = (usize, &'a E::ScalarField)>,
    {
        let uncommitted_beta_tilde_m_pairs: OwnedPairs<_, _> = pair_valid_items_with_slice(
            indexed_revealed_messages_sorted_by_index,
            CheckLeft(seq_pairs_satisfy(|a, b| a < b)),
            beta_tilde,
        )
        .map_ok(|(&beta_tilde, &msg)| (beta_tilde, msg))
        .collect::<Result<_>>()?;

        let prepared = join!(
            E::G2Prepared::from(uncommitted_beta_tilde_m_pairs.msm() + *k + alpha_tilde),
            g_tilde.into()
        );

        Ok(prepared)
    }

    pub(crate) fn split(&self) -> (E::G1Affine, E::G1Affine) {
        self.0.split()
    }
}

#[cfg(test)]
mod tests {
    use core::iter::empty;

    use crate::{
        helpers::{rand, Pairs},
        setup::test_setup,
        signature_pok::k::K,
    };

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type G1 = <Bls12_381 as Pairing>::G1;

    #[test]
    fn test_randomized_signature_all_blinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();
            let r = rand(&mut rng);
            let r_bar = rand(&mut rng);
            let rand_sig = RandomizedSignature::new(&sig, &r, &r_bar);
            let k = K::new(Pairs::new(&pk.beta_tilde, &msgs).unwrap(), &r, &params);

            rand_sig.verify(empty(), &k, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_randomized_signature_all_known_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();
            let r = rand(&mut rng);
            let r_bar = rand(&mut rng);
            let rand_sig = RandomizedSignature::new(&sig, &r, &r_bar);
            let k = K::new(
                Pairs::new(&pk.beta_tilde[0..0], &msgs[0..0]).unwrap(),
                &r,
                &params,
            );

            rand_sig
                .verify(msgs.iter().enumerate(), &k, &pk, &params)
                .unwrap();
        }
    }

    #[test]
    fn test_randomized_signature_some_blinded_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();
            let r = rand(&mut rng);
            let r_bar = rand(&mut rng);
            let rand_sig = RandomizedSignature::new(&sig, &r, &r_bar);
            let k = K::new(
                Pairs::new(&pk.beta_tilde[0..1], &msgs[0..1]).unwrap(),
                &r,
                &params,
            );

            rand_sig
                .verify(msgs.iter().enumerate().skip(1), &k, &pk, &params)
                .unwrap();
        }
    }

    #[test]
    fn test_invalid_randomized_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();
            let r = rand(&mut rng);
            let r_bar = rand(&mut rng);
            let mut rand_sig = RandomizedSignature::new(&sig, &r, &r_bar);
            let k = K::new(Pairs::new(&pk.beta_tilde, &msgs).unwrap(), &r, &params);

            rand_sig.0.sigma_1 = G1::rand(&mut rng).into_affine();

            assert!(rand_sig.verify(empty(), &k, &pk, &params).is_err());
        }
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        for i in 1..10 {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, i);

            let sig = Signature::new_deterministic::<Blake2b512>(msgs.as_slice(), &sk).unwrap();
            let r = rand(&mut rng);
            let r_bar = rand(&mut rng);
            let rand_sig = RandomizedSignature::new(&sig, &r, &r_bar);

            let k = K::new(Pairs::new(&pk.beta_tilde, &msgs).unwrap(), &r, &params);

            rand_sig.verify(empty(), &k, &pk, &params).unwrap();
        }
    }
}
