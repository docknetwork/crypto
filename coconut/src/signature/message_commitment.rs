use alloc::vec::Vec;
use core::borrow::Borrow;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use ark_ec::{pairing::Pairing, CurveGroup};

use ark_serialize::*;
use ark_std::{cfg_into_iter, rand::RngCore};
use utils::{aliases::SyncIfParallel, serde_utils::ArkObjectBytes};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use schnorr_pok::{error::SchnorrError, SchnorrCommitment};

use utils::{impl_indexed_iter, impl_into_indexed_iter};

use crate::{
    helpers::{n_rand, WithSchnorrAndBlindings, WithSchnorrResponse},
    setup::SignatureParams,
};
use utils::pairs;

/// `g * o + h * m`
#[serde_as]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct MessageCommitment<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] E::G1Affine);
utils::impl_deref! { MessageCommitment<E: Pairing>(E::G1Affine) }

impl<E: Pairing> MessageCommitment<E> {
    /// `g * o + h * m`.
    pub fn new(
        &g: &E::G1Affine,
        &o: &E::ScalarField,
        &h: &E::G1Affine,
        &m: &E::ScalarField,
    ) -> Self {
        Self(pairs!([g, h], [o, m]).msm().into_affine())
    }

    /// Produces an iterator of `g * o_{j} + h * m_{j}`.
    pub fn new_iter<'iter>(
        o_m_pairs: impl_into_indexed_iter!(<Item = (impl Borrow<E::ScalarField> + SyncIfParallel + 'iter, impl Borrow<E::ScalarField> + SyncIfParallel + 'iter)> + 'iter),
        h: &E::G1Affine,
        SignatureParams { g, .. }: &SignatureParams<E>,
    ) -> impl_indexed_iter!(<Item = Self> + 'iter) {
        Self::bases_exps(o_m_pairs, h, g).map(|([g, h], [o, m])| Self::new(&g, &o, &h, &m))
    }

    /// Produces parallel iterator of scalar groups `o_{j}` and `m_{j}`.
    fn exps<'iter>(
        o_m_pairs: impl_into_indexed_iter!(<Item = (impl Borrow<E::ScalarField> + SyncIfParallel + 'iter, impl Borrow<E::ScalarField> + SyncIfParallel + 'iter)> + 'iter),
    ) -> impl_indexed_iter!(<Item = [E::ScalarField; 2]> + 'iter) {
        cfg_into_iter!(o_m_pairs).map(|(o, m)| [*o.borrow(), *m.borrow()])
    }

    /// Produces parallel iterator of bases and scalars groups `g * o_{j} + h * m_{j}` each used in `multi_scalar_mul`.
    fn bases_exps<'iter>(
        o_m_pairs: impl_into_indexed_iter!(<Item = (impl Borrow<E::ScalarField> + SyncIfParallel + 'iter, impl Borrow<E::ScalarField> + SyncIfParallel + 'iter)> + 'iter),
        &h: &E::G1Affine,
        &g: &E::G1Affine,
    ) -> impl_indexed_iter!(<Item = ([E::G1Affine; 2], [E::ScalarField; 2])> + 'iter) {
        Self::exps(o_m_pairs).map(move |o_j_m_j| ([g, h], o_j_m_j))
    }
}

impl<E: Pairing> WithSchnorrAndBlindings<E::G1Affine, MessageCommitment<E>> {
    /// Schnorr response for relation `com_{j} = g * o_{j} + h * m_{j}`
    pub fn response(
        &self,
        &o: &E::ScalarField,
        &m: &E::ScalarField,
        challenge: &E::ScalarField,
    ) -> Result<WithSchnorrResponse<E::G1Affine, MessageCommitment<E>>, SchnorrError> {
        self.schnorr
            .response(&[o, m], challenge)
            .map(|resp| WithSchnorrResponse::new(resp, self, 1..2))
    }
}

impl<E: Pairing> WithSchnorrResponse<E::G1Affine, MessageCommitment<E>> {
    /// Verifies relation `com_{j} = g * o_{j} + h * m_{j}`
    pub fn verify_challenge(
        &self,
        challenge: &E::ScalarField,
        &g: &E::G1Affine,
        &h: &E::G1Affine,
    ) -> Result<(), SchnorrError> {
        let Self {
            response,
            value: com_j,
            commitment,
            ..
        } = self;
        let bases = [g, h];

        response.is_valid(&bases, com_j, commitment, challenge)
    }
}

/// Contains randomness along with params used in `SchnorrCommitment` for `MessageCommitment`.
///
/// `\sum_{i}(g * o_{i} + h * m_{i})`
pub(crate) struct MessageCommitmentRandomness<'a, E: Pairing> {
    o: Vec<E::ScalarField>,
    blindings: &'a [E::ScalarField],
    h: &'a E::G1Affine,
    g: &'a E::G1Affine,
}

impl<'a, E: Pairing> MessageCommitmentRandomness<'a, E> {
    /// Generates new randomness `o` and captures `blindings` along with `h`, and `g` from signature params.
    pub fn init<R: RngCore>(
        rng: &mut R,
        blindings: &'a [E::ScalarField],
        h: &'a E::G1Affine,
        SignatureParams { g, .. }: &'a SignatureParams<E>,
    ) -> Self {
        let o = n_rand(rng, blindings.len()).collect();

        Self { o, blindings, h, g }
    }

    /// Produces an iterator of `SchnorrCommitment`s for `MessageCommitment`s.
    pub fn commit(&self) -> impl_indexed_iter!(<Item = SchnorrCommitment<E::G1Affine>> + '_) {
        let &Self {
            ref o,
            blindings,
            g,
            h,
        } = self;
        let o_blindings_pairs = pairs!(o, blindings);

        MessageCommitment::<E>::bases_exps(o_blindings_pairs, h, g)
            .map(|(bases, exps)| SchnorrCommitment::new(&bases, exps.to_vec()))
    }
}
