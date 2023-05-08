use alloc::vec::Vec;
use itertools::Itertools;

use core::{borrow::Borrow, iter::once};

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_serialize::*;
use ark_std::rand::RngCore;
use schnorr_pok::{error::SchnorrError, SchnorrCommitment};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::ArkObjectBytes;

use crate::helpers::{rand, OwnedPairs, Pairs, WithSchnorrAndBlindings, WithSchnorrResponse};

/// `g * o + \sum_{i}(h_{i} * m_{i})`
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
pub struct MultiMessageCommitment<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] E::G1Affine);
utils::impl_deref! { MultiMessageCommitment<E: Pairing>(E::G1Affine) }

impl<E: Pairing> MultiMessageCommitment<E> {
    /// `g * o + \sum_{i}(h_{i} * m_{i})`
    pub fn new(
        h_m_pairs: Pairs<impl Borrow<E::G1Affine>, impl Borrow<E::ScalarField>>,
        g: &E::G1Affine,
        o: &E::ScalarField,
    ) -> Self {
        let bases_exps: OwnedPairs<_, _> = Self::bases_exps(g, o, h_m_pairs).collect();

        Self(bases_exps.msm().into_affine())
    }

    /// Produces an iterator of scalars for `g * o + \sum_{i}(h_{i} * m_{i})` used in `multi_scalar_mul`.
    pub fn exps(
        &o: &E::ScalarField,
        m: impl IntoIterator<Item = impl Borrow<E::ScalarField>>,
    ) -> impl Iterator<Item = E::ScalarField> {
        once(o).chain(m.into_iter().map(|v| *v.borrow()))
    }

    /// Produces an iterator of bases for `g * o + \sum_{i}(h_{i} * m_{i})` used in `multi_scalar_mul`.
    pub fn bases(
        &g: &E::G1Affine,
        h: impl IntoIterator<Item = impl Borrow<E::G1Affine>>,
    ) -> impl Iterator<Item = E::G1Affine> {
        once(g).chain(h.into_iter().map(|v| *v.borrow()))
    }

    /// Produces an iterator of bases and scalars for `g * o + \sum_{i}(h_{i} * m_{i})` used in `multi_scalar_mul`.
    pub fn bases_exps<'a>(
        g: &E::G1Affine,
        o: &E::ScalarField,
        h_m_pairs: Pairs<'a, 'a, impl Borrow<E::G1Affine>, impl Borrow<E::ScalarField>>,
    ) -> impl Iterator<Item = (E::G1Affine, E::ScalarField)> + 'a {
        let (h, m) = h_m_pairs.split();
        let bases = Self::bases(g, h.iter().map(Borrow::borrow));
        let exps = Self::exps(o, m.iter().map(Borrow::borrow));

        bases.zip(exps)
    }
}

impl<E: Pairing> WithSchnorrAndBlindings<E::G1Affine, MultiMessageCommitment<E>> {
    /// Schnorr response for relation `com = g * o + \sum_{i}(h_{i} * m_{i})`
    pub fn response(
        &self,
        o: &E::ScalarField,
        m: impl IntoIterator<Item = impl Borrow<E::ScalarField>>,
        challenge: &E::ScalarField,
    ) -> Result<WithSchnorrResponse<E::G1Affine, MultiMessageCommitment<E>>, SchnorrError> {
        let witnesses = MultiMessageCommitment::<E>::exps(o, m).collect_vec();

        self.schnorr
            .response(&witnesses, challenge)
            .map(|response| {
                let msg_end = response.0.len();

                WithSchnorrResponse::new(response, self, 1..msg_end)
            })
    }
}

impl<E> WithSchnorrResponse<E::G1Affine, MultiMessageCommitment<E>>
where
    E: Pairing,
{
    /// Verifies relation `com = g * o + \sum_{i}(h_{i} * m_{i})`.
    pub fn verify_challenge(
        &self,
        challenge: &E::ScalarField,
        g: &E::G1Affine,
        committed_h: impl IntoIterator<Item = impl Borrow<E::G1Affine>>,
    ) -> Result<(), SchnorrError> {
        let Self {
            response,
            value: com,
            commitment: t,
            ..
        } = self;
        let bases = MultiMessageCommitment::<E>::bases(g, committed_h).collect_vec();

        response.is_valid(&bases, com, t, challenge)
    }
}

/// Contains randomness along with params used in `SchnorrCommitment` for `MultiMessageCommitment`.
///
/// `g * o + \sum_{i}(h_{i} * m_{i})`
pub(crate) struct MultiMessageCommitmentRandomness<'a, E: Pairing> {
    o: E::ScalarField,
    h_blindings_pairs: Pairs<'a, 'a, &'a E::G1Affine, E::ScalarField>,
    g: &'a E::G1Affine,
}

impl<'a, E: Pairing> MultiMessageCommitmentRandomness<'a, E> {
    /// Creates randomness `o` and captures `blindings`, `g`, and `h` from signature params.
    pub fn init<R: RngCore>(
        rng: &mut R,
        h_blindings_pairs: Pairs<'a, 'a, &'a E::G1Affine, E::ScalarField>,
        g: &'a E::G1Affine,
    ) -> Self {
        let o = rand(rng);

        Self {
            o,
            h_blindings_pairs,
            g,
        }
    }

    /// Commits given randomness.
    pub fn commit(&self) -> SchnorrCommitment<E::G1Affine> {
        let Self {
            o,
            g,
            h_blindings_pairs,
        } = self;
        let (bases, exps): (Vec<_>, _) =
            MultiMessageCommitment::<E>::bases_exps(g, o, *h_blindings_pairs).unzip();

        SchnorrCommitment::new(&bases, exps)
    }
}
