use alloc::vec::Vec;
use ark_serialize::*;
use core::{borrow::Borrow, iter::once};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::ArkObjectBytes;

use ark_ec::{pairing::Pairing, CurveGroup};

use ark_std::rand::RngCore;

use super::Result;
use schnorr_pok::{error::SchnorrError, SchnorrCommitment};

use crate::{
    helpers::{rand, OwnedPairs, Pairs, WithSchnorrAndBlindings, WithSchnorrResponse},
    setup::SignatureParams,
};

/// `\sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
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
pub struct K<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] E::G2Affine);
utils::impl_deref! { K<E: Pairing>(E::G2Affine) }

impl<E: Pairing> K<E> {
    /// `\sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`
    pub(crate) fn new(
        beta_tilde_msgs: Pairs<impl Borrow<E::G2Affine>, impl Borrow<E::ScalarField>>,
        r: &E::ScalarField,
        SignatureParams { g_tilde, .. }: &SignatureParams<E>,
    ) -> Self {
        let bases_exps: OwnedPairs<_, _> = Self::bases_exps(beta_tilde_msgs, r, g_tilde).collect();

        Self(bases_exps.msm().into_affine())
    }

    /// Produces an iterator of scalars for `\sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})` used in `multi_scalar_mul`.
    fn exps(
        msgs: impl IntoIterator<Item = impl Borrow<E::ScalarField>>,
        &r: &E::ScalarField,
    ) -> impl Iterator<Item = E::ScalarField> {
        msgs.into_iter().map(|v| *v.borrow()).chain(once(r))
    }

    /// Produces an iterator of bases for `\sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})` used in `multi_scalar_mul`.
    fn bases(
        beta_tilde: impl IntoIterator<Item = impl Borrow<E::G2Affine>>,
        &g_tilde: &E::G2Affine,
    ) -> impl Iterator<Item = E::G2Affine> {
        beta_tilde
            .into_iter()
            .map(|v| *v.borrow())
            .chain(once(g_tilde))
    }

    /// Produces an iterator of bases and scalars for `\sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})` used in `multi_scalar_mul`.
    fn bases_exps<'a>(
        beta_tilde_msgs: Pairs<'a, 'a, impl Borrow<E::G2Affine>, impl Borrow<E::ScalarField>>,
        r: &E::ScalarField,
        g_tilde: &E::G2Affine,
    ) -> impl Iterator<Item = (E::G2Affine, E::ScalarField)> + 'a {
        let (beta_tilde, msgs) = beta_tilde_msgs.split();
        let bases = Self::bases(beta_tilde.iter().map(Borrow::borrow), g_tilde);
        let exps = Self::exps(msgs.iter().map(Borrow::borrow), r);

        bases.zip(exps)
    }
}

impl<E: Pairing> WithSchnorrAndBlindings<E::G2Affine, K<E>> {
    /// Schnorr response for relation `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`.
    pub fn response(
        &self,
        msgs: impl IntoIterator<Item = impl Borrow<E::ScalarField>>,
        r: &E::ScalarField,
        challenge: &E::ScalarField,
    ) -> Result<WithSchnorrResponse<E::G2Affine, K<E>>, SchnorrError> {
        let witnesses = K::<E>::exps(msgs, r).collect_vec();

        self.schnorr
            .response(&witnesses, challenge)
            .map(|response| {
                let msg_end = response.0.len() - 1;

                WithSchnorrResponse::new(response, self, 0..msg_end)
            })
    }
}

impl<E: Pairing> WithSchnorrResponse<E::G2Affine, K<E>> {
    /// Verifies that `k_{l} = \sum_{j}(beta_tilde_{j} * m_{l}{j} + g_tilde * r_{l})`.
    pub fn verify_challenge(
        &self,
        challenge: &E::ScalarField,
        committed_beta_tilde: impl IntoIterator<Item = impl Borrow<E::G2Affine>>,
        g_tilde: &E::G2Affine,
    ) -> Result<(), SchnorrError> {
        let Self {
            response,
            value,
            commitment,
            ..
        } = self;
        let bases = K::<E>::bases(committed_beta_tilde, g_tilde).collect_vec();

        response.is_valid(&bases, value, commitment, challenge)
    }
}

/// Contains randomness along with params used in `SchnorrCommitment` for `K`.
pub(crate) struct KRandomness<'a, E: Pairing> {
    r: E::ScalarField,
    beta_tilde_blinding_pairs: Pairs<'a, 'a, &'a E::G2Affine, E::ScalarField>,
    g_tilde: &'a E::G2Affine,
}

impl<'a, E: Pairing> KRandomness<'a, E> {
    /// Creates new randomness `r` and captures supplied `blinding`s paired with `beta_tilde` from the public key, `g_tilde` from signature params.
    pub fn init<R: RngCore>(
        rng: &mut R,
        beta_tilde_blinding_pairs: Pairs<'a, 'a, &'a E::G2Affine, E::ScalarField>,
        SignatureParams { g_tilde, .. }: &'a SignatureParams<E>,
    ) -> Self {
        let r = rand(rng);

        Self {
            r,
            beta_tilde_blinding_pairs,
            g_tilde,
        }
    }

    /// Commits given randomness.
    pub fn commit(&self) -> SchnorrCommitment<E::G2Affine> {
        let &Self {
            r,
            beta_tilde_blinding_pairs,
            g_tilde,
        } = self;
        let (bases, exps): (Vec<_>, _) =
            K::<E>::bases_exps(beta_tilde_blinding_pairs, &r, g_tilde).unzip();

        SchnorrCommitment::new(&bases, exps)
    }
}
