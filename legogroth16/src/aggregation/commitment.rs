use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::aggregation::{
    error::AggregationError,
    key::{PreparedVKey, WKey},
};

/// Commits to either a single vector of group G1 elements or 2 vectors, 1 of group G1 and 1 of group G2 elements.
/// Both commitment outputs a pair of $F_q^k$ element.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct PairCommitment<E: Pairing> {
    pub t: PairingOutput<E>,
    pub u: PairingOutput<E>,
}

impl<E: Pairing> PairCommitment<E> {
    /// Commits to a single vector of group G1 elements.
    pub fn single(
        vkey: impl Into<PreparedVKey<E>>,
        a_vec: &[E::G1Affine],
    ) -> Result<Self, AggregationError> {
        let vkey = vkey.into();
        vkey.ensure_sufficient_len(a_vec)?;
        let PreparedVKey { a, b } = vkey;
        let t = E::multi_pairing(a_vec, a);
        let u = E::multi_pairing(a_vec, b);
        Ok(Self { t, u })
    }

    /// Commits to 2 vector, 1 of group G1 elements and 1 of group G2 elements.
    pub fn double(
        vkey: impl Into<PreparedVKey<E>>,
        wkey: &WKey<E>,
        a: &[E::G1Affine],
        b: impl IntoIterator<Item = impl Into<E::G2Prepared>>,
    ) -> Result<Self, AggregationError> {
        let vkey = vkey.into();
        let PreparedVKey {
            a: mut v_a,
            b: mut v_b,
        } = vkey;
        let b_prep: Vec<E::G2Prepared> = b.into_iter().map(|b| b.into()).collect::<Vec<_>>();
        let b_len = b_prep.len();
        v_a.truncate(a.len());
        v_a.append(&mut b_prep.clone());
        v_b.truncate(a.len());
        v_b.append(&mut b_prep.clone());
        Ok(Self {
            t: E::multi_pairing(
                cfg_iter!(a)
                    .map(|e| E::G1Prepared::from(*e))
                    .chain(cfg_iter!(wkey.a[0..b_len]).map(|e| E::G1Prepared::from(*e)))
                    .collect::<Vec<_>>(),
                v_a,
            ),
            u: E::multi_pairing(
                cfg_iter!(a)
                    .map(|e| E::G1Prepared::from(*e))
                    .chain(cfg_iter!(wkey.b[0..b_len]).map(|e| E::G1Prepared::from(*e)))
                    .collect::<Vec<_>>(),
                v_b,
            ),
        })
    }
}
