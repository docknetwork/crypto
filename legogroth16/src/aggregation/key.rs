use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::error::AggregationError;

/// This module implements two binding commitment schemes used in the Groth16
/// aggregation.
/// The first one is a commitment scheme that commits to a single vector $a$ of
/// length n in the second base group $G_1$ (for example):
/// * it requires a structured SRS $v_1$ of the form $(h,h^u,h^{u^2}, ...
/// ,g^{h^{n-1}})$ with $h \in G_2$ being a random generator of $G_2$ and $u$ a
/// random scalar (coming from a power of tau ceremony for example)
/// * it requires a second structured SRS $v_2$ of the form $(h,h^v,h^{v^2},
/// ...$ with $v$ being a random scalar different than u (coming from another
/// power of tau ceremony for example)
/// The Commitment is a tuple $(\prod_{i=0}^{n-1} e(a_i,v_{1,i}),
/// \prod_{i=0}^{n-1} e(a_i,v_{2,i}))$
///
/// The second one takes two vectors $a \in G_1^n$ and $b \in G_2^n$ and commits
/// to them using a similar approach as above. It requires an additional SRS
/// though:
/// * $v_1$ and $v_2$ stay the same
/// * An additional tuple $w_1 = (g^{u^n},g^{u^{n+1}},...g^{u^{2n-1}})$ and $w_2 =
/// (g^{v^n},g^{v^{n+1},...,g^{v^{2n-1}})$ where $g$ is a random generator of
/// $G_1$
/// The commitment scheme returns a tuple:
/// * $\prod_{i=0}^{n-1} e(a_i,v_{1,i})e(w_{1,i},b_i)$
/// * $\prod_{i=0}^{n-1} e(a_i,v_{2,i})e(w_{2,i},b_i)$
///
/// The second commitment scheme enables to save some KZG verification in the
/// verifier of the Groth16 verification protocol since we pack two vectors in
/// one commitment.
/// Key is a generic commitment key that is instantiated with g and h as basis,
/// and a and b as powers.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Key<G: AffineRepr> {
    /// Exponent is a
    pub a: Vec<G>,
    /// Exponent is b
    pub b: Vec<G>,
}

/// Commitment key used by the "single" commitment on G1 values as
/// well as in the "pair" commitment.
/// It contains $\{h^a^i\}_{i=1}^n$ and $\{h^b^i\}_{i=1}^n$
pub type VKey<E> = Key<<E as Pairing>::G2Affine>;

/// Commitment key used by the "pair" commitment. Note the sequence of
/// powers starts at $n$ already.
/// It contains $\{g^{a^{n+i}}\}_{i=1}^n$ and $\{g^{b^{n+i}}\}_{i=1}^n$
pub type WKey<E> = Key<<E as Pairing>::G1Affine>;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVKey<E: Pairing> {
    /// Exponent is a
    pub a: Vec<<E as Pairing>::G2Prepared>,
    /// Exponent is b
    pub b: Vec<<E as Pairing>::G2Prepared>,
}

impl<E: Pairing> From<&VKey<E>> for PreparedVKey<E> {
    fn from(other: &VKey<E>) -> Self {
        let a = cfg_iter!(other.a)
            .map(|e| E::G2Prepared::from(*e))
            .collect::<Vec<_>>();
        let b = cfg_iter!(other.b)
            .map(|e| E::G2Prepared::from(*e))
            .collect::<Vec<_>>();
        Self { a, b }
    }
}

impl<E: Pairing> PreparedVKey<E> {
    pub fn len(&self) -> usize {
        self.a.len()
    }

    pub fn ensure_sufficient_len<K>(&self, m: &[K]) -> Result<(), AggregationError> {
        if self.a.len() < m.len() {
            return Err(AggregationError::InsufficientKeyLength(self.len()));
        }
        return Ok(());
    }
}

impl<G> Key<G>
where
    G: AffineRepr,
{
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.a.len() == n && self.b.len() == n
    }

    pub fn ensure_sufficient_len<K>(&self, m: &[K]) -> Result<(), AggregationError> {
        if self.a.len() < m.len() {
            return Err(AggregationError::InsufficientKeyLength(self.len()));
        }
        return Ok(());
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }

    /// Returns both vectors of key scaled by the given vector entrywise.
    /// In other words, it returns $\{v_i^{s_i}\}$
    pub fn scale(&self, s_vec: &[G::ScalarField]) -> Result<Self, AggregationError> {
        if self.a.len() != s_vec.len() {
            return Err(AggregationError::InvalidKeyLength);
        }
        let (a, b): (Vec<G::Group>, Vec<G::Group>) = cfg_iter!(self.a)
            .zip(cfg_iter!(self.b))
            .zip(cfg_iter!(s_vec))
            .map(|((ap, bp), si)| {
                let s_repr = si.into_bigint();
                let v1s = ap.mul_bigint(s_repr);
                let v2s = bp.mul_bigint(s_repr);
                (v1s, v2s)
            })
            .unzip();

        Ok(Self {
            a: G::Group::normalize_batch(&a),
            b: G::Group::normalize_batch(&b),
        })
    }

    /// Returns the left and right commitment key part. It makes copy.
    pub fn split(mut self, at: usize) -> (Self, Self) {
        let a_right = self.a.split_off(at);
        let b_right = self.b.split_off(at);
        (
            Self {
                a: self.a,
                b: self.b,
            },
            Self {
                a: a_right,
                b: b_right,
            },
        )
    }

    /// Takes a left and right commitment key and returns a commitment
    /// key $left \circ right^{scale} = (left_i*right_i^{scale} ...)$. This is
    /// required step during GIPA recursion.
    pub fn compress(&self, right: &Self, scale: &G::ScalarField) -> Result<Self, AggregationError> {
        let left = self;
        if left.a.len() != right.a.len() {
            return Err(AggregationError::InvalidKeyLength);
        }
        let (a, b): (Vec<G::Group>, Vec<G::Group>) = cfg_iter!(left.a)
            .zip(cfg_iter!(left.b))
            .zip(cfg_iter!(right.a))
            .zip(cfg_iter!(right.b))
            .map(|(((left_a, left_b), right_a), right_b)| {
                let s_repr = scale.into_bigint();
                let mut ra = right_a.mul_bigint(s_repr);
                let mut rb = right_b.mul_bigint(s_repr);
                ra += left_a;
                rb += left_b;
                (ra, rb)
            })
            .unzip();

        Ok(Self {
            a: G::Group::normalize_batch(&a),
            b: G::Group::normalize_batch(&b),
        })
    }

    /// Returns the first values in the vector of v1 and v2 (respectively
    /// w1 and w2). When commitment key is of size one, it's a proxy to get the
    /// final values.
    pub fn first(&self) -> (G, G) {
        (self.a[0], self.b[0])
    }
}
