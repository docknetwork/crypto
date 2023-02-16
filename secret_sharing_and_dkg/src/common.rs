use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::vec::Vec;

use zeroize::Zeroize;

pub type ShareId = u16;

pub type ParticipantId = u16;

/// Share used in Shamir secret sharing and Feldman verifiable secret sharing
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Share<F: PrimeField> {
    pub id: ShareId,
    pub threshold: ShareId,
    pub share: F,
}

/// Collection of `Share`s. A sufficient number of `Share`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct Shares<F: PrimeField>(pub Vec<Share<F>>);

/// Share used in Pedersen verifiable secret sharing
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableShare<F: PrimeField> {
    pub id: ShareId,
    pub threshold: ShareId,
    pub secret_share: F,
    pub blinding_share: F,
}

/// Collection of `VerifiableShares`s. A sufficient number of `VerifiableShares`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableShares<F: PrimeField>(pub Vec<VerifiableShare<F>>);

/// Commitments to coefficients of the of the polynomial created during secret sharing. Each commitment
/// in the vector could be a Pedersen commitment or a computationally hiding and computationally binding
/// commitment (scalar multiplication of the coefficient with a public group element). The former is used
/// in Pedersen secret sharing and the latter in Feldman
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentToCoefficients<G: AffineCurve>(pub Vec<G>);

impl<F: PrimeField> Drop for Share<F> {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl<F: PrimeField> From<(ShareId, ShareId, F)> for Share<F> {
    fn from((i, t, s): (ShareId, ShareId, F)) -> Self {
        Share {
            id: i,
            threshold: t,
            share: s,
        }
    }
}

impl<F: PrimeField> Drop for VerifiableShare<F> {
    fn drop(&mut self) {
        self.secret_share.zeroize();
        self.blinding_share.zeroize();
    }
}

impl<F: PrimeField> Shares<F> {
    pub fn threshold(&self) -> ShareId {
        self.0[0].threshold
    }
}

impl<G: AffineCurve> From<Vec<G>> for CommitmentToCoefficients<G> {
    fn from(coeffs: Vec<G>) -> Self {
        CommitmentToCoefficients(coeffs)
    }
}

impl<G: AffineCurve> CommitmentToCoefficients<G> {
    /// The constant coefficient is the secret and thus returns the commitment to that.
    pub fn commitment_to_secret(&self) -> &G {
        &self.0[0]
    }

    /// The degree of the polynomial whose coefficients were committed
    pub fn poly_degree(&self) -> usize {
        self.0.len() - 1
    }

    pub fn supports_threshold(&self, threshold: ShareId) -> bool {
        threshold as usize - 1 == self.poly_degree()
    }
}

/// Return the Lagrange basis polynomial at x = 0 given the `x` coordinates
/// `(x_coords[0]) * (x_coords[1]) * ... / ((x_coords[0] - i) * (x_coords[1] - i) * ...)`
/// Assumes all `x` coordinates are distinct and appropriate number of coordinates are provided
pub fn lagrange_basis_at_0<F: PrimeField>(x_coords: &[ShareId], i: ShareId) -> F {
    let mut numerator = F::one();
    let mut denominator = F::one();
    let i_f = F::from(i as u64);
    for x in x_coords {
        if *x == i {
            continue;
        }
        let x = F::from(*x as u64);
        numerator *= x;
        denominator *= x - i_f;
    }
    denominator.inverse_in_place().unwrap();
    numerator * denominator
}
