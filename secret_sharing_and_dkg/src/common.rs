use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    hashing_utils::affine_group_elem_from_try_and_incr, serde_utils::ArkObjectBytes, byte_slices_to_affine,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub type ShareId = u16;

pub type ParticipantId = u16;

/// Share used in Shamir secret sharing and Feldman verifiable secret sharing
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Share<F: PrimeField> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[serde_as(as = "ArkObjectBytes")]
    pub share: F,
}

/// Collection of `Share`s. A sufficient number of `Share`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Shares<F: PrimeField>(pub Vec<Share<F>>);

/// Share used in Pedersen verifiable secret sharing
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct VerifiableShare<F: PrimeField> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[serde_as(as = "ArkObjectBytes")]
    pub secret_share: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub blinding_share: F,
}

/// Collection of `VerifiableShares`s. A sufficient number of `VerifiableShares`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VerifiableShares<F: PrimeField>(pub Vec<VerifiableShare<F>>);

/// Commitments to coefficients of the of the polynomial created during secret sharing. Each commitment
/// in the vector could be a Pedersen commitment or a computationally hiding and computationally binding
/// commitment (scalar multiplication of the coefficient with a public group element). The former is used
/// in Pedersen secret sharing and the latter in Feldman
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct CommitmentToCoefficients<G: AffineRepr>(
    #[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<G>,
);

impl<F: PrimeField> From<(ShareId, ShareId, F)> for Share<F> {
    fn from((i, t, s): (ShareId, ShareId, F)) -> Self {
        Share {
            id: i,
            threshold: t,
            share: s,
        }
    }
}

impl<F: PrimeField> Shares<F> {
    pub fn threshold(&self) -> ShareId {
        self.0[0].threshold
    }
}

impl<G: AffineRepr> From<Vec<G>> for CommitmentToCoefficients<G> {
    fn from(coeffs: Vec<G>) -> Self {
        CommitmentToCoefficients(coeffs)
    }
}

impl<G: AffineRepr> CommitmentToCoefficients<G> {
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

/// The elliptic curve base point which is multiplied by the secret key to generate the public key
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyBase<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

impl<G: AffineRepr> PublicKeyBase<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        Self(byte_slices_to_affine!(label))
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

/// Return the Lagrange basis polynomial at x = 0 for each of the given `x` coordinates. Faster than
/// doing multiple calls to `lagrange_basis_at_0`
pub fn lagrange_basis_at_0_for_all<F: PrimeField>(x_coords: Vec<ShareId>) -> Vec<F> {
    let x = cfg_into_iter!(x_coords.as_slice())
        .map(|x| F::from(*x as u64))
        .collect::<Vec<_>>();

    // Product of all `x`, i.e. \prod_{i}(x_i}
    let product = cfg_iter!(x).product::<F>();

    cfg_into_iter!(x.clone())
        .map(move |i| {
            let mut denominator = cfg_iter!(x)
                .filter(|&j| &i != j)
                .map(|&j| j - i)
                .product::<F>();
            denominator.inverse_in_place().unwrap();

            // The numerator is of the form `x_1*x_2*...x_{i-1}*x_{i+1}*x_{i+2}*..` which is a product of all
            // `x` except `x_i` and thus can be calculated as \prod_{i}(x_i} * (1 / x_i)
            let numerator = product * i.inverse().unwrap();

            denominator * numerator
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn compare_lagrange_basis_at_0() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let count = 20;
        let x = (0..count)
            .map(|_| ShareId::rand(&mut rng))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let single = cfg_iter!(x)
            .map(|i| lagrange_basis_at_0(&x, *i))
            .collect::<Vec<Fr>>();
        println!("For {} x, single took {:?}", count, start.elapsed());

        let start = Instant::now();
        let multiple = lagrange_basis_at_0_for_all(x);
        println!("For {} x, multiple took {:?}", count, start.elapsed());

        assert_eq!(single, multiple);
    }
}
