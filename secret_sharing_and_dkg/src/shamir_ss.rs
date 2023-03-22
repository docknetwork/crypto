//! Shamir secret sharing

use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::rand::RngCore;
use ark_std::{cfg_into_iter, cfg_iter, vec::Vec};

use crate::common;
use crate::common::{ShareId, Shares};
use crate::error::SSError;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Generate a random secret with its shares according to Shamir secret sharing.
/// Returns the secret, shares and the polynomial whose evaluations are the secret and the shares
pub fn deal_random_secret<R: RngCore, F: PrimeField>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
) -> Result<(F, Shares<F>, DensePolynomial<F>), SSError> {
    let secret = F::rand(rng);
    let (shares, poly) = deal_secret(rng, secret, threshold, total)?;
    Ok((secret, shares, poly))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<R: RngCore, F: PrimeField>(
    rng: &mut R,
    secret: F,
    threshold: ShareId,
    total: ShareId,
) -> Result<(Shares<F>, DensePolynomial<F>), SSError> {
    if threshold > total {
        return Err(SSError::InvalidThresholdOrTotal(threshold, total));
    }
    if threshold < 1 {
        return Err(SSError::InvalidThresholdOrTotal(threshold, total));
    }
    let mut coeffs = Vec::with_capacity(threshold as usize);
    coeffs.append(&mut (0..threshold - 1).map(|_| F::rand(rng)).collect());
    coeffs.insert(0, secret);
    let poly = DensePolynomial::from_coefficients_vec(coeffs);
    let shares = cfg_into_iter!((1..=total))
        .map(|i| (i as ShareId, threshold, poly.evaluate(&F::from(i as u64))).into())
        .collect::<Vec<_>>();
    Ok((Shares(shares), poly))
}

impl<F: PrimeField> Shares<F> {
    /// Reconstruct the secret. Assumes that shares are unique and have the same threshold
    pub fn reconstruct_secret(&self) -> Result<F, SSError> {
        let threshold = self.threshold();
        let len = self.0.len() as ShareId;
        if threshold > len {
            return Err(SSError::BelowThreshold(threshold, len));
        }
        let shares = &self.0[0..threshold as usize];
        let share_ids = shares.iter().map(|s| s.id).collect::<Vec<_>>();
        Ok(cfg_iter!(shares)
            .map(|s| common::lagrange_basis_at_0::<F>(&share_ids, s.id) * s.share)
            .sum::<F>())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn shamir_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);

        assert!(deal_random_secret::<_, Fr>(&mut rng, 5, 4).is_err());

        for (threshold, total) in vec![
            (2, 2),
            (2, 3),
            (2, 4),
            (2, 5),
            (3, 3),
            (3, 4),
            (3, 5),
            (4, 5),
            (4, 8),
            (4, 9),
            (4, 12),
            (5, 5),
            (5, 7),
            (5, 10),
            (5, 13),
            (7, 10),
            (7, 15),
        ] {
            let (secret, shares, poly) =
                deal_random_secret::<_, Fr>(&mut rng, threshold as ShareId, total as ShareId)
                    .unwrap();

            assert_eq!(shares.0.len(), total);
            assert_eq!(poly.degree(), threshold - 1);
            assert_eq!(secret, poly.evaluate(&Fr::from(0 as u64)));
            for i in 1..=total {
                assert_eq!(shares.0[i - 1].id, i as ShareId);
                assert_eq!(shares.0[i - 1].share, poly.evaluate(&Fr::from(i as u64)));
            }

            assert_eq!(shares.reconstruct_secret().unwrap(), secret);
        }
    }
}
