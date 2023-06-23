//! Feldman Verifiable Secret Sharing Scheme. Based on the paper [A practical scheme for non-interactive verifiable secret sharing](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};

use dock_crypto_utils::ff::powers;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    common::{CommitmentToCoefficients, Share, ShareId, Shares},
    error::SSError,
    shamir_ss,
};

/// Generate a random secret with its shares according to Feldman's verifiable secret sharing.
/// Returns the secret, shares, and commitments to coefficients of the polynomials for
/// the secret and the polynomial
pub fn deal_random_secret<'a, R: RngCore, G: AffineRepr>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
    ck: impl Into<&'a G>,
) -> Result<
    (
        G::ScalarField,
        Shares<G::ScalarField>,
        CommitmentToCoefficients<G>,
        DensePolynomial<G::ScalarField>,
    ),
    SSError,
> {
    let secret = G::ScalarField::rand(rng);
    let (shares, coeff_comms, poly) = deal_secret(rng, secret, threshold, total, ck)?;
    Ok((secret, shares, coeff_comms, poly))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<'a, R: RngCore, G: AffineRepr>(
    rng: &mut R,
    secret: G::ScalarField,
    threshold: ShareId,
    total: ShareId,
    ck: impl Into<&'a G>,
) -> Result<
    (
        Shares<G::ScalarField>,
        CommitmentToCoefficients<G>,
        DensePolynomial<G::ScalarField>,
    ),
    SSError,
> {
    let (shares, poly) = shamir_ss::deal_secret(rng, secret, threshold, total)?;
    let coeff_comms = commit_to_poly(&poly, ck.into());
    Ok((shares, coeff_comms.into(), poly))
}

pub(crate) fn commit_to_poly<G: AffineRepr>(
    poly: &DensePolynomial<G::ScalarField>,
    ck: &G,
) -> Vec<G> {
    G::Group::normalize_batch(
        &cfg_iter!(poly.coeffs)
            .map(|i| ck.mul_bigint(i.into_bigint()))
            .collect::<Vec<_>>(),
    )
}

impl<F: PrimeField> Share<F> {
    /// Executed by each participant to verify its share received from the dealer.
    pub fn verify<'a, G: AffineRepr<ScalarField = F>>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        ck: impl Into<&'a G>,
    ) -> Result<(), SSError> {
        let len = commitment_coeffs.0.len() as ShareId;
        if self.threshold > len {
            return Err(SSError::BelowThreshold(self.threshold, len));
        }
        let powers = powers(
            &G::ScalarField::from(self.id as u64),
            self.threshold as usize,
        );
        if G::Group::msm_unchecked(&commitment_coeffs.0, &powers)
            != ck.into().mul_bigint(self.share.into_bigint())
        {
            return Err(SSError::InvalidShare);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    use test_utils::test_serialization;

    #[test]
    fn feldman_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let g2 = <Bls12_381 as Pairing>::G2Affine::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, g: &G) {
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
                let (secret, shares, commitments, _) =
                    deal_random_secret::<_, G>(rng, threshold as ShareId, total as ShareId, g)
                        .unwrap();

                for share in &shares.0 {
                    // Wrong share fails to verify
                    let mut wrong_share = share.clone();
                    wrong_share.share += G::ScalarField::one();
                    assert!(wrong_share.verify(&commitments, g).is_err());

                    // Correct share verifies
                    share.verify(&commitments, g).unwrap();
                }

                assert_eq!(shares.reconstruct_secret().unwrap(), secret);

                test_serialization!(CommitmentToCoefficients<G>, commitments);
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
