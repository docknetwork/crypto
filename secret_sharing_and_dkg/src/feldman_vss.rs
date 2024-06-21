//! Feldman Verifiable Secret Sharing Scheme. Based on the paper [A practical scheme for non-interactive verifiable secret sharing](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
//! The scheme works as follows for threshold `t` and total `n`:
//! 1. Dealer samples a random `t-1` degree polynomial `f = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}` such that `f(0) = a_0 = s` where `s` is the secret.
//! 2. Dealer commits to coefficients of `f` as `C = [c_0, c_1, ..., c_{t-1}] = [g*a_0, g*a_1, ..., g*a_{t-1}]` and broadcasts `C`
//! 3. Dealer creates the `n` shares as `[f(1), f(2), ..., f(n)]` and gives `f(i)` to party `P_i`.
//! 4. Each party `P_i` verifiers its share as `g*f(i) == c_0 + c_1*i + c_2*i^2 + ... + c_{t-1} * i^{t-1}`

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_std::{rand::RngCore, vec::Vec, UniformRand};

use dock_crypto_utils::ff::powers;

use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

use crate::{
    common::{CommitmentToCoefficients, Share, ShareId, Shares},
    error::SSError,
    shamir_ss,
};

/// Generate a random secret with its shares according to Feldman's verifiable secret sharing.
/// At least `threshold` number of shares are needed to reconstruct the secret.
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
    G::Group::normalize_batch(&multiply_field_elems_with_same_group_elem(
        ck.into_group(),
        &poly.coeffs,
    ))
}

impl<F: PrimeField> Share<F> {
    /// Executed by each participant to verify its share received from the dealer.
    /// Also, should be called by the "reconstructor" to verify that each of the share being used in
    /// reconstruction is a valid share.
    pub fn verify<'a, G: AffineRepr<ScalarField = F>>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        ck: impl Into<&'a G>,
    ) -> Result<(), SSError> {
        let len = commitment_coeffs.0.len() as ShareId;
        if self.threshold > len {
            return Err(SSError::BelowThreshold(self.threshold, len));
        }
        let powers = powers(&G::ScalarField::from(self.id as u64), self.threshold as u32);
        let l = G::Group::msm_unchecked(&commitment_coeffs.0, &powers);
        let r = *ck.into() * self.share;
        if l != r {
            return Err(SSError::InvalidShare);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ff::One;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::time::Instant;

    use test_utils::test_serialization;

    #[test]
    fn feldman_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Affine::rand(&mut rng);
        let g2 = G2Affine::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, g: &G) {
            let mut checked_serialization = false;
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
                println!("For {}-of-{} sharing", threshold, total);
                let start = Instant::now();
                let (secret, shares, commitments, _) =
                    deal_random_secret::<_, G>(rng, threshold as ShareId, total as ShareId, g)
                        .unwrap();
                println!(
                    "Time to create shares and commitments {:?}",
                    start.elapsed()
                );
                println!(
                    "Commitment size is {} bytes",
                    commitments.serialized_size(Compress::Yes)
                );

                let mut noted_time = false;

                for share in &shares.0 {
                    // Wrong share fails to verify
                    let mut wrong_share = share.clone();
                    wrong_share.share += G::ScalarField::one();
                    assert!(wrong_share.verify(&commitments, g).is_err());

                    // Correct share verifies
                    let start = Instant::now();
                    share.verify(&commitments, g).unwrap();
                    if !noted_time {
                        println!("Time to verify share is {:?}", start.elapsed());
                        noted_time = true;
                    }
                }

                // Its assumed that reconstructor verifies each share before calling `reconstruct_secret`
                assert_eq!(shares.reconstruct_secret().unwrap(), secret);

                if !checked_serialization {
                    test_serialization!(CommitmentToCoefficients<G>, commitments);
                    checked_serialization = true;
                }
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
