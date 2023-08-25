//! Pedersen Verifiable secret sharing. Based on the paper "Non-interactive and information-theoretic secure verifiable secret sharing", section 4. <https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF>.
//! The basic idea is the following
//! - Dealer wants to share a secret `s` in `k-of-n` manner with `n` participants
//! - Dealer commits to secret `s` with randomness t so `C_0 = C(s, t) = g*s + h*t`
//! - Create polynomial `F(x) = s + F_1.x + F_2.x^2 + ... F_{k-1}.x^{k-1}` such that `F(0) = s`.
//! - Create polynomial `G(x) = t + G_1.x + G_2.x^2 + ... G_{k-1}.x^{k-1}` such that `G(0) = t`.
//! - Commits to coefficients as `C_1 = C(F_1, G_1), C_2 = C(F_2, G_2),..., `C_k = C(F_k, G_k)`, broadcast to all `n` participants
//! - Dealer sends `(F(i), G(i))` to participant `i`
//! - Each participant verifies `C(F(i), G(i)) = C_0 * C_1*i * C_2*{i^2} * ... C_{k-1}*{k-1}`

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, ops::Add, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    concat_slices, ff::powers, hashing_utils::projective_group_elem_from_try_and_incr,
    serde_utils::ArkObjectBytes,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    common::{CommitmentToCoefficients, Share, ShareId, Shares, VerifiableShare, VerifiableShares},
    error::SSError,
    shamir_ss,
};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct CommitmentKey<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub h: G,
}

impl<G: AffineRepr> CommitmentKey<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g =
            projective_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : g"]).into();
        let h =
            projective_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : h"]).into();
        Self { g, h }
    }

    pub fn commit(&self, s: &G::ScalarField, t: &G::ScalarField) -> G::Group {
        self.g
            .mul_bigint(s.into_bigint())
            .add(&self.h.mul_bigint(t.into_bigint()))
    }
}

/// Generate a random secret with its shares according to Pedersen's verifiable secret sharing.
/// Returns the secret, blinding, shares, Pedersen commitments to coefficients of the polynomials for
/// the secret and blinding and the polynomials
pub fn deal_random_secret<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
    comm_key: &CommitmentKey<G>,
) -> Result<
    (
        G::ScalarField,
        G::ScalarField,
        VerifiableShares<G::ScalarField>,
        CommitmentToCoefficients<G>,
        DensePolynomial<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
    ),
    SSError,
> {
    let secret = G::ScalarField::rand(rng);
    let (t, shares, coeff_comms, s_poly, t_poly) =
        deal_secret(rng, secret, threshold, total, comm_key)?;
    Ok((secret, t, shares, coeff_comms, s_poly, t_poly))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    secret: G::ScalarField,
    threshold: ShareId,
    total: ShareId,
    comm_key: &CommitmentKey<G>,
) -> Result<
    (
        G::ScalarField,
        VerifiableShares<G::ScalarField>,
        CommitmentToCoefficients<G>,
        DensePolynomial<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
    ),
    SSError,
> {
    // Shares of the secret
    let (s_shares, s_poly) = shamir_ss::deal_secret(rng, secret, threshold, total)?;
    // Create a random blinding and shares of that
    let (t, t_shares, t_poly) = shamir_ss::deal_random_secret(rng, threshold, total)?;
    // Create Pedersen commitments where each commitment commits to a coefficient of the polynomial `s_poly` and with blinding as coefficient of the polynomial `t_poly`
    let coeff_comms = G::Group::normalize_batch(
        &cfg_into_iter!(0..threshold as usize)
            .map(|i| comm_key.commit(&s_poly.coeffs[i], &t_poly.coeffs[i]))
            .collect::<Vec<_>>(),
    );

    Ok((
        t,
        VerifiableShares(
            cfg_into_iter!(s_shares.0)
                .zip(cfg_into_iter!(t_shares.0))
                .map(|(s, t)| VerifiableShare {
                    id: s.id,
                    threshold,
                    secret_share: s.share,
                    blinding_share: t.share,
                })
                .collect(),
        ),
        coeff_comms.into(),
        s_poly,
        t_poly,
    ))
}

impl<F: PrimeField> VerifiableShare<F> {
    /// Executed by each participant to verify its share received from the dealer.
    pub fn verify<G: AffineRepr<ScalarField = F>>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        comm_key: &CommitmentKey<G>,
    ) -> Result<(), SSError> {
        let len = commitment_coeffs.0.len() as ShareId;
        if self.threshold > len {
            return Err(SSError::BelowThreshold(self.threshold, len));
        }
        // Check commitment_coeffs[0] + commitment_coeffs[1]*id + commitment_coeffs[2]*{id^2} + ... commitment_coeffs[threshold-1]*{id^threshold-1} == g*share.s + h*share.t
        // => commitment_coeffs[0] + commitment_coeffs[1]*id + commitment_coeffs[2]*{id^2} + ... commitment_coeffs[threshold-1]*{id^threshold-1} * {g*share.s + h*share.t}*-1 == 1

        let powers = powers(&G::ScalarField::from(self.id as u64), self.threshold as u32);
        if G::Group::msm_unchecked(&commitment_coeffs.0, &powers)
            != comm_key.commit(&self.secret_share, &self.blinding_share)
        {
            return Err(SSError::InvalidShare);
        }
        Ok(())
    }
}

impl<F: PrimeField> VerifiableShares<F> {
    pub fn reconstruct_secret(&self) -> Result<(F, F), SSError> {
        let threshold = self.threshold();
        let mut s_shares = Vec::with_capacity(self.0.len());
        let mut t_shares = Vec::with_capacity(self.0.len());
        for share in &self.0 {
            s_shares.push(Share {
                id: share.id,
                threshold,
                share: share.secret_share,
            });
            t_shares.push(Share {
                id: share.id,
                threshold,
                share: share.blinding_share,
            });
        }
        let s = Shares(s_shares).reconstruct_secret()?;
        let t = Shares(t_shares).reconstruct_secret()?;

        Ok((s, t))
    }

    pub fn threshold(&self) -> ShareId {
        self.0[0].threshold
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_ff::One;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use test_utils::{test_serialization, G1, G2};

    #[test]
    fn pedersen_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key1 = CommitmentKey::<G1>::new::<Blake2b512>(b"test");
        let comm_key2 = CommitmentKey::<G2>::new::<Blake2b512>(b"test");

        fn check<G: AffineRepr>(rng: &mut StdRng, comm_key: &CommitmentKey<G>) {
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
                let (secret, blinding, shares, commitments, _, _) = deal_random_secret::<_, G>(
                    rng,
                    threshold as ShareId,
                    total as ShareId,
                    &comm_key,
                )
                .unwrap();

                for share in &shares.0 {
                    // Wrong share fails to verify
                    let mut wrong_share = share.clone();
                    wrong_share.secret_share += G::ScalarField::one();
                    assert!(wrong_share.verify(&commitments, &comm_key).is_err());

                    let mut wrong_share = share.clone();
                    wrong_share.blinding_share += G::ScalarField::one();
                    assert!(wrong_share.verify(&commitments, &comm_key).is_err());

                    // Correct share verifies
                    share.verify(&commitments, &comm_key).unwrap();
                }

                let (s, t) = shares.reconstruct_secret().unwrap();
                assert_eq!(s, secret);
                assert_eq!(t, blinding);

                test_serialization!(VerifiableShares<G::ScalarField>, shares);
                test_serialization!(VerifiableShare<G::ScalarField>, shares.0[0]);
                test_serialization!(CommitmentToCoefficients<G>, commitments);
            }
        }

        check(&mut rng, &comm_key1);
        check(&mut rng, &comm_key2);
    }
}
