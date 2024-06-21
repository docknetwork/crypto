//! Feldman's Verifiable Secret Sharing Scheme, with faster verification but slower sharing, by K. Baghery.
//! As described in Fig 3 of the paper [A Unified Framework for Verifiable Secret Sharing](https://eprint.iacr.org/2023/1669)

use crate::{
    common::{Share, ShareId, Shares},
    error::SSError,
    shamir_ss,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{commitment::PedersenCommitmentKey, serde_utils::ArkObjectBytes};
use schnorr_pok::compute_random_oracle_challenge;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Proof that the dealer shared the secret correctly.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Proof<G: AffineRepr> {
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub commitments: Vec<G>,
    #[serde_as(as = "ArkObjectBytes")]
    pub resp: DensePolynomial<G::ScalarField>,
    #[serde_as(as = "ArkObjectBytes")]
    pub challenge: G::ScalarField,
}

/// Generate a random secret with its shares according to Shamir's secret sharing.
/// At least `threshold` number of shares are needed to reconstruct the secret.
/// Returns the secret, shares, the polynomial and proof to verify the correct sharing
pub fn deal_random_secret<R: RngCore, G: AffineRepr, D: Digest>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
    comm_key: &PedersenCommitmentKey<G>,
) -> Result<
    (
        G::ScalarField,
        Shares<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
        Proof<G>,
    ),
    SSError,
> {
    let secret = G::ScalarField::rand(rng);
    let (shares, sharing_poly, proof) =
        deal_secret::<_, _, D>(rng, secret, threshold, total, comm_key)?;
    Ok((secret, shares, sharing_poly, proof))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<R: RngCore, G: AffineRepr, D: Digest>(
    rng: &mut R,
    secret: G::ScalarField,
    threshold: ShareId,
    total: ShareId,
    comm_key: &PedersenCommitmentKey<G>,
) -> Result<
    (
        Shares<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
        Proof<G>,
    ),
    SSError,
> {
    let (shares, f) = shamir_ss::deal_secret(rng, secret, threshold, total)?;
    let r = <DensePolynomial<G::ScalarField> as DenseUVPolynomial<G::ScalarField>>::rand(
        threshold as usize - 1,
        rng,
    );
    debug_assert_eq!(f.degree(), r.degree());
    let r_evals = cfg_into_iter!(1..=total)
        .map(|i| r.evaluate(&G::ScalarField::from(i)))
        .collect::<Vec<_>>();
    let commitments = G::Group::normalize_batch(
        &cfg_into_iter!(0..total as usize)
            .map(|i| comm_key.commit_as_projective(&shares.0[i].share, &r_evals[i]))
            .collect::<Vec<_>>(),
    );
    let mut chal_bytes = vec![];
    comm_key.g.serialize_compressed(&mut chal_bytes)?;
    comm_key.h.serialize_compressed(&mut chal_bytes)?;
    for c in &commitments {
        c.serialize_compressed(&mut chal_bytes)?;
    }
    let d = compute_random_oracle_challenge::<G::ScalarField, D>(&chal_bytes);
    let z = r + (&f * d);
    Ok((
        shares,
        f,
        Proof {
            commitments,
            resp: z,
            challenge: d,
        },
    ))
}

impl<G: AffineRepr> Proof<G> {
    pub fn verify<D: Digest>(
        &self,
        share: &Share<G::ScalarField>,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<(), SSError> {
        if self.resp.degree() != share.threshold as usize - 1 {
            return Err(SSError::DoesNotSupportThreshold(share.threshold));
        }
        let mut chal_bytes = vec![];
        comm_key.g.serialize_compressed(&mut chal_bytes)?;
        comm_key.h.serialize_compressed(&mut chal_bytes)?;
        for c in &self.commitments {
            c.serialize_compressed(&mut chal_bytes)?;
        }
        let d = compute_random_oracle_challenge::<G::ScalarField, D>(&chal_bytes);
        let r = self.resp.evaluate(&G::ScalarField::from(share.id)) - d * share.share;
        if self.commitments[share.id as usize - 1] != comm_key.commit(&share.share, &r) {
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
    use blake2::Blake2b512;
    use std::time::Instant;
    use test_utils::test_serialization;

    #[test]
    fn baghery_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key1 = PedersenCommitmentKey::<G1Affine>::new::<Blake2b512>(b"test");
        let comm_key2 = PedersenCommitmentKey::<G2Affine>::new::<Blake2b512>(b"test");

        fn check<G: AffineRepr>(rng: &mut StdRng, comm_key: &PedersenCommitmentKey<G>) {
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
                let (secret, shares, _, proof) = deal_random_secret::<_, G, Blake2b512>(
                    rng,
                    threshold as ShareId,
                    total as ShareId,
                    &comm_key,
                )
                .unwrap();
                println!("Time to create shares and proof {:?}", start.elapsed());
                println!(
                    "Proof size is {} bytes",
                    proof.serialized_size(Compress::Yes)
                );

                let mut noted_time = false;

                for share in &shares.0 {
                    // Wrong share fails to verify
                    let mut wrong_share = share.clone();
                    wrong_share.share += G::ScalarField::one();
                    assert!(proof.verify::<Blake2b512>(&wrong_share, &comm_key).is_err());

                    // Correct share verifies
                    let start = Instant::now();
                    proof.verify::<Blake2b512>(&share, &comm_key).unwrap();
                    if !noted_time {
                        println!("Time to verify share is {:?}", start.elapsed());
                        noted_time = true;
                    }
                }

                // Its assumed that reconstructor verifies each share before calling `reconstruct_secret`
                let s = shares.reconstruct_secret().unwrap();
                assert_eq!(s, secret);

                // Test serialization
                if !checked_serialization {
                    test_serialization!(Shares<G::ScalarField>, shares);
                    test_serialization!(Share<G::ScalarField>, shares.0[0]);
                    test_serialization!(Proof<G>, proof);
                    checked_serialization = true;
                }
            }
        }

        check(&mut rng, &comm_key1);
        check(&mut rng, &comm_key2);
    }
}
