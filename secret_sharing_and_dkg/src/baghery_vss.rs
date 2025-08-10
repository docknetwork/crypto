//! Verifiable Secret Sharing scheme inspired by Feldman's, but using hash function for commitment instead of elliptic curve operations. By K. Baghery.
//!
//! As described by `Π_LA`, in Fig 5 of the paper [A Unified Framework for Verifiable Secret Sharing](https://eprint.iacr.org/2023/1669)

use crate::{
    common::{Share, ShareId, Shares},
    error::SSError,
    shamir_ss,
};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, rand::RngCore, vec, vec::Vec};
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::compute_random_oracle_challenge;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub const DEFAULT_DIGEST_SIZE: usize = 64;
pub const DOMAIN_SEPARATOR: &[u8] = b"PI_LA";

/// Proof that the dealer shared the secret correctly.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<F: PrimeField, const DIGEST_SIZE: usize = DEFAULT_DIGEST_SIZE> {
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<[_; DIGEST_SIZE]>"))]
    pub commitments: Vec<[u8; DIGEST_SIZE]>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub resp: DensePolynomial<F>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub challenge: F,
}

/// Generate a random secret with its shares according to Shamir's secret sharing.
/// At least `threshold` number of shares are needed to reconstruct the secret.
/// Returns the secret, shares, the polynomial and proof to verify the correct sharing
pub fn deal_random_secret<R: RngCore, F: PrimeField, D: Digest, const DIGEST_SIZE: usize>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
) -> Result<(F, Shares<F>, DensePolynomial<F>, Proof<F, DIGEST_SIZE>), SSError> {
    let secret = F::rand(rng);
    let (shares, sharing_poly, proof) =
        deal_secret::<_, _, D, DIGEST_SIZE>(rng, secret, threshold, total)?;
    Ok((secret, shares, sharing_poly, proof))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<R: RngCore, F: PrimeField, D: Digest, const DIGEST_SIZE: usize>(
    rng: &mut R,
    secret: F,
    threshold: ShareId,
    total: ShareId,
) -> Result<(Shares<F>, DensePolynomial<F>, Proof<F, DIGEST_SIZE>), SSError> {
    let (shares, f) = shamir_ss::deal_secret(rng, secret, threshold, total)?;
    let r = <DensePolynomial<F> as DenseUVPolynomial<F>>::rand(threshold as usize - 1, rng);
    debug_assert_eq!(f.degree(), r.degree());
    let commitments = cfg_into_iter!(0..total as usize)
        .map(|i| {
            hash_commitment::<_, D, DIGEST_SIZE>(
                shares.0[i].share,
                r.evaluate(&F::from(i as u64 + 1)),
            )
        })
        .collect::<Vec<_>>();
    let mut chal_bytes = vec![];
    for c in &commitments {
        c.serialize_compressed(&mut chal_bytes)?;
    }
    let d = compute_random_oracle_challenge::<F, D>(&chal_bytes);
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

impl<F: PrimeField, const DIGEST_SIZE: usize> Proof<F, DIGEST_SIZE> {
    pub fn verify<D: Digest>(&self, share: &Share<F>) -> Result<(), SSError> {
        if self.resp.degree() != share.threshold as usize - 1 {
            return Err(SSError::DoesNotSupportThreshold(share.threshold));
        }
        let mut chal_bytes = vec![];
        for c in &self.commitments {
            c.serialize_compressed(&mut chal_bytes)?;
        }
        let d = compute_random_oracle_challenge::<F, D>(&chal_bytes);
        let r = self.resp.evaluate(&F::from(share.id)) - d * share.share;
        if self.commitments[share.id as usize - 1]
            != hash_commitment::<_, D, DIGEST_SIZE>(share.share, r)
        {
            return Err(SSError::InvalidShare);
        }
        Ok(())
    }
}

pub fn hash_commitment<T: CanonicalSerialize, D: Digest, const DIGEST_SIZE: usize>(
    msg: T,
    r: T,
) -> [u8; DIGEST_SIZE] {
    let serz_size = T::compressed_size(&msg);
    let mut bytes = Vec::with_capacity(serz_size * 2 + DOMAIN_SEPARATOR.len());
    msg.serialize_compressed(&mut bytes).unwrap();
    bytes.extend_from_slice(DOMAIN_SEPARATOR);
    r.serialize_compressed(&mut bytes).unwrap();
    let d = D::digest(&bytes);
    d.as_slice().try_into().expect("Wrong length")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use std::time::Instant;
    use test_utils::test_serialization;

    #[test]
    fn baghery_verifiable_secret_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
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
            (15, 32),
            (63, 128),
            (255, 512),
        ] {
            println!("For {}-of-{} sharing", threshold, total);
            let start = Instant::now();
            let (secret, shares, _, proof) =
                deal_random_secret::<_, Fr, Blake2b512, DEFAULT_DIGEST_SIZE>(
                    &mut rng,
                    threshold as ShareId,
                    total as ShareId,
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
                wrong_share.share += Fr::one();
                assert!(proof.verify::<Blake2b512>(&wrong_share).is_err());

                // Correct share verifies
                let start = Instant::now();
                proof.verify::<Blake2b512>(&share).unwrap();
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
                test_serialization!(Shares<Fr>, shares);
                test_serialization!(Share<Fr>, shares.0[0]);
                test_serialization!(Proof<Fr>, proof);
                checked_serialization = true;
            }
        }
    }
}
