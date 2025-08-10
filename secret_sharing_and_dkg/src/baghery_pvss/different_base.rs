use crate::{baghery_pvss::Share, common::ShareId, error::SSError, shamir_ss};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{expect_equality, msm::WindowTable};
use schnorr_pok::compute_random_oracle_challenge;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Share encrypted for the party
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptedShare<G: AffineRepr> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    /// Masked share `y'_i = j * k_i + g * k_i = (j + g) * k_i`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub masked_share: G,
    /// Mask `y_i = h_i * k_i`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub mask: G,
}

/// Proof that the correct shares are correctly encrypted for each party
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<F: PrimeField> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub challenge: F,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub resp: DensePolynomial<F>,
}

/// Generate a random secret with its shares according to Shamir secret sharing and returns encrypted
/// commitments to the shares with one encryption for each public key. Assumes the public keys are given
/// in the increasing order of their ids in the context of secret sharing and number of public keys equals `total`.
/// At least `threshold` number of share-commitments are needed to reconstruct the commitment to the secret.
/// If additional faults need to be handled, then the threshold should be increased, eg. if `f` number of faults
/// need to be handled and `threshold` number of parties are required to reconstruct the secret, `total >= threshold + f`
/// `pk_base` is the base of the public keys (`g`) and `target_base` is the base for the secret share commitment (`j`)
pub fn deal_random_secret<'a, R: RngCore, G: AffineRepr, D: Digest>(
    rng: &mut R,
    threshold: ShareId,
    total: ShareId,
    public_keys: Vec<G>,
    pk_base: &G,
    target_base: &G,
) -> Result<
    (
        G::ScalarField,
        Vec<EncryptedShare<G>>,
        Proof<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
    ),
    SSError,
> {
    let secret = G::ScalarField::rand(rng);
    let (enc_shares, proof, poly) = deal_secret::<R, G, D>(
        rng,
        secret,
        threshold,
        total,
        public_keys,
        pk_base,
        target_base,
    )?;
    Ok((secret, enc_shares, proof, poly))
}

/// Same as `deal_random_secret` above but accepts the secret to share
pub fn deal_secret<'a, R: RngCore, G: AffineRepr, D: Digest>(
    rng: &mut R,
    secret: G::ScalarField,
    threshold: ShareId,
    total: ShareId,
    public_keys: Vec<G>,
    pk_base: &G,
    target_base: &G,
) -> Result<
    (
        Vec<EncryptedShare<G>>,
        Proof<G::ScalarField>,
        DensePolynomial<G::ScalarField>,
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
    let mut chal_bytes = vec![];
    let mut enc_shares = vec![];
    let mask_base = WindowTable::new(total as usize, *target_base + pk_base);
    mask_base.serialize_compressed(&mut chal_bytes)?;
    // NOTE: The following can be done in parallel
    for (i, pk) in public_keys.into_iter().enumerate() {
        let share_i = &shares.0[i];
        debug_assert_eq!(share_i.id as usize, i + 1);
        // Use same blinding for both relations
        let blinding = r_evals[i];
        let t_mask = pk * blinding;
        // `h_i * k_i`
        let mask = (pk * share_i.share).into_affine();
        let t_masked_share = mask_base.multiply(&blinding).into_affine();
        // `(j + g) * k_i`
        let masked_share = mask_base.multiply(&share_i.share).into_affine();
        pk.serialize_compressed(&mut chal_bytes)?;
        t_mask.serialize_compressed(&mut chal_bytes)?;
        t_masked_share.serialize_compressed(&mut chal_bytes)?;
        mask.serialize_compressed(&mut chal_bytes)?;
        masked_share.serialize_compressed(&mut chal_bytes)?;
        enc_shares.push(EncryptedShare {
            id: share_i.id,
            threshold: share_i.threshold,
            masked_share,
            mask,
        });
    }
    let d = compute_random_oracle_challenge::<G::ScalarField, D>(&chal_bytes);
    let z = r + (&f * d);
    Ok((
        enc_shares,
        Proof {
            challenge: d,
            resp: z,
        },
        f,
    ))
}

impl<F: PrimeField> Proof<F> {
    /// Assumes the public keys and encrypted shares are given in the increasing order of their ids in the context
    /// of secret sharing and number of public keys equals `total`
    /// `pk_base` is the base of the public keys (`g`) and `target_base` is the base for the secret share commitment (`j`)
    pub fn verify<G: AffineRepr<ScalarField = F>, D: Digest>(
        &self,
        threshold: ShareId,
        total: ShareId,
        public_keys: Vec<G>,
        enc_shares: &[EncryptedShare<G>],
        pk_base: &G,
        target_base: &G,
    ) -> Result<(), SSError> {
        expect_equality!(
            enc_shares.len(),
            public_keys.len(),
            SSError::UnequalNoOfSharesAndPublicKeys
        );
        if self.resp.degree() != threshold as usize - 1 {
            return Err(SSError::DoesNotSupportThreshold(threshold));
        }
        let mut chal_bytes = vec![];
        let mask_base = WindowTable::new(total as usize, *target_base + pk_base);
        mask_base.serialize_compressed(&mut chal_bytes)?;
        // NOTE: The following can be done in parallel but since this will be done on blockchain (in our use-case)
        // where we won't have parallelization, keeping it serial
        for (i, pk) in public_keys.into_iter().enumerate() {
            let enc_share_i = &enc_shares[i];
            debug_assert_eq!(enc_share_i.id as usize, i + 1);
            let resp_i = self.resp.evaluate(&G::ScalarField::from(enc_share_i.id));
            // h_i * z(i) - y_i * d
            let t_mask = (pk * resp_i) - (enc_share_i.mask * self.challenge);
            // (j + g) * z(i) - y'_i * d
            let t_masked_share =
                mask_base.multiply(&resp_i) - (enc_share_i.masked_share * self.challenge);
            pk.serialize_compressed(&mut chal_bytes)?;
            t_mask.serialize_compressed(&mut chal_bytes)?;
            t_masked_share.serialize_compressed(&mut chal_bytes)?;
            enc_share_i.mask.serialize_compressed(&mut chal_bytes)?;
            enc_share_i
                .masked_share
                .serialize_compressed(&mut chal_bytes)?;
        }
        if self.challenge != compute_random_oracle_challenge::<G::ScalarField, D>(&chal_bytes) {
            return Err(SSError::InvalidProof);
        }
        Ok(())
    }
}

impl<G: AffineRepr> EncryptedShare<G> {
    pub fn decrypt(&self, sk: &G::ScalarField) -> Share<G> {
        // y_i * 1 / s_i = g * k_i
        let mask = self.mask * sk.inverse().unwrap();
        Share {
            id: self.id,
            threshold: self.threshold,
            // (j + g) * k_i - g * k_i = j * k_i
            share: (self.masked_share.into_group() - mask).into_affine(),
        }
    }

    // Proof of knowledge of same secret key in public key and the encrypted share can be done by existing PokPedersenCommitmentProtocol protocol
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::common;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::VariableBaseMSM;
    use ark_poly::Polynomial;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use dock_crypto_utils::misc::n_rand;
    use std::time::Instant;
    use test_utils::test_serialization;

    #[test]
    fn pvss_with_different_base_than_public_key() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng, pk_base: G, target_base: G) {
            let mut checked_serialization = false;
            for (threshold, total) in vec![
                (1, 3),
                (1, 4),
                (2, 5),
                (2, 6),
                (3, 7),
                (3, 10),
                (4, 9),
                (4, 15),
                (5, 11),
                (5, 13),
                (7, 15),
                (7, 20),
            ] {
                let sks = n_rand(rng, total).collect::<Vec<_>>();
                let pks = (0..total)
                    .map(|i| (pk_base * &sks[i]).into_affine())
                    .collect::<Vec<_>>();
                println!("For {}-of-{} sharing", threshold, total);
                let start = Instant::now();
                let (secret, enc_shares, proof, poly) = deal_random_secret::<_, G, Blake2b512>(
                    rng,
                    threshold as ShareId,
                    total as ShareId,
                    pks.clone(),
                    &pk_base,
                    &target_base,
                )
                .unwrap();
                println!("Time to create shares and proof: {:?}", start.elapsed());
                println!(
                    "Proof size is {} bytes",
                    proof.serialized_size(Compress::Yes)
                );

                let start = Instant::now();
                proof
                    .verify::<G, Blake2b512>(
                        threshold as ShareId,
                        total as ShareId,
                        pks.clone(),
                        &enc_shares,
                        &pk_base,
                        &target_base,
                    )
                    .unwrap();
                println!("Time to verify proof: {:?}", start.elapsed());

                let mut decrypted_shares = vec![];
                for (i, enc_share) in enc_shares.iter().enumerate() {
                    let dec_share = enc_share.decrypt(&sks[i]);
                    assert_eq!(
                        dec_share.share,
                        (target_base * poly.evaluate(&G::ScalarField::from(enc_share.id)))
                            .into_affine()
                    );
                    decrypted_shares.push(dec_share);
                }

                let share_ids = decrypted_shares[0..threshold]
                    .iter()
                    .map(|s| s.id)
                    .collect::<Vec<_>>();
                let share_vals = decrypted_shares[0..threshold]
                    .iter()
                    .map(|s| s.share)
                    .collect::<Vec<_>>();
                let basis =
                    common::lagrange_basis_at_0_for_all::<G::ScalarField>(share_ids).unwrap();
                assert_eq!(
                    G::Group::msm_unchecked(&share_vals, &basis),
                    target_base * secret
                );

                if !checked_serialization {
                    test_serialization!(Proof<G::ScalarField>, proof);
                    test_serialization!(Vec<EncryptedShare<G>>, enc_shares);
                    test_serialization!(Vec<Share<G>>, decrypted_shares);
                    checked_serialization = true;
                }
            }
        }

        let pk_base_g1 = G1Affine::rand(&mut rng);
        let target_base_g1 = G1Affine::rand(&mut rng);
        let pk_base_g2 = G2Affine::rand(&mut rng);
        let target_base_g2 = G2Affine::rand(&mut rng);
        println!("Checking in group G1");
        check(&mut rng, pk_base_g1, target_base_g1);
        println!("Checking in group G2");
        check(&mut rng, pk_base_g2, target_base_g2);
    }
}
