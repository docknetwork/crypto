//! Elgamal encryption and some variations
//! Implements:
//! 1. Plain Elgamal scheme where the message to be encrypted is a group element (of the same group as the public key)
//! 2. Hashed Elgamal where the message to be encrypted is a field element.
//! 3. A more efficient, batched hashed Elgamal where multiple messages, each being a field element, are encrypted for the same public key.  

#[cfg(feature = "serde")]
use crate::serde_utils::ArkObjectBytes;
use crate::{aliases::FullDigest, hashing_utils::hash_to_field, msm::WindowTable};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(
    Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct SecretKey<F: PrimeField>(pub F);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<G: AffineRepr>(pub G);

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

impl<G: AffineRepr> PublicKey<G> {
    pub fn new(secret_key: &SecretKey<G::ScalarField>, g: &G) -> Self {
        Self(g.mul_bigint(secret_key.0.into_bigint()).into_affine())
    }
}

/// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
pub fn keygen<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    g: &G,
) -> (SecretKey<G::ScalarField>, PublicKey<G>) {
    let sk = SecretKey::new(rng);
    let pk = PublicKey::new(&sk, g);
    (sk, pk)
}

/// Elgamal encryption of a group element `m`
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext<G: AffineRepr> {
    /// `m + r * pk`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub encrypted: G,
    /// Ephemeral public key `r * g`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub eph_pk: G,
}

impl<G: AffineRepr> Ciphertext<G> {
    /// Returns the ciphertext and randomness created for encryption
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new<R: RngCore>(rng: &mut R, msg: &G, public_key: &G, g: &G) -> (Self, G::ScalarField) {
        let randomness = G::ScalarField::rand(rng);
        (
            Self::new_given_randomness(msg, &randomness, public_key, g),
            randomness,
        )
    }

    /// Returns the ciphertext
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness(
        msg: &G,
        randomness: &G::ScalarField,
        public_key: &G,
        g: &G,
    ) -> Self {
        let b = randomness.into_bigint();
        let encrypted = (public_key.mul_bigint(b) + msg).into_affine();
        Self {
            encrypted,
            eph_pk: g.mul_bigint(b).into_affine(),
        }
    }

    /// Returns the ciphertext but takes the window tables for the public key and generator. Useful when a lot
    /// of encryptions have to be done using the same public key
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness_and_window_tables(
        msg: &G,
        randomness: &G::ScalarField,
        public_key: &WindowTable<G::Group>,
        g: &WindowTable<G::Group>,
    ) -> Self {
        let encrypted = ((public_key * randomness) + msg).into_affine();
        Self {
            encrypted,
            eph_pk: g.multiply(randomness).into_affine(),
        }
    }

    pub fn decrypt(&self, secret_key: &G::ScalarField) -> G {
        (self.eph_pk.mul(secret_key).neg() + self.encrypted).into_affine()
    }
}

/// Hashed Elgamal. Encryption of a field element `m`. The shared secret is hashed to a field element
/// and the result is added to the message to get the ciphertext.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashedElgamalCiphertext<G: AffineRepr> {
    /// `m + Hash(r * pk)`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub encrypted: G::ScalarField,
    /// Ephemeral public key `r * g`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub eph_pk: G,
}

impl<G: AffineRepr> HashedElgamalCiphertext<G> {
    /// Returns the ciphertext and randomness created for encryption
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new<R: RngCore, D: FullDigest>(
        rng: &mut R,
        msg: &G::ScalarField,
        public_key: &G,
        g: &G,
    ) -> (Self, G::ScalarField) {
        let randomness = G::ScalarField::rand(rng);
        (
            Self::new_given_randomness::<D>(msg, &randomness, public_key, g),
            randomness,
        )
    }

    /// Returns the ciphertext
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness<D: FullDigest>(
        msg: &G::ScalarField,
        randomness: &G::ScalarField,
        public_key: &G,
        g: &G,
    ) -> Self {
        let b = randomness.into_bigint();
        let shared_secret = public_key.mul_bigint(b).into_affine();
        Self {
            encrypted: Self::otp::<D>(shared_secret) + msg,
            eph_pk: g.mul_bigint(b).into_affine(),
        }
    }

    /// Returns the ciphertext but takes the window tables for the public key and generator. Useful when a lot
    /// of encryptions have to be done using the same public key
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness_and_window_tables<D: FullDigest>(
        msg: &G::ScalarField,
        randomness: &G::ScalarField,
        public_key: &WindowTable<G::Group>,
        g: &WindowTable<G::Group>,
    ) -> Self {
        let shared_secret = public_key.multiply(randomness).into_affine();
        Self {
            encrypted: Self::otp::<D>(shared_secret) + msg,
            eph_pk: g.multiply(randomness).into_affine(),
        }
    }

    pub fn decrypt<D: FullDigest>(&self, secret_key: &G::ScalarField) -> G::ScalarField {
        let shared_secret = self.eph_pk.mul(secret_key).into_affine();
        self.encrypted - Self::otp::<D>(shared_secret)
    }

    /// Return a OTP (One Time Pad) by hashing the shared secret.
    pub fn otp<D: FullDigest>(shared_secret: G) -> G::ScalarField {
        let mut bytes = Vec::with_capacity(shared_secret.compressed_size());
        shared_secret.serialize_uncompressed(&mut bytes).unwrap();
        hash_to_field::<G::ScalarField, D>(b"", &bytes)
    }
}

/// Hashed Elgamal variant for encrypting a batch of messages. Encryption of vector of field elements.
/// Generates a batch of OTPs (One Time Pad) by hashing the concatenation of the shared secret and the
/// message index, corresponding to which the OTP is created. The OTPs are then added to the corresponding
/// message to get the ciphertext. This is an efficient mechanism of encrypting multiple messages to the same
/// public key as there is only 1 shared secret created by a scalar multiplication and one randomness chosen
/// by the encryptor
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BatchedHashedElgamalCiphertext<G: AffineRepr> {
    /// `m_i + Hash((r * pk) || i)`
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    pub encrypted: Vec<G::ScalarField>,
    /// Ephemeral public key `r * g`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub eph_pk: G,
}

impl<G: AffineRepr> BatchedHashedElgamalCiphertext<G> {
    /// Returns the ciphertext and randomness created for encryption
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new<R: RngCore, D: FullDigest>(
        rng: &mut R,
        msgs: &[G::ScalarField],
        public_key: &G,
        g: &G,
    ) -> (Self, G::ScalarField) {
        let randomness = G::ScalarField::rand(rng);
        (
            Self::new_given_randomness::<D>(msgs, &randomness, public_key, g),
            randomness,
        )
    }

    /// Returns the ciphertext
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness<D: FullDigest>(
        msgs: &[G::ScalarField],
        randomness: &G::ScalarField,
        public_key: &G,
        g: &G,
    ) -> Self {
        let b = randomness.into_bigint();
        let shared_secret = public_key.mul_bigint(b).into_affine();
        Self {
            encrypted: Self::enc_with_otp::<D>(&msgs, &shared_secret),
            eph_pk: g.mul_bigint(b).into_affine(),
        }
    }

    /// Returns the ciphertext but takes the window tables for the public key and generator. Useful when a lot
    /// of encryptions have to be done using the same public key
    /// `g` is the generator used in the scheme to generate public key and ephemeral public key by sender/encryptor
    pub fn new_given_randomness_and_window_tables<D: FullDigest>(
        msgs: &[G::ScalarField],
        randomness: &G::ScalarField,
        public_key: &WindowTable<G::Group>,
        g: &WindowTable<G::Group>,
    ) -> Self {
        let shared_secret = public_key.multiply(randomness).into_affine();
        Self {
            encrypted: Self::enc_with_otp::<D>(&msgs, &shared_secret),
            eph_pk: g.multiply(randomness).into_affine(),
        }
    }

    pub fn decrypt<D: FullDigest>(&self, secret_key: &G::ScalarField) -> Vec<G::ScalarField> {
        let shared_secret = self.eph_pk.mul(secret_key).into_affine();
        cfg_iter!(self.encrypted)
            .enumerate()
            .map(|(i, e)| *e - Self::otp::<D>(&shared_secret, i as u32))
            .collect::<Vec<_>>()
    }

    pub fn batch_size(&self) -> usize {
        self.encrypted.len()
    }

    /// Return a OTP (One Time Pad) by hashing the shared secret along with the message index.
    pub fn otp<D: FullDigest>(shared_secret: &G, msg_idx: u32) -> G::ScalarField {
        let mut bytes = Vec::with_capacity(shared_secret.compressed_size());
        shared_secret.serialize_uncompressed(&mut bytes).unwrap();
        msg_idx.serialize_uncompressed(&mut bytes).unwrap();
        hash_to_field::<G::ScalarField, D>(b"", &bytes)
    }

    fn enc_with_otp<D: FullDigest>(
        msgs: &[G::ScalarField],
        shared_secret: &G,
    ) -> Vec<G::ScalarField> {
        cfg_iter!(msgs)
            .enumerate()
            .map(|(i, m)| Self::otp::<D>(shared_secret, i as u32) + m)
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng) {
            let g = G::Group::rand(rng).into_affine();
            let (sk, pk) = keygen(rng, &g);

            let msg = G::Group::rand(rng).into_affine();
            let (ciphertext, _) = Ciphertext::new(rng, &msg, &pk.0, &g);
            assert_eq!(ciphertext.decrypt(&sk.0), msg);
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn hashed_encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng) {
            let g = G::Group::rand(rng).into_affine();
            let (sk, pk) = keygen(rng, &g);

            let msg = G::ScalarField::rand(rng);
            let (ciphertext, _) =
                HashedElgamalCiphertext::new::<_, Blake2b512>(rng, &msg, &pk.0, &g);
            assert_eq!(ciphertext.decrypt::<Blake2b512>(&sk.0), msg);
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn hashed_encrypt_decrypt_batch() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng) {
            let g = G::Group::rand(rng).into_affine();
            let (sk, pk) = keygen(rng, &g);
            let count = 10;

            let msgs = (0..count)
                .map(|_| G::ScalarField::rand(rng))
                .collect::<Vec<_>>();
            let mut enc_time = Duration::default();
            let mut dec_time = Duration::default();
            for i in 0..count {
                let start = Instant::now();
                let (ciphertext, _) =
                    HashedElgamalCiphertext::new::<_, Blake2b512>(rng, &msgs[i], &pk.0, &g);
                enc_time += start.elapsed();
                let start = Instant::now();
                assert_eq!(ciphertext.decrypt::<Blake2b512>(&sk.0), msgs[i]);
                dec_time += start.elapsed();
            }
            println!(
                "For encryption {} messages one by one, time to encrypt {:?} and to decrypt: {:?}",
                count, enc_time, dec_time
            );

            let start = Instant::now();
            let (ciphertext, _) =
                BatchedHashedElgamalCiphertext::new::<_, Blake2b512>(rng, &msgs, &pk.0, &g);
            enc_time = start.elapsed();
            let start = Instant::now();
            assert_eq!(ciphertext.decrypt::<Blake2b512>(&sk.0), msgs);
            dec_time = start.elapsed();

            println!(
                "For encryption {} messages in batch, time to encrypt {:?} and to decrypt: {:?}",
                count, enc_time, dec_time
            );
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }
}
