use crate::tz_21::seed_tree::SeedTree;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, fmt::Debug, rand::RngCore, vec::Vec, UniformRand,
};
use dock_crypto_utils::{
    aliases::FullDigest,
    elgamal::{BatchedHashedElgamalCiphertext, HashedElgamalCiphertext},
    msm::WindowTable,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A list of Elgamal ciphertexts, one for each message. For each message, encryptor creates fresh
/// randomness and a thus a new shared secret using Diffie-Hellman key exchange
#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SimpleBatchElgamalCiphertext<G: AffineRepr>(Vec<HashedElgamalCiphertext<G>>);

/// A trait implemented by schemes encrypting a batch of messages
pub trait BatchCiphertext<G: AffineRepr>:
    Sized
    + Clone
    + Default
    + PartialEq
    + Debug
    + Send
    + Sync
    + CanonicalSerialize
    + CanonicalDeserialize
{
    /// Randomness used in the encryption
    type Randomness: Clone + Default + PartialEq + CanonicalSerialize + CanonicalDeserialize;

    /// Create a new ciphertext for the batch of messages
    fn new<D: FullDigest>(
        msgs: &[G::ScalarField],
        randomness: &Self::Randomness,
        public_key: &WindowTable<G::Group>,
        gen: &WindowTable<G::Group>,
    ) -> Self;

    fn batch_size(&self) -> usize;

    /// Decrypt the ciphertext to get the message batch back
    fn decrypt<D: FullDigest>(&self, secret_key: &G::ScalarField) -> Vec<G::ScalarField>;

    /// Add 1 item each from the given `deltas` to a ciphertext
    fn add_to_ciphertexts(&mut self, deltas: &[G::ScalarField]);

    /// Multiply each ciphertext by the given multiplier `m`
    fn multiply_with_ciphertexts(&mut self, m: &G::ScalarField);

    /// Multiply the OTP (one time pad) with given `m` before applying the OTP
    fn decrypt_after_multiplying_otp<D: FullDigest>(
        &self,
        m: &G::ScalarField,
        secret_key: &G::ScalarField,
    ) -> Vec<G::ScalarField>;

    /// Get randomness for encryption deterministically. Used in DKGitH
    fn get_randomness_from_seed_tree<
        const NUM_PARTIES: usize,
        const SEED_SIZE: usize,
        D: FullDigest,
    >(
        seed_tree: &SeedTree<NUM_PARTIES, SEED_SIZE>,
        party_index: u16,
        witness_count: usize,
    ) -> Self::Randomness;

    /// Get randomness for encryption using the given random number generator. Used in RDKGitH
    fn get_randomness_from_rng<R: RngCore>(rng: &mut R, witness_count: usize) -> Self::Randomness;

    fn is_randomness_size_correct(randomness: &Self::Randomness, witness_count: usize) -> bool;
}

impl<G: AffineRepr> BatchCiphertext<G> for SimpleBatchElgamalCiphertext<G> {
    /// A different random value is created for each message to be encrypted
    type Randomness = Vec<G::ScalarField>;

    fn new<D: FullDigest>(
        msgs: &[G::ScalarField],
        randomness: &Vec<G::ScalarField>,
        public_key: &WindowTable<G::Group>,
        gen: &WindowTable<G::Group>,
    ) -> Self {
        assert_eq!(msgs.len(), randomness.len());
        Self(
            cfg_into_iter!(msgs)
                .zip(cfg_into_iter!(randomness))
                .map(|(m, r)| {
                    HashedElgamalCiphertext::<G>::new_given_randomness_and_window_tables::<D>(
                        m, r, public_key, gen,
                    )
                })
                .collect(),
        )
    }

    fn batch_size(&self) -> usize {
        self.0.len()
    }

    fn decrypt<D: FullDigest>(&self, secret_key: &G::ScalarField) -> Vec<G::ScalarField> {
        cfg_into_iter!(0..self.batch_size())
            .map(|i| self.0[i].decrypt::<D>(secret_key))
            .collect()
    }

    fn add_to_ciphertexts(&mut self, deltas: &[G::ScalarField]) {
        assert_eq!(deltas.len(), self.batch_size());
        cfg_iter_mut!(self.0)
            .zip(cfg_iter!(deltas))
            .for_each(|(m, d)| {
                m.encrypted += d;
            })
    }

    fn multiply_with_ciphertexts(&mut self, m: &G::ScalarField) {
        cfg_iter_mut!(self.0).for_each(|c| {
            c.encrypted *= m;
        })
    }

    fn decrypt_after_multiplying_otp<D: FullDigest>(
        &self,
        m: &G::ScalarField,
        secret_key: &G::ScalarField,
    ) -> Vec<G::ScalarField> {
        cfg_into_iter!(0..self.batch_size())
            .map(|i| {
                let otp = HashedElgamalCiphertext::otp::<D>(
                    (self.0[i].eph_pk * secret_key).into_affine(),
                ) * m;
                self.0[i].encrypted - otp
            })
            .collect()
    }

    fn get_randomness_from_seed_tree<
        const NUM_PARTIES: usize,
        const SEED_SIZE: usize,
        D: FullDigest,
    >(
        seed_tree: &SeedTree<NUM_PARTIES, SEED_SIZE>,
        party_index: u16,
        witness_count: usize,
    ) -> Self::Randomness {
        cfg_into_iter!(0..witness_count)
            .map(|k| {
                seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(
                    party_index,
                    &(witness_count + k).to_le_bytes(),
                )
            })
            .collect()
    }

    fn get_randomness_from_rng<R: RngCore>(rng: &mut R, witness_count: usize) -> Self::Randomness {
        (0..witness_count)
            .map(|_| G::ScalarField::rand(rng))
            .collect()
    }

    fn is_randomness_size_correct(randomness: &Self::Randomness, witness_count: usize) -> bool {
        randomness.len() == witness_count
    }
}

impl<G: AffineRepr> BatchCiphertext<G> for BatchedHashedElgamalCiphertext<G> {
    /// Only a single value is created and then OTPs are generated by "appending" counters for each message to be encrypted
    type Randomness = G::ScalarField;

    fn new<D: FullDigest>(
        msgs: &[G::ScalarField],
        randomness: &G::ScalarField,
        public_key: &WindowTable<G::Group>,
        gen: &WindowTable<G::Group>,
    ) -> Self {
        BatchedHashedElgamalCiphertext::new_given_randomness_and_window_tables::<D>(
            msgs, randomness, public_key, gen,
        )
    }

    fn batch_size(&self) -> usize {
        self.batch_size()
    }

    fn decrypt<D: FullDigest>(&self, secret_key: &G::ScalarField) -> Vec<G::ScalarField> {
        self.decrypt::<D>(secret_key)
    }

    fn add_to_ciphertexts(&mut self, deltas: &[G::ScalarField]) {
        cfg_iter_mut!(self.encrypted)
            .zip(cfg_into_iter!(deltas))
            .for_each(|(e_j, s_j)| {
                *e_j += s_j;
            })
    }

    fn multiply_with_ciphertexts(&mut self, m: &G::ScalarField) {
        cfg_iter_mut!(self.encrypted).for_each(|c| {
            *c *= m;
        })
    }

    fn decrypt_after_multiplying_otp<D: FullDigest>(
        &self,
        m: &G::ScalarField,
        secret_key: &G::ScalarField,
    ) -> Vec<G::ScalarField> {
        let shared_secret = (self.eph_pk * secret_key).into_affine();
        cfg_into_iter!(0..self.batch_size())
            .map(|i| {
                let otp = BatchedHashedElgamalCiphertext::otp::<D>(&shared_secret, i as u32) * m;
                self.encrypted[i] - otp
            })
            .collect()
    }

    fn get_randomness_from_seed_tree<
        const NUM_PARTIES: usize,
        const SEED_SIZE: usize,
        D: FullDigest,
    >(
        seed_tree: &SeedTree<NUM_PARTIES, SEED_SIZE>,
        party_index: u16,
        witness_count: usize,
    ) -> Self::Randomness {
        seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(
            party_index,
            &(witness_count + party_index as usize).to_le_bytes(),
        )
    }

    fn get_randomness_from_rng<R: RngCore>(rng: &mut R, _witness_count: usize) -> Self::Randomness {
        G::ScalarField::rand(rng)
    }

    fn is_randomness_size_correct(_randomness: &Self::Randomness, _witness_count: usize) -> bool {
        true
    }
}
