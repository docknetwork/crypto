use alloc::vec::Vec;

use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField,
};
use ark_serialize::*;
use ark_std::rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::helpers::{n_rand, rand, FullDigest};
use utils::{aliases::SyncIfParallel, join};

/// `SecretKey` used in Pointcheval-Sanders signature scheme.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SecretKey<P: PrimeField> {
    pub(crate) x: P,
    pub(crate) y: Vec<P>,
}

impl<P: PrimeField> SecretKey<P> {
    /// Generates random secret key compatible with `message_count` messages.
    pub fn rand<R: RngCore>(rng: &mut R, message_count: usize) -> Self {
        let x = rand(rng);
        let y = n_rand(rng, message_count).collect();

        Self { x, y }
    }

    /// Generates secret key compatible with `message_count` messages from supplied seed.
    pub fn from_seed<D>(seed: &[u8], message_count: usize) -> Self
    where
        D: FullDigest + SyncIfParallel,
    {
        const X_SALT: &[u8] = b"PS-SIG-X-KEYGEN-SALT";
        const Y_SALT: &[u8] = b"PS-SIG-Y-KEYGEN-SALT";

        let hasher = <DefaultFieldHasher<D> as HashToField<P>>::new;

        let (x, y) = join!(
            hasher(X_SALT).hash_to_field(seed, 1).pop().unwrap(),
            hasher(Y_SALT).hash_to_field(seed, message_count)
        );

        Self { x, y }
    }
}
