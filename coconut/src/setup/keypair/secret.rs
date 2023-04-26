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

/// `SecretKey` used in the modified Pointcheval-Sanders signature scheme.
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField> {
    pub(crate) x: F,
    pub(crate) y: Vec<F>,
}

impl<F: PrimeField> SecretKey<F> {
    const X_SALT: &[u8] = b"PS-SIG-X-KEYGEN-SALT";
    const Y_SALT: &[u8] = b"PS-SIG-Y-KEYGEN-SALT";

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
        let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new;

        let (x, y) = join!(
            hasher(Self::X_SALT).hash_to_field(seed, 1).pop().unwrap(),
            hasher(Self::Y_SALT).hash_to_field(seed, message_count)
        );

        Self { x, y }
    }

    /// Returns max amount of messages supported by this secret key.
    pub fn supported_message_count(&self) -> usize {
        self.y.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn from_seed() {
        let seed = b"test-seed";
        let other_seed = b"other-seed";

        assert_eq!(
            SecretKey::<Fr>::from_seed::<Blake2b512>(seed, 10),
            SecretKey::<Fr>::from_seed::<Blake2b512>(seed, 10),
        );

        assert!(
            SecretKey::<Fr>::from_seed::<Blake2b512>(seed, 10)
                != SecretKey::<Fr>::from_seed::<Blake2b512>(other_seed, 10)
        );
    }
}
