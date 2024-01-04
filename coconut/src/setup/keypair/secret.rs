use alloc::vec::Vec;

use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField,
};
use ark_serialize::*;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::{misc::le_bytes_iter, serde_utils::ArkObjectBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::helpers::{n_rand, rand, FullDigest};
use utils::{aliases::SyncIfParallel, concat_slices, join};

/// `SecretKey` used in the modified Pointcheval-Sanders signature scheme.
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub x: F,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub y: Vec<F>,
}

impl<F: PrimeField> SecretKey<F> {
    pub const X_SALT: &'static [u8] = b"PS-SIG-X-KEYGEN-SALT";
    pub const Y_SALT: &'static [u8] = b"PS-SIG-Y-KEYGEN-SALT";

    /// Generates random secret key compatible with `message_count` messages.
    pub fn rand<R: RngCore>(rng: &mut R, message_count: u32) -> Self {
        let x = rand(rng);
        let y = n_rand(rng, message_count as usize).collect();

        Self { x, y }
    }

    /// Generates secret key compatible with `message_count` messages from supplied seed.
    pub fn from_seed<D>(seed: &[u8], message_count: u32) -> Self
    where
        D: FullDigest + SyncIfParallel,
    {
        let new_hasher = <DefaultFieldHasher<D> as HashToField<F>>::new;

        let (x, y) = join!(
            new_hasher(Self::X_SALT)
                .hash_to_field(seed, 1)
                .pop()
                .unwrap(),
            {
                let hasher = new_hasher(Self::Y_SALT);

                le_bytes_iter(message_count)
                    .map(|ctr| concat_slices!(seed, ctr))
                    .map(|seed| hasher.hash_to_field(&seed, 1).pop().unwrap())
                    .collect()
            }
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

        assert_eq!(
            SecretKey::<Fr>::from_seed::<Blake2b512>(seed, 10).y[0..9],
            SecretKey::<Fr>::from_seed::<Blake2b512>(seed, 9).y,
        );
    }
}
