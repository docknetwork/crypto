//! Modified Pointcheval-Sanders signature scheme setup.
//! Defines params, public/private keys, and setup params.
//! Implements keygen based on Shamir's secret sharing.

use alloc::vec::Vec;

pub mod keygen;
pub mod keypair;
pub mod signature_params;

pub use keypair::*;
pub use signature_params::*;

/// **Not intended to be used anywhere except for tests.**
/// Initializes secret/public key along with params and messages to be used in tests.
#[allow(clippy::type_complexity)]
pub fn test_setup<E, D, R>(
    rng: &mut R,
    message_count: usize,
) -> (
    SecretKey<E::ScalarField>,
    PublicKey<E>,
    SignatureParams<E>,
    Vec<E::ScalarField>,
)
where
    E: ark_ec::pairing::Pairing,
    D: digest::Digest,
    R: ark_std::rand::RngCore,
{
    use crate::helpers::n_rand;

    let params = SignatureParams::new::<D>(b"test", message_count as u32);
    let secret = SecretKey::rand(rng, message_count as u32);
    let public = PublicKey::new(&secret, &params);
    let messages = n_rand(rng, message_count).collect();

    (secret, public, params, messages)
}
