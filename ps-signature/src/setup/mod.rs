use alloc::vec::Vec;

pub mod keygen;
pub mod keypair;
pub mod signature_params;

pub use keypair::*;
pub use signature_params::*;

#[allow(clippy::type_complexity)]
pub fn test_setup<E: ark_ec::pairing::Pairing, D: digest::Digest, R: ark_std::rand::RngCore>(
    rng: &mut R,
    message_count: usize,
) -> (
    SecretKey<E::ScalarField>,
    PublicKey<E>,
    SignatureParams<E>,
    Vec<E::ScalarField>,
) {
    use crate::helpers::n_rand;

    let params = SignatureParams::new::<D>(b"test", message_count);
    let secret = SecretKey::rand(rng, message_count);
    let public = PublicKey::new(&secret, &params);
    let messages = n_rand(rng, message_count).collect();

    (secret, public, params, messages)
}
