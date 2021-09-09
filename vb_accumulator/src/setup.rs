#![allow(non_snake_case)]

//! Keys and setup parameters. Described in section 2 of the paper
//! # Examples
//!
//! Creating setup parameters and keypair:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use blake2::Blake2b;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let params_1 = SetupParams::<Bls12_381>::new::<Blake2b>(&[1, 2, 3, 4]);
//!
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//! ```

use crate::utils::group_elem_from_try_and_incr;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField, SquareRootField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    rand::RngCore,
    UniformRand,
};

use digest::Digest;
use schnorr_pok::{error::SchnorrError, impl_proof_of_knowledge_of_discrete_log};

/// Secret key for accumulator manager
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<F: PrimeField + SquareRootField>(pub F);

/// Public key for accumulator manager
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<G: AffineCurve> {
    pub Q_tilde: G,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Keypair<E: PairingEngine> {
    pub secret_key: SecretKey<E::Fr>,
    pub public_key: PublicKey<E::G2Affine>,
}

/// Setup parameters for accumulators
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupParams<E: PairingEngine> {
    pub P: E::G1Affine,
    pub P_tilde: E::G2Affine,
}

impl<E> SetupParams<E>
where
    E: PairingEngine,
{
    /// Generate params using a random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self {
            P: E::G1Projective::rand(rng).into(),
            P_tilde: E::G2Projective::rand(rng).into(),
        }
    }

    /// Generate params by hashing a known string. The hash function is vulnerable to timing
    /// attack but since all this is public knowledge, it is fine.
    /// This is useful if people need to be convinced that the discrete of group elements wrt each other is not known.
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let P = group_elem_from_try_and_incr::<E::G1Affine, D>(
            &to_bytes![label, " : P".as_bytes()].unwrap(),
        )
        .into();
        let P_tilde = group_elem_from_try_and_incr::<E::G2Affine, D>(
            &to_bytes![label, " : P_tilde".as_bytes()].unwrap(),
        )
        .into();
        Self { P, P_tilde }
    }
}

impl<E> Keypair<E>
where
    E: PairingEngine,
{
    /// Create a secret key and corresponding public key
    pub fn generate<R: RngCore>(rng: &mut R, setup_params: &SetupParams<E>) -> Self {
        let secret_key = E::Fr::rand(rng);
        let Q_tilde = setup_params.P_tilde.mul(secret_key.into_repr()).into();
        Self {
            secret_key: SecretKey(secret_key),
            public_key: PublicKey { Q_tilde },
        }
    }
}

// Implement proof of knowledge of secret key in public key

impl_proof_of_knowledge_of_discrete_log!(PoKSecretKeyInPublicKey, PoKSecretKeyInPublicKeyProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b;

    #[test]
    fn setup_serialization() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        test_serialization!(SetupParams, params);

        let params_1 = SetupParams::<Bls12_381>::new::<Blake2b>("test".as_bytes());
        test_serialization!(SetupParams, params_1);

        let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
        test_serialization!(Keypair, keypair);
        test_serialization!(SecretKey, keypair.secret_key);
        test_serialization!(PublicKey, keypair.public_key);
    }
}
