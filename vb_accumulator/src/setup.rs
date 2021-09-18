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

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField, SquareRootField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    rand::RngCore,
    UniformRand,
};

use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use schnorr_pok::{error::SchnorrError, impl_proof_of_knowledge_of_discrete_log};

use dock_crypto_utils::hashing_utils::{
    field_elem_from_seed, projective_group_elem_from_try_and_incr,
};

/// Secret key for accumulator manager
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<F: PrimeField + SquareRootField>(pub F);

/// Public key for accumulator manager
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<G: AffineCurve>(pub G);

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

impl<F: PrimeField + SquareRootField> SecretKey<F> {
    pub fn generate_using_seed<D>(seed: &[u8]) -> Self
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        Self(field_elem_from_seed::<F, D>(
            seed,
            "VB-ACCUM-KEYGEN-SALT-".as_bytes(),
        ))
    }
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
        let P = projective_group_elem_from_try_and_incr::<E::G1Affine, D>(
            &to_bytes![label, " : P".as_bytes()].unwrap(),
        )
        .into();
        let P_tilde = projective_group_elem_from_try_and_incr::<E::G2Affine, D>(
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
    /// Create a secret key and corresponding public key using seed
    pub fn generate_using_seed<D>(seed: &[u8], setup_params: &SetupParams<E>) -> Self
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let secret_key = SecretKey::<E::Fr>::generate_using_seed::<D>(seed);
        let public_key = Self::public_key_from_secret_key(&secret_key, &setup_params);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a secret key and corresponding public key using given pseudo random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R, setup_params: &SetupParams<E>) -> Self {
        let secret_key = SecretKey(E::Fr::rand(rng));
        let public_key = Self::public_key_from_secret_key(&secret_key, &setup_params);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Generate public key from given secret key and signature parameters
    pub fn public_key_from_secret_key(
        secret_key: &SecretKey<E::Fr>,
        setup_params: &SetupParams<E>,
    ) -> PublicKey<E::G2Affine> {
        PublicKey(setup_params.P_tilde.mul(secret_key.0.into_repr()).into())
    }
}

impl<G: AffineCurve> PublicKey<G> {
    // TODO: Doesn't work. I need to convert PairingEngine's affine curve type to AffineCurve
    /*/// Generate public key from given secret key and signature parameters
    pub fn new_from_secret_key<F: PrimeField + SquareRootField, E: PairingEngine<Fr=F>>(secret_key: &SecretKey<F>, setup_params: &SetupParams<E>) -> Self {
        Self(setup_params.P_tilde.mul(secret_key.0.into_repr()).into())
    }*/

    /// Public key shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.0.is_zero()
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

        let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
        test_serialization!(Keypair, keypair);
        test_serialization!(SecretKey, keypair.secret_key);
        test_serialization!(PublicKey, keypair.public_key);
    }
}
