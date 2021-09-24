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
//! // Generate keypair using random number generator
//! let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
//!
//! // Generate keypair using a secret `seed`. The same seed will return same keypair. The seed
//! // is hashed (along with other things) using the given hash function, the example below use Blake2b
//! // let seed: &[u8] = <Some secret seed>
//! let keypair_1 = Keypair::<Bls12_381>::generate_using_seed::<Blake2b>(seed, &params);
//!
//! // Another way to generate keypair is
//! let sk = SecretKey::generate_using_seed::<Blake2b>(&seed);
//! let pk = Keypair::public_key_from_secret_key(&sk, &params);
//! Keypair {secret_key: sk, public_key: pk}
//!
//! ```

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField, SquareRootField, Zero};
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
use dock_crypto_utils::serde_utils::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Secret key for accumulator manager
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SecretKey<F: PrimeField + SquareRootField>(#[serde_as(as = "FieldBytes")] pub F);

/// Public key for accumulator manager
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<G: AffineCurve>(#[serde_as(as = "AffineGroupBytes")] pub G);

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Keypair<E: PairingEngine> {
    pub secret_key: SecretKey<E::Fr>,
    pub public_key: PublicKey<E::G2Affine>,
}

/// Setup parameters for accumulators
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SetupParams<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub P: E::G1Affine,
    #[serde_as(as = "AffineGroupBytes")]
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

    /// Params shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.P.is_zero() && !self.P_tilde.is_zero()
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
    fn keypair() {
        // Same seed generates same keypair
        let params = SetupParams::<Bls12_381>::new::<Blake2b>("test".as_bytes());
        assert!(params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P = <Bls12_381 as PairingEngine>::G1Affine::zero();
        assert!(!invalid_params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P_tilde = <Bls12_381 as PairingEngine>::G2Affine::zero();
        assert!(!invalid_params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P = <Bls12_381 as PairingEngine>::G1Affine::zero();
        invalid_params.P_tilde = <Bls12_381 as PairingEngine>::G2Affine::zero();
        assert!(!invalid_params.is_valid());

        let seed = vec![0, 1, 4, 6, 2, 10];

        let sk = SecretKey::generate_using_seed::<Blake2b>(&seed);
        assert_eq!(sk, SecretKey::generate_using_seed::<Blake2b>(&seed));

        let pk = Keypair::public_key_from_secret_key(&sk, &params);
        assert!(pk.is_valid());
        let mut invalid_pk = pk.clone();
        invalid_pk.0 = <Bls12_381 as PairingEngine>::G2Affine::zero();
        assert!(!invalid_pk.is_valid());

        let keypair = Keypair::generate_using_seed::<Blake2b>(&seed, &params);
        assert_eq!(
            keypair,
            Keypair {
                secret_key: sk,
                public_key: pk
            }
        );
    }

    #[test]
    fn setup_serialization() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        test_serialization!(SetupParams<Bls12_381>, params);

        let params_1 = SetupParams::<Bls12_381>::new::<Blake2b>("test".as_bytes());
        test_serialization!(SetupParams<Bls12_381>, params_1);

        let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
        test_serialization!(Keypair<Bls12_381>, keypair);
        test_serialization!(
            SecretKey<<Bls12_381 as PairingEngine>::Fr>,
            keypair.secret_key
        );
        test_serialization!(
            PublicKey<<Bls12_381 as PairingEngine>::G2Affine>,
            keypair.public_key
        );
    }
}
