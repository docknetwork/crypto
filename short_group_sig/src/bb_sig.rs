//! BB signature

use crate::{
    common::{SignatureParams, SignatureParamsWithPairing},
    error::ShortGroupSigError,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    Field, PrimeField, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::DynDigest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key used by the signer to sign messages
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Zeroize,
    ZeroizeOnDrop,
    Serialize,
    Deserialize,
)]
pub struct SecretKey<F: PrimeField>(
    #[serde_as(as = "ArkObjectBytes")] pub F,
    #[serde_as(as = "ArkObjectBytes")] pub F,
);

/// Public key used to verify signatures
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyG2<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub <E as Pairing>::G2Affine,
    #[serde_as(as = "ArkObjectBytes")] pub <E as Pairing>::G2Affine,
);

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng), F::rand(rng))
    }
}

impl<E: Pairing> PublicKeyG2<E> {
    pub fn generate_using_secret_key(
        secret_key: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        Self(
            (params.g2 * secret_key.0).into(),
            (params.g2 * secret_key.1).into(),
        )
    }

    /// Public key shouldn't be 0. A verifier on receiving this must first check that its
    /// valid and only then use it for any signature or proof of knowledge of signature verification.
    pub fn is_valid(&self) -> bool {
        !(self.0.is_zero() || self.1.is_zero())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedPublicKeyG2<E: Pairing>(pub E::G2Prepared, pub E::G2Prepared, pub E::G2Affine);

impl<E: Pairing> From<PublicKeyG2<E>> for PreparedPublicKeyG2<E> {
    fn from(pk: PublicKeyG2<E>) -> Self {
        Self(E::G2Prepared::from(pk.0), E::G2Prepared::from(pk.1), pk.1)
    }
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    CanonicalSerialize,
    CanonicalDeserialize,
    Zeroize,
    ZeroizeOnDrop,
    Serialize,
    Deserialize,
)]
pub struct SignatureG1<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")] pub E::ScalarField,
);

impl<E: Pairing> SignatureG1<E> {
    /// Create a new signature
    pub fn new<R: RngCore>(
        rng: &mut R,
        message: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        let mut r = E::ScalarField::rand(rng);
        while r == ((sk.0 + message) * sk.1.inverse().unwrap()).neg() {
            r = E::ScalarField::rand(rng)
        }
        Self::new_given_randomness(message, r, sk, params)
    }

    /// Create a new deterministic signature. The randomness in the signature comes from a PRF applied on the message
    /// and the secret key.
    pub fn new_deterministic<D: Default + DynDigest + Clone>(
        message: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        let randomness = Self::generate_random_for_message::<D>(message, sk);
        Self::new_given_randomness(message, randomness, sk, params)
    }

    /// Create a new signature with the provided randomness
    pub fn new_given_randomness(
        message: &E::ScalarField,
        randomness: E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        Self(
            (params.g1 * ((sk.0 + message + sk.1 * randomness).inverse().unwrap())).into(),
            randomness,
        )
    }

    pub fn verify(
        &self,
        message: &E::ScalarField,
        pk: &PublicKeyG2<E>,
        params: &SignatureParams<E>,
    ) -> Result<(), ShortGroupSigError> {
        if !self.is_non_zero() {
            return Err(ShortGroupSigError::ZeroSignature);
        }
        // Check e(sig, v1 + g2*m + v2*r) == e(g1, g2) => e(g1, g2) - e(sig, v1 + g2*m + v2*r) == 0 => e(g1, g2) + e(sig, -(v1 + g2*m + v2*r)) == 0
        // gm = -g2*m - v1 - v2*r
        let gm = params.g2 * message.neg() - pk.0 - pk.1 * self.1;
        if !E::multi_pairing(
            [E::G1Prepared::from(self.0), E::G1Prepared::from(params.g1)],
            [E::G2Prepared::from(gm), E::G2Prepared::from(params.g2)],
        )
        .is_zero()
        {
            return Err(ShortGroupSigError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_given_sig_params_with_pairing(
        &self,
        message: &E::ScalarField,
        pk: &PublicKeyG2<E>,
        params: &SignatureParamsWithPairing<E>,
    ) -> Result<(), ShortGroupSigError> {
        if !self.is_non_zero() {
            return Err(ShortGroupSigError::ZeroSignature);
        }
        // Check e(sig, v1 + g2*m + v2*r) == e(g1, g2)
        // gm = g2*m + g2*x
        let gm = params.g2 * message + pk.0 + pk.1 * self.1;
        if E::pairing(E::G1Prepared::from(self.0), E::G2Prepared::from(gm)) != params.g1g2 {
            return Err(ShortGroupSigError::InvalidSignature);
        }
        Ok(())
    }

    pub fn is_non_zero(&self) -> bool {
        !(self.0.is_zero() || self.1.is_zero())
    }

    /// Generate randomness to be used in the signature for a given message
    pub fn generate_random_for_message<D: Default + DynDigest + Clone>(
        message: &E::ScalarField,
        secret_key: &SecretKey<E::ScalarField>,
    ) -> E::ScalarField {
        prf::<E::ScalarField, D>(message, secret_key)
    }
}

/// A PRF (PseudoRandom Function) with key as the signing key. The PRF is computed as `H(sk||message)` where `H` is hash
/// function that outputs a finite field element
pub fn prf<F: PrimeField, D: Default + DynDigest + Clone>(
    message: &F,
    secret_key: &SecretKey<F>,
) -> F {
    let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(b"BB-SIG-RANDOMNESS");
    // bytes = sk.0||sk.1||msg
    let mut bytes = vec![];
    secret_key.0.serialize_compressed(&mut bytes).unwrap();
    secret_key.1.serialize_compressed(&mut bytes).unwrap();
    message.serialize_compressed(&mut bytes).unwrap();
    let r = hasher.hash_to_field(&bytes, 1).pop().unwrap();
    bytes.zeroize();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn signature_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);
        let params_with_pairing = SignatureParamsWithPairing::<Bls12_381>::from(params.clone());
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);

        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&mut rng, &message, &sk, &params);
        sig.verify(&message, &pk, &params).unwrap();
        sig.verify_given_sig_params_with_pairing(&message, &pk, &params_with_pairing)
            .unwrap();

        let sig1 = SignatureG1::new(&mut rng, &message, &sk, &params);
        sig1.verify(&message, &pk, &params).unwrap();
        assert_ne!(sig, sig1);

        let sig2 = SignatureG1::new_deterministic::<Blake2b512>(&message, &sk, &params);
        let sig3 = SignatureG1::new_deterministic::<Blake2b512>(&message, &sk, &params);
        sig2.verify(&message, &pk, &params).unwrap();
        sig3.verify(&message, &pk, &params).unwrap();
        assert_eq!(sig2, sig3);
    }
}
