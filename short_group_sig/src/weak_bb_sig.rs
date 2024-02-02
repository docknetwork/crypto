//! Weak BB signature

use crate::{
    common::{SignatureParams, SignatureParamsWithPairing},
    error::ShortGroupSigError,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use core::ops::Neg;
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
pub struct SecretKey<F: PrimeField>(pub F);

/// Public key used to verify signatures
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyG2<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub <E as Pairing>::G2Affine);

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyG1<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedPublicKeyG2<E: Pairing>(pub E::G2Prepared);

impl<E: Pairing> From<PublicKeyG2<E>> for PreparedPublicKeyG2<E> {
    fn from(pk: PublicKeyG2<E>) -> Self {
        Self(E::G2Prepared::from(pk.0))
    }
}

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

impl<F: PrimeField> AsRef<F> for SecretKey<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<E: Pairing> PublicKeyG2<E> {
    pub fn generate_using_secret_key(
        secret_key: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        Self((params.g2 * secret_key.0).into())
    }

    /// Public key shouldn't be 0. A verifier on receiving this must first check that its
    /// valid and only then use it for any signature or proof of knowledge of signature verification.
    pub fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }
}

impl<G: AffineRepr> PublicKeyG1<G> {
    pub fn generate_using_secret_key<E: Pairing<G1Affine = G>>(
        secret_key: &SecretKey<G::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        Self((params.g1 * secret_key.0).into())
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
pub struct SignatureG1<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub E::G1Affine);

impl<E: Pairing> SignatureG1<E> {
    /// Create a new signature
    pub fn new(
        message: &E::ScalarField,
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams<E>,
    ) -> Self {
        Self((params.g1 * ((sk.0 + message).inverse().unwrap())).into())
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
        // Check e(sig, pk + g2*m) == e(g1, g2) => e(g1, g2) - e(sig, pk + g2*m) == 0 => e(g1, g2) + e(sig, -(pk + g2*m)) == 0
        // gm = -g2*m - g2*x
        let gm = params.g2 * message.neg() - pk.0;
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
        // Check e(sig, pk + g2*m) == e(g1, g2)
        // gm = g2*m + g2*x
        let gm = params.g2 * message + pk.0;
        if E::pairing(E::G1Prepared::from(self.0), E::G2Prepared::from(gm)) != params.g1g2 {
            return Err(ShortGroupSigError::InvalidSignature);
        }
        Ok(())
    }

    pub fn is_non_zero(&self) -> bool {
        !self.0.is_zero()
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for SignatureG1<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn signature_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);
        let params_with_pairing = SignatureParamsWithPairing::<Bls12_381>::from(params.clone());
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);

        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&message, &sk, &params);
        sig.verify(&message, &pk, &params).unwrap();
        sig.verify_given_sig_params_with_pairing(&message, &pk, &params_with_pairing)
            .unwrap();
    }
}
