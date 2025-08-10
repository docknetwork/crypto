//! Weak BB signature

use crate::{
    common::{SignatureParams, SignatureParamsWithPairing},
    error::ShortGroupSigError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use core::ops::Neg;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key used by the signer to sign messages
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey<F: PrimeField>(pub F);

/// Public key used to verify signatures
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKeyG2<E: Pairing>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub <E as Pairing>::G2Affine,
);

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKeyG1<G: AffineRepr>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub G,
);

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

impl<E: Pairing> AsRef<E::G2Affine> for PublicKeyG2<E> {
    fn as_ref(&self) -> &E::G2Affine {
        &self.0
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

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignatureG1<E: Pairing>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub E::G1Affine,
);

impl<E: Pairing> SignatureG1<E> {
    /// Create a new signature
    pub fn new(
        message: &E::ScalarField,
        sk: impl AsRef<E::ScalarField>,
        g: impl AsRef<E::G1Affine>,
    ) -> Self {
        Self(gen_sig::<E::G1Affine>(message, sk, g.as_ref()))
    }

    pub fn verify(
        &self,
        message: &E::ScalarField,
        pk: impl AsRef<E::G2Affine>,
        params: &SignatureParams<E>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_given_destructured_params(message, pk, &params.g1, params.g2)
    }

    pub fn verify_given_destructured_params(
        &self,
        message: &E::ScalarField,
        pk: impl AsRef<E::G2Affine>,
        g1: &E::G1Affine,
        g2: E::G2Affine,
    ) -> Result<(), ShortGroupSigError> {
        if !self.is_non_zero() {
            return Err(ShortGroupSigError::ZeroSignature);
        }
        // Check e(sig, pk + g2*m) == e(g1, g2) => e(g1, g2) - e(sig, pk + g2*m) == 0 => e(g1, g2) + e(sig, -(pk + g2*m)) == 0
        // gm = -g2*m - g2*x
        let gm = g2 * message.neg() - pk.as_ref();
        if !E::multi_pairing(
            [E::G1Prepared::from(self.0), E::G1Prepared::from(g1)],
            [E::G2Prepared::from(gm), E::G2Prepared::from(g2)],
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
        pk: impl AsRef<E::G2Affine>,
        params: &SignatureParamsWithPairing<E>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_given_destructured_params_with_pairing(message, pk, params.g2, params.g1g2)
    }

    pub fn verify_given_destructured_params_with_pairing(
        &self,
        message: &E::ScalarField,
        pk: impl AsRef<E::G2Affine>,
        g2: E::G2Affine,
        g1g2: PairingOutput<E>,
    ) -> Result<(), ShortGroupSigError> {
        if !self.is_non_zero() {
            return Err(ShortGroupSigError::ZeroSignature);
        }
        // Check e(sig, pk + g2*m) == e(g1, g2)
        // gm = g2*m + g2*x
        let gm = g2 * message + pk.as_ref();
        if E::pairing(E::G1Prepared::from(self.0), E::G2Prepared::from(gm)) != g1g2 {
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

/// Generate weak-BB signature. Useful when working in a non-pairing setting
pub fn gen_sig<G: AffineRepr>(
    message: &G::ScalarField,
    sk: impl AsRef<G::ScalarField>,
    g: &G,
) -> G {
    (*g * ((*sk.as_ref() + message).inverse().unwrap())).into()
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
