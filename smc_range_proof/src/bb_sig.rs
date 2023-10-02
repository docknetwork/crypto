//! BB signature

use crate::error::SmcRangeProofError;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, collections::BTreeSet, ops::Neg, rand::RngCore, vec::Vec, UniformRand,
};
use digest::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

use dock_crypto_utils::{concat_slices, hashing_utils::affine_group_elem_from_try_and_incr};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Public parameters for creating and verifying BB signatures
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureParams<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
}

/// `SignatureParams` with pre-computation done for protocols more efficient
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureParamsWithPairing<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub g2_prepared: E::G2Prepared,
    /// pairing e(g1, g2)
    pub g1g2: PairingOutput<E>,
}

/// Secret key used by the signer to sign messages
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField>(pub F);

/// Public key used to verify signatures
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKeyG2<E: Pairing>(pub <E as Pairing>::G2Affine);

impl<E: Pairing> SignatureParams<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g1 =
            affine_group_elem_from_try_and_incr::<E::G1Affine, D>(&concat_slices![label, b" : g1"]);
        let g2 =
            affine_group_elem_from_try_and_incr::<E::G2Affine, D>(&concat_slices![label, b" : g2"]);
        Self { g1, g2 }
    }

    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self {
            g1: E::G1::rand(rng).into(),
            g2: E::G2::rand(rng).into(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !(self.g1.is_zero() || self.g2.is_zero())
    }
}

impl<E: Pairing> From<SignatureParams<E>> for SignatureParamsWithPairing<E> {
    fn from(params: SignatureParams<E>) -> Self {
        let g1g2 = E::pairing(params.g1, params.g2);
        Self {
            g1: params.g1,
            g2: params.g2,
            g2_prepared: E::G2Prepared::from(params.g2),
            g1g2,
        }
    }
}

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }

    /// Generate secret key which should not be in `0, -1, 2, .. -(base-1)` because during range proof using
    /// base `base`, signature is created over `0, 1, 2, ... base-1`
    pub fn new_for_base<R: RngCore>(rng: &mut R, base: u16) -> Self {
        let mut sk = F::rand(rng);
        let neg_bases = cfg_into_iter!(0..base)
            .map(|b| F::from(b).neg())
            .collect::<BTreeSet<_>>();
        while neg_bases.contains(&sk) {
            sk = F::rand(rng)
        }
        Self(sk)
    }

    pub fn is_valid_for_base(&self, base: u16) -> bool {
        let neg_bases = (0..base).map(|b| F::from(b).neg());
        let position = neg_bases.into_iter().position(|b| b == self.0);
        position.is_none()
    }
}

impl<E: Pairing> PublicKeyG2<E>
where
    E: Pairing,
{
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

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct SignatureG1<E: Pairing>(pub E::G1Affine);

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
    ) -> Result<(), SmcRangeProofError> {
        if !self.is_non_zero() {
            return Err(SmcRangeProofError::ZeroSignature);
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
            return Err(SmcRangeProofError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_given_sig_params_with_pairing(
        &self,
        message: &E::ScalarField,
        pk: &PublicKeyG2<E>,
        params: &SignatureParamsWithPairing<E>,
    ) -> Result<(), SmcRangeProofError> {
        if !self.is_non_zero() {
            return Err(SmcRangeProofError::ZeroSignature);
        }
        // Check e(sig, pk + g2*m) == e(g1, g2)
        // gm = g2*m + g2*x
        let gm = params.g2 * message + pk.0;
        if E::pairing(E::G1Prepared::from(self.0), E::G2Prepared::from(gm)) != params.g1g2 {
            return Err(SmcRangeProofError::InvalidSignature);
        }
        Ok(())
    }

    pub fn is_non_zero(&self) -> bool {
        !self.0.is_zero()
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
    fn secret_key_validation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for base in [2, 4, 8, 16, 32, 64] {
            SecretKey::<Fr>::new_for_base(&mut rng, base);
        }

        // Create secret key as negative of a base
        let sk = SecretKey(Fr::from(32).neg());

        for base in [2, 4, 8, 16] {
            assert!(sk.is_valid_for_base(base));
        }

        for base in [33, 64, 128] {
            assert!(!sk.is_valid_for_base(base));
        }
    }

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
