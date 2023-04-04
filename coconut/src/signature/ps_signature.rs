use alloc::vec::Vec;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::*;
use ark_std::{cfg_into_iter, rand::RngCore, UniformRand, Zero};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::serde_utils::ArkObjectBytes;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use utils::hashing_utils::projective_group_elem_from_try_and_incr;

use crate::{
    helpers::Pairs,
    setup::{PublicKey, SecretKey, SignatureParams},
    PSError,
};
use utils::{multi_pairing, try_pairs};

type Result<T, E = PSError> = core::result::Result<T, E>;

/// Modified Pointcheval-Sanders signature used in Coconut.
/// This signature can be obtained in two ways:
///
/// - Secret key's owner signs messages
/// - `BlindSignature` gets unblinded
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Signature<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) sigma_1: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) sigma_2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    /// Creates a new signature. The signature generation involves generating a random value for `sigma_1` so different
    /// calls to this method with same messages, signing key and params will give different value
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: &[E::ScalarField],
        SecretKey { x, y }: &SecretKey<E::ScalarField>,
        SignatureParams { g, .. }: &SignatureParams<E>,
    ) -> Result<Self> {
        if messages.is_empty() {
            Err(PSError::NoMessages)?
        }

        let m_y_pairs = try_pairs!(messages, y)
            .map_err(|(received, expected)| PSError::InvalidMessageCount { received, expected })?;

        let r = E::ScalarField::rand(rng);
        // h = g * r
        let h = g.mul_bigint(r.into_bigint());

        Ok(Self::from_sigma_1(h, m_y_pairs, x))
    }

    /// Creates a new signature. The signature generation doesn't involve generating a random value but
    /// the messages are hashed to get a pseudorandom value for `sigma_1`. Hence different calls to this method
    /// with same messages and signing key will give same value
    pub fn new_deterministic<D: Digest>(
        messages: &[E::ScalarField],
        SecretKey { x, y }: &SecretKey<E::ScalarField>,
    ) -> Result<Self> {
        if messages.is_empty() {
            Err(PSError::NoMessages)?
        }

        let m_y_pairs = try_pairs!(messages, y)
            .map_err(|(received, expected)| PSError::InvalidMessageCount { received, expected })?;

        let messages: Vec<_> = cfg_into_iter!(messages)
            .map(|field| field.into_bigint().to_bytes_be())
            .collect();

        let mut digest = D::new();
        for msg in messages {
            digest.update(msg);
        }
        let bytes = digest.finalize();
        let h = projective_group_elem_from_try_and_incr::<E::G1Affine, D>(&bytes);

        Ok(Self::from_sigma_1(h, m_y_pairs, x))
    }

    /// Verifies a signature. Can verify aggregated signature and unblinded signature received from a signer as well.
    pub fn verify(
        &self,
        messages: &[E::ScalarField],
        PublicKey {
            alpha_tilde,
            beta_tilde,
            ..
        }: &PublicKey<E>,
        &SignatureParams { g_tilde, .. }: &SignatureParams<E>,
    ) -> Result<()> {
        if messages.is_empty() {
            Err(PSError::NoMessages)?
        }

        // `\sum_{i}(beta_tilde_{i} * m_{i})`
        let beta_tilde_mul_m = try_pairs!(beta_tilde, messages)
            .map_err(|(expected, received)| PSError::InvalidMessageCount { received, expected })?
            .msm();

        self.verify_pairing(beta_tilde_mul_m + alpha_tilde, g_tilde)
    }

    /// Checks if a signature has zero elements. A valid signature should not have zero elements.
    pub fn is_zero(&self) -> bool {
        self.sigma_1.is_zero() || self.sigma_2.is_zero()
    }

    /// Ensures that `e(sigma_1, p1) == e(sigma_2, p2)` and signature isn't zero.
    pub(crate) fn verify_pairing<P1, P2>(&self, p1: P1, p2: P2) -> Result<()>
    where
        P1: Into<E::G2Prepared>,
        P2: Into<E::G2Prepared>,
    {
        if self.is_zero() {
            Err(PSError::ZeroSignature)?
        }

        let prod = multi_pairing! {
            self.sigma_1, p1;
            -self.sigma_2.into_group(), p2
        };

        if prod.is_zero() {
            Ok(())
        } else {
            Err(PSError::PairingCheckFailed)
        }
    }

    pub(crate) fn combine<S1, S2>(sigma_1: S1, sigma_2: S2) -> Self
    where
        S1: Into<E::G1Affine>,
        S2: Into<E::G1Affine>,
    {
        Self {
            sigma_1: sigma_1.into(),
            sigma_2: sigma_2.into(),
        }
    }

    pub(crate) fn split(&self) -> (E::G1Affine, E::G1Affine) {
        (self.sigma_1, self.sigma_2)
    }

    /// Generates signature when first element of signature tuple is given.
    ///
    /// `h * (x + \sum{j}(m_{j} * y_{j}))`
    fn from_sigma_1(
        h: E::G1,
        m_y_pairs: Pairs<E::ScalarField, E::ScalarField>,
        &x: &E::ScalarField,
    ) -> Self {
        let sigma_1 = h;
        let sigma_2 = h * cfg_into_iter!(m_y_pairs)
            .map(|(&message, &sec_key_y)| sec_key_y * message)
            .chain(utils::aliases::iter::once(x))
            .sum::<E::ScalarField>();

        Self::combine(sigma_1, sigma_2)
    }
}

#[cfg(test)]
mod tests {
    use crate::{helpers::rand, setup::test_setup};

    use super::*;
    use ark_bls12_381::Bls12_381;
    type G1 = <Bls12_381 as Pairing>::G1;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    #[test]
    fn test_signature_all_known_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);
        for i in 1..10 {
            let count_msgs = (i % 5) + 1;
            let (sk, pk, params, msgs) =
                test_setup::<Bls12_381, Blake2b512, _>(&mut rng, count_msgs);

            let sig = Signature::new(&mut rng, msgs.as_slice(), &sk, &params).unwrap();

            sig.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn test_deterministic_signature_all_known_messages() {
        for i in 1..10 {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (sk, pk, params, msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, i);

            let sig = Signature::new_deterministic::<Blake2b512>(msgs.as_slice(), &sk).unwrap();
            sig.verify(&msgs, &pk, &params).unwrap();
        }
    }

    #[test]
    fn valid_signature_other_pubkey() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk1, pk1, _params, _msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);
        let (_sk2, pk2, params, msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);

        let sig = Signature::new(&mut rng, &msgs, &sk1, &params).unwrap();
        assert!(sig.verify(&msgs, &pk2, &params).is_err());
        assert!(sig.verify(&msgs, &pk1, &params).is_ok());

        let sig = Signature::new_deterministic::<Blake2b512>(&msgs, &sk1).unwrap();
        assert!(sig.verify(&msgs, &pk2, &params).is_err());
        assert!(sig.verify(&msgs, &pk1, &params).is_ok());
    }

    #[test]
    fn no_msgs() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, _pk, params, _msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);

        assert_eq!(
            Signature::<Bls12_381>::new_deterministic::<Blake2b512>(&[], &sk),
            Err(PSError::NoMessages)
        );
        assert_eq!(
            Signature::new(&mut rng, &[], &sk, &params),
            Err(PSError::NoMessages)
        );
    }

    #[test]
    fn zero_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (_, pk, params, msgs) = test_setup::<Bls12_381, Blake2b512, _>(&mut rng, 1);

        assert_eq!(
            Signature::combine::<G1, G1>(Zero::zero(), rand(&mut rng)).verify(&msgs, &pk, &params),
            Err(PSError::ZeroSignature)
        );
        assert_eq!(
            Signature::combine::<G1, G1>(rand(&mut rng), Zero::zero()).verify(&msgs, &pk, &params),
            Err(PSError::ZeroSignature)
        );

        assert_eq!(
            Signature::combine::<G1, G1>(Zero::zero(), Zero::zero()).verify(&msgs, &pk, &params),
            Err(PSError::ZeroSignature)
        );
    }
}
