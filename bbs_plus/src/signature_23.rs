//! BBS signature and verification. Signature is in group G1.

use crate::{
    error::BBSPlusError,
    setup::{PreparedPublicKeyG2, PreparedSignatureParams23G1, SecretKey, SignatureParams23G1},
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{fields::Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::BTreeMap, fmt::Debug, ops::Mul, rand::RngCore, vec::Vec, UniformRand, Zero,
};
use dock_crypto_utils::{expect_equality, serde_utils::*, signature::MultiMessageSignatureParams};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BBS signature created by the signer after signing a multi-message
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct Signature23G1<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub e: E::ScalarField,
}

impl<E: Pairing> Signature23G1<E> {
    /// Create a new signature with all messages known to the signer.
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: &[E::ScalarField],
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams23G1<E>,
    ) -> Result<Self, BBSPlusError> {
        if messages.is_empty() {
            return Err(BBSPlusError::NoMessageToSign);
        }
        expect_equality!(
            messages.len(),
            params.supported_message_count(),
            BBSPlusError::MessageCountIncompatibleWithSigParams
        );
        // Create map of msg index (0-based) -> message
        let msg_map: BTreeMap<usize, &E::ScalarField> =
            messages.iter().enumerate().map(|(i, e)| (i, e)).collect();
        // All messages are known so commitment is the zero element
        Self::new_with_committed_messages(rng, &E::G1Affine::zero(), msg_map, sk, params)
    }

    /// Create a new (partially)blind signature where some of the messages are hidden from the
    /// signer under the given commitment. `uncommitted_messages` is the map from message index
    /// to message. Eg if signer while signing a multi-message `[m_0, m_1, m_2, m_3, m_4]` only
    /// knows of messages `m_1`, `m_3` and `m_4` while messages `m_0` and `m_2` are
    /// committed in `commitment` by the requester, `uncommitted_messages` will be the mapping
    /// `(1 -> m_1), (3 -> m_3), (4 -> m_4)`. It is assumed that the signer has verified the requester's
    /// knowledge of `m_0` and `m_2` in the `commitment`
    pub fn new_with_committed_messages<R: RngCore>(
        rng: &mut R,
        commitment: &E::G1Affine,
        uncommitted_messages: BTreeMap<usize, &E::ScalarField>,
        sk: &SecretKey<E::ScalarField>,
        params: &SignatureParams23G1<E>,
    ) -> Result<Self, BBSPlusError> {
        if uncommitted_messages.is_empty() {
            return Err(BBSPlusError::NoMessageToSign);
        }
        // `>` as commitment will have 0 or more messages. In practice, commitment should have
        // at least 1 message
        if uncommitted_messages.len() > params.supported_message_count() {
            return Err(BBSPlusError::MessageCountIncompatibleWithSigParams(
                uncommitted_messages.len(),
                params.supported_message_count(),
            ));
        }

        // `b` is the part of signature on uncommitted messages,
        // i.e. partial_sig = g_1 + sum(h_i * m_i) for all i in uncommitted_messages
        let b = params.b(uncommitted_messages)?;

        let mut e = E::ScalarField::rand(rng);
        while (e + sk.0).is_zero() {
            e = E::ScalarField::rand(rng)
        }
        // 1/(e+x)
        let e_plus_x_inv = (e + sk.0).inverse().unwrap();

        // {commitment + b} * {1/(e+x)}
        let commitment_plus_b = b + commitment;
        let A = commitment_plus_b.mul_bigint(e_plus_x_inv.into_bigint());
        Ok(Self {
            A: A.into_affine(),
            e,
        })
    }

    /// Checks that the elliptic curve point in the signature is non-zero
    pub fn is_non_zero(&self) -> bool {
        !self.A.is_zero()
    }

    /// Basic validations before signature verification like there is at-least 1 message, the
    /// number of messages are supported by params, signature is non-zero. Returns value to be
    /// used in pairing check
    pub fn pre_verify(
        &self,
        messages: &[E::ScalarField],
        params: &PreparedSignatureParams23G1<E>,
    ) -> Result<E::G1, BBSPlusError> {
        if messages.is_empty() {
            return Err(BBSPlusError::NoMessageToSign);
        }
        expect_equality!(
            messages.len(),
            params.supported_message_count(),
            BBSPlusError::MessageCountIncompatibleWithSigParams
        );
        if !self.is_non_zero() {
            return Err(BBSPlusError::ZeroSignature);
        }
        params.b(messages.iter().enumerate())
    }
}

impl<E: Pairing> Signature23G1<E> {
    /// Verify the validity of the signature. Assumes that the public key and parameters
    /// have been validated already.
    pub fn verify(
        &self,
        messages: &[E::ScalarField],
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        // The pairing check is `e(A, pk + g2*e) == e(b, g2)` which can be written as `e(A, pk)*e(A, g2*e) == e(b, g2)`.
        // Simplifying more `e(A, pk)*e(A*e, g2) == e(b, g2)` ==> `e(A, pk)*e(A*e, g2)*e(-b, g2) == 1` => `e(A, pk)*e(A*e - b, g2) == 1`.
        let b = self.pre_verify(messages, &params)?;
        // Aeb = A*e - b
        let Aeb = self.A.mul(self.e) - b;
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.A),
                E::G1Prepared::from(Aeb.into_affine()),
            ],
            [pk.into().0, params.g2],
        )
        .is_zero()
        {
            return Err(BBSPlusError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{setup::KeypairG2, test_serialization};
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn signature_verification() {
        // Test signing and verification
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 20;
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, message_count);
        let keypair =
            KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params);

        let start = Instant::now();
        // All messages are known to signer
        let sig =
            Signature23G1::<Bls12_381>::new(&mut rng, &messages, &keypair.secret_key, &params)
                .unwrap();
        println!(
            "Time to sign multi-message of size {} is {:?}",
            message_count,
            start.elapsed()
        );

        let (verif_params, verif_pk) = (
            PreparedSignatureParams23G1::from(params.clone()),
            PreparedPublicKeyG2::from(keypair.public_key.clone()),
        );

        let mut zero_sig = sig.clone();
        zero_sig.A = G1Affine::zero();
        assert!(zero_sig
            .verify(&messages, verif_pk.clone(), verif_params.clone())
            .is_err());

        let start = Instant::now();
        sig.verify(&messages, verif_pk, verif_params).unwrap();
        println!(
            "Time to verify signature over multi-message of size {} is {:?}",
            message_count,
            start.elapsed()
        );

        test_serialization!(Signature23G1<Bls12_381>, sig);

        drop(sig);
    }
}
