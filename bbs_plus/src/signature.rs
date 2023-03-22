#![allow(non_snake_case)]

//! BBS+ signature and verification as per section 4.3 of the paper
//! # Examples
//!
//! Creating signature and verifying it:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use bbs_plus::setup::{SignatureParamsG1, SignatureParamsG2, KeypairG1, KeypairG2};
//! use bbs_plus::signature::{SignatureG1, SignatureG2};
//!
//! let params_g1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_g2 = SignatureParamsG2::<Bls12_381>::generate_using_rng(&mut rng, 5);
//!
//! let keypair_g2 = KeypairG2::<Bls12_381>::generate(&mut rng, &params_g1);
//! let keypair_g1 = KeypairG1::<Bls12_381>::generate(&mut rng, &params_g2);
//!
//! let pk_g2 = &keypair_g2.public_key;
//! let pk_g1 = &keypair_g1.public_key;
//!
//! // `messages` contains elements of the scalar field
//!
//! // Verifiers should check that the signature parameters and public key are valid before verifying
//! // any signatures. This just needs to be done once when the verifier fetches/receives them.
//!
//! assert!(params_g1.is_valid());
//! assert!(params_g2.is_valid());
//! assert!(pk_g2.is_valid());
//! assert!(pk_g1.is_valid());
//!
//! let sig_g1 = SignatureG1::<Bls12_381>::new(&mut rng, &messages, &keypair_g2.secret_key, &params_g1).unwrap();
//! sig_g1.verify(&messages, pk_g2, &params_g1).unwrap();
//!
//! let sig_g2 = SignatureG2::<Bls12_381>::new(&mut rng, &messages, &keypair_g1.secret_key, &params_g2).unwrap();
//! sig_g2.verify(&messages, pk_g1, &params_g2).unwrap();
//!
//! // Requesting a partially blind signature from the signer, i.e. where signer does not know all the messages
//! // Requester creates a Pedersen commitment over the messages he wants to hide from the signer.
//! // Requester creates a map of message index to message as `committed_messages` and random field element
//! // `blinding` and commits as:
//! let commitment_g1 = params_g1
//!                 .commit_to_messages(committed_messages, &blinding)
//!                 .unwrap();
//!
//! // Its upto the signer to verify that the commitment was created with the correct bases and checking
//! // a proof of knowledge is sufficient for that. Check the `proof_system` crate in this repo on
//! // how to such proof of knowledge, there is test to show this workflow.
//!
//! // Once the signer is satisfied, he creates a blind signature as:
//! let blinded_sig_g1 = SignatureG1::<Bls12_381>::new_with_committed_messages(
//!                 &mut rng,
//!                 &commitment_g1,
//!                 uncommitted_messages,
//!                 &keypair_g2.secret_key,
//!                 &params_g1,
//!             )
//!             .unwrap();
//!
//! // The requester unblinds the signature and verifies it to ensure correct sig.
//! let sig_g1 = blinded_sig_g1.unblind(&blinding);
//! sig_g1.verify(&messages, &keypair_g2.public_key, &params_g1).unwrap();
//!
//! // Similar process is followed to create blind signature is group G2 but the commitment here
//! // would also be in G2 as `commitment_g2`.
//! let commitment_g2 = params_g2
//!                 .commit_to_messages(committed_messages, &blinding)
//!                 .unwrap();
//!
//! // Signer creates blind signature
//! let blinded_sig_g2 = SignatureG2::<Bls12_381>::new_with_committed_messages(
//!                 &mut rng,
//!                 &commitment_g2,
//!                 uncommitted_messages,
//!                 &keypair_g1.secret_key,
//!                 &params_g2,
//!             )
//!             .unwrap();
//!
//!
//! let sig_g2 = blinded_sig_g2.unblind(&blinding);
//! sig_g2.verify(&messages, &keypair_g1.public_key, &params_g2).unwrap();
//! ```

use crate::error::BBSPlusError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{fields::Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, rand::RngCore, vec::Vec, UniformRand, Zero};

use crate::setup::{PublicKeyG1, PublicKeyG2, SecretKey, SignatureParamsG1, SignatureParamsG2};
use ark_std::collections::BTreeMap;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::Zeroize;

macro_rules! impl_signature_struct {
    ( $name:ident, $group:ident ) => {
        /// Signature created by the signer after signing a multi-message
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
        )]
        pub struct $name<E: Pairing> {
            #[serde_as(as = "ArkObjectBytes")]
            pub A: E::$group,
            #[serde_as(as = "ArkObjectBytes")]
            pub e: E::ScalarField,
            #[serde_as(as = "ArkObjectBytes")]
            pub s: E::ScalarField,
        }

        impl<E: Pairing> Zeroize for $name<E> {
            fn zeroize(&mut self) {
                self.A.zeroize();
                self.e.zeroize();
                self.s.zeroize();
            }
        }

        impl<E: Pairing> Drop for $name<E> {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
}

impl_signature_struct!(SignatureG1, G1Affine);
impl_signature_struct!(SignatureG2, G2Affine);

// Macro to do the pairing check in signature verification when signature is in group G1
macro_rules! pairing_check_for_g1_sig {
    ($A:expr, $w:expr, $g2:expr, $k:expr) => {
        E::multi_pairing(
            [E::G1Prepared::from($A), E::G1Prepared::from($k)],
            [E::G2Prepared::from($w), E::G2Prepared::from($g2)],
        )
        .is_zero()
    };
}

// Macro to do the pairing check in signature verification when signature is in group G2
macro_rules! pairing_check_for_g2_sig {
    ($A:expr, $w:expr, $g2:expr, $k:expr) => {
        E::multi_pairing(
            [E::G1Prepared::from($w), E::G1Prepared::from($g2)],
            [E::G2Prepared::from($A), E::G2Prepared::from($k)],
        )
        .is_zero()
    };
}

macro_rules! impl_signature_alg {
    ( $name:ident, $params:ident, $pk:ident, $sig_group_proj:ident, $sig_group_affine:ident, $pairing:tt ) => {
        /// Signature creation and verification
        impl<E: Pairing> $name<E> {
            /// Create a new signature with all messages known to the signer.
            pub fn new<R: RngCore>(
                rng: &mut R,
                messages: &[E::ScalarField],
                sk: &SecretKey<E::ScalarField>,
                params: &$params<E>,
            ) -> Result<Self, BBSPlusError> {
                if messages.is_empty() {
                    return Err(BBSPlusError::NoMessageToSign);
                }
                if messages.len() != params.supported_message_count() {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams(
                        messages.len(),
                        params.supported_message_count(),
                    ));
                }
                // Create map of msg index (0-based) -> message
                let msg_map: BTreeMap<usize, &E::ScalarField> =
                    messages.iter().enumerate().map(|(i, e)| (i, e)).collect();
                // All messages are known so commitment is the zero element
                Self::new_with_committed_messages(
                    rng,
                    &E::$sig_group_affine::zero(),
                    msg_map,
                    sk,
                    params,
                )
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
                commitment: &E::$sig_group_affine,
                uncommitted_messages: BTreeMap<usize, &E::ScalarField>,
                sk: &SecretKey<E::ScalarField>,
                params: &$params<E>,
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

                let s = E::ScalarField::rand(rng);
                // `b` is the part of signature on uncommitted messages,
                // i.e. partial_sig = g_1 + {h_0}*s + sum(h_i * m_i) for all i in uncommitted_messages
                let b = params.b(uncommitted_messages, &s)?;

                let e = E::ScalarField::rand(rng);
                // 1/(e+x)
                let e_plus_x_inv = (e + sk.0).inverse().ok_or(BBSPlusError::CannotInvert0)?;

                // {commitment + b} * {1/(e+x)}
                let commitment_plus_b = b + commitment;
                let A = commitment_plus_b.mul_bigint(e_plus_x_inv.into_bigint());
                Ok(Self {
                    A: A.into_affine(),
                    e,
                    s,
                })
            }

            /// Checks that the elliptic curve point in the signature is non-zero
            pub fn is_non_zero(&self) -> bool {
                !self.A.is_zero()
            }

            /// Used to unblind a blind signature from signer
            pub fn unblind(self, blinding: &E::ScalarField) -> Self {
                Self {
                    A: self.A,
                    s: self.s + blinding,
                    e: self.e,
                }
            }

            /// Verify the validity of the signature. Assumes that the public key and parameters
            /// have been validated already.
            pub fn verify(
                &self,
                messages: &[E::ScalarField],
                pk: &$pk<E>,
                params: &$params<E>,
            ) -> Result<(), BBSPlusError> {
                if messages.is_empty() {
                    return Err(BBSPlusError::NoMessageToSign);
                }
                if messages.len() != params.supported_message_count() {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams(
                        messages.len(),
                        params.supported_message_count(),
                    ));
                }
                if !self.is_non_zero() {
                    return Err(BBSPlusError::ZeroSignature);
                }

                let b = params.b(
                    messages
                        .iter()
                        .enumerate()
                        .collect::<BTreeMap<usize, &E::ScalarField>>(),
                    &self.s,
                )?;
                let g2_e = params.g2.mul_bigint(self.e.into_bigint());
                if !$pairing!(
                    self.A,
                    (g2_e + pk.0).into_affine(), // g2*e + w
                    (-(params.g2.into_group())).into_affine(),
                    b.into_affine()
                ) {
                    return Err(BBSPlusError::InvalidSignature);
                }
                Ok(())
            }
        }
    };
}

impl_signature_alg!(
    SignatureG1,
    SignatureParamsG1,
    PublicKeyG2,
    G1Projective,
    G1Affine,
    pairing_check_for_g1_sig
);
impl_signature_alg!(
    SignatureG2,
    SignatureParamsG2,
    PublicKeyG1,
    G2Projective,
    G2Affine,
    pairing_check_for_g2_sig
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{KeypairG1, KeypairG2};
    use crate::test_serialization;
    use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::collections::HashSet;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    macro_rules! test_sig_verif {
        ($keypair:ident, $params:ident, $sig:ident, $rng:ident, $message_count: ident, $messages: ident, $group: ident) => {
            let params = $params::<Bls12_381>::generate_using_rng(&mut $rng, $message_count);
            let keypair = $keypair::<Bls12_381>::generate_using_rng(&mut $rng, &params);
            let public_key = &keypair.public_key;
            let start = Instant::now();
            // All messages are known to signer
            let sig = $sig::<Bls12_381>::new(&mut $rng, &$messages, &keypair.secret_key, &params)
                .unwrap();
            println!(
                "Time to sign multi-message of size {} is {:?}",
                $message_count,
                start.elapsed()
            );

            // Verifier first checks that public parameters are valid
            assert!(params.is_valid());
            assert!(public_key.is_valid());

            let mut zero_sig = sig.clone();
            zero_sig.A = $group::zero();
            assert!(zero_sig.verify(&$messages, public_key, &params).is_err());

            let start = Instant::now();
            sig.verify(&$messages, public_key, &params).unwrap();
            println!(
                "Time to verify signature over multi-message of size {} is {:?}",
                $message_count,
                start.elapsed()
            );

            drop(sig);

            // 4 messages are not known to signer but are given in a commitment
            let blinding = Fr::rand(&mut $rng);
            // Commit messages with indices 0, 1, 4, 9
            let mut committed_indices = HashSet::new();
            committed_indices.insert(0);
            committed_indices.insert(1);
            committed_indices.insert(4);
            committed_indices.insert(9);

            let committed_messages = committed_indices
                .iter()
                .map(|i| (*i, &$messages[*i]))
                .collect::<BTreeMap<_, _>>();
            let commitment = params
                .commit_to_messages(committed_messages, &blinding)
                .unwrap();

            let mut uncommitted_messages = BTreeMap::new();
            for (i, msg) in $messages.iter().enumerate() {
                if committed_indices.contains(&i) {
                    continue;
                }
                uncommitted_messages.insert(i, msg);
            }

            let blinded_sig = $sig::<Bls12_381>::new_with_committed_messages(
                &mut $rng,
                &commitment,
                uncommitted_messages,
                &keypair.secret_key,
                &params,
            )
            .unwrap();
            // First test should fail since the signature is blinded
            assert!(blinded_sig.verify(&$messages, public_key, &params).is_err());

            let sig = blinded_sig.unblind(&blinding);
            sig.verify(&$messages, public_key, &params).unwrap();

            // sig and blinded_sig have same struct so just checking serialization on sig
            test_serialization!($sig<Bls12_381>, sig);

            drop(sig);
        };
    }

    #[test]
    fn signature_verification() {
        // Test signing and verification
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 20;
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        {
            test_sig_verif!(
                KeypairG2,
                SignatureParamsG1,
                SignatureG1,
                rng,
                message_count,
                messages,
                G1Affine
            );
        }

        {
            test_sig_verif!(
                KeypairG1,
                SignatureParamsG2,
                SignatureG2,
                rng,
                message_count,
                messages,
                G2Affine
            );
        }
    }
}
