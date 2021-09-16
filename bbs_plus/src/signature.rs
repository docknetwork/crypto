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
//! // `messages` contains elements of the scalar field
//!
//! let sig_g1 = SignatureG1::<Bls12_381>::new(&mut rng, &messages, &keypair_g2.secret_key, &params_g1).unwrap();
//! sig_g1.verify(&messages, &keypair_g2.public_key, &params_g1).unwrap();
//!
//! let sig_g2 = SignatureG2::<Bls12_381>::new(&mut rng, &messages, &keypair_g1.secret_key, &params_g2).unwrap();
//! sig_g2.verify(&messages, &keypair_g1.public_key, &params_g2).unwrap();
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
use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{fields::Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt::Debug,
    io::{Read, Write},
    rand::RngCore,
    One, UniformRand, Zero,
};

use crate::setup::{PublicKeyG1, PublicKeyG2, SecretKey, SignatureParamsG1, SignatureParamsG2};
use ark_std::collections::BTreeMap;

// TODO: Zeroize secret key and other cloned/copied elements

macro_rules! impl_signature_struct {
    ( $name:ident, $group:ident ) => {
        /// Signature created by the signer after signing a multi-message
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        pub struct $name<E: PairingEngine> {
            pub A: E::$group,
            pub e: E::Fr,
            pub s: E::Fr,
        }
    };
}

impl_signature_struct!(SignatureG1, G1Affine);
impl_signature_struct!(SignatureG2, G2Affine);

// Macro to do the pairing check in signature verification when signature is in group G1
macro_rules! pairing_check_for_g1_sig {
    ($A:expr, $w:expr, $g2:expr, $k:expr) => {
        E::product_of_pairings(&[
            (E::G1Prepared::from($A), E::G2Prepared::from($w)),
            (E::G1Prepared::from($k), E::G2Prepared::from($g2)),
        ])
        .is_one()
    };
}

// Macro to do the pairing check in signature verification when signature is in group G2
macro_rules! pairing_check_for_g2_sig {
    ($A:expr, $w:expr, $g2:expr, $k:expr) => {
        E::product_of_pairings(&[
            (E::G1Prepared::from($w), E::G2Prepared::from($A)),
            (E::G1Prepared::from($g2), E::G2Prepared::from($k)),
        ])
        .is_one()
    };
}

macro_rules! impl_signature_alg {
    ( $name:ident, $params:ident, $pk:ident, $sig_group_proj:ident, $sig_group_affine:ident, $pairing:tt ) => {
        /// Signature creation and verification
        impl<E: PairingEngine> $name<E> {
            /// Create a new signature with all messages known to the signer.
            pub fn new<R: RngCore>(
                rng: &mut R,
                messages: &[E::Fr],
                sk: &SecretKey<E::Fr>,
                params: &$params<E>,
            ) -> Result<Self, BBSPlusError> {
                if messages.is_empty() {
                    return Err(BBSPlusError::NoMessageToSign);
                }
                if messages.len() != params.max_message_count() {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams);
                }
                // Create map of msg index (0-based) -> message
                let msg_map: BTreeMap<usize, &E::Fr> =
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
                uncommitted_messages: BTreeMap<usize, &E::Fr>,
                sk: &SecretKey<E::Fr>,
                params: &$params<E>,
            ) -> Result<Self, BBSPlusError> {
                if uncommitted_messages.is_empty() {
                    return Err(BBSPlusError::NoMessageToSign);
                }
                // `>` as commitment will have one or more messages (preventing accidents only)
                if uncommitted_messages.len() > params.max_message_count() {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams);
                }

                let s = E::Fr::rand(rng);
                // `b` is the part of signature on uncommitted messages, i.e. partial_sig = g_1{h_0}^s.prod(h_i.m_i) for all i in uncommitted_messages
                let b = params.b(uncommitted_messages, &s)?;

                let e = E::Fr::rand(rng);
                // 1/(e+x)
                let e_plus_x_inv = (e + sk.0).inverse().unwrap();

                // {commitment + b}^{1/(e+x)}
                let commitment_plus_b = b.add_mixed(commitment);
                let A = <E::$sig_group_proj as Group>::mul(&commitment_plus_b, &e_plus_x_inv);
                Ok(Self {
                    A: A.into_affine(),
                    e,
                    s,
                })
            }

            fn is_valid(&self) -> bool {
                !self.A.is_zero()
            }

            /// Used to unblind a blind signature from signer
            pub fn unblind(self, blinding: &E::Fr) -> Self {
                Self {
                    A: self.A,
                    s: self.s + blinding,
                    e: self.e,
                }
            }

            /// Verify the validity of the signature.
            pub fn verify(
                &self,
                messages: &[E::Fr],
                pk: &$pk<E>,
                params: &$params<E>,
            ) -> Result<(), BBSPlusError> {
                if messages.is_empty() {
                    return Err(BBSPlusError::NoMessageToSign);
                }
                if messages.len() != params.max_message_count() {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams);
                }
                if !self.is_valid() {
                    return Err(BBSPlusError::ZeroSignature);
                }

                let b = params.b(
                    messages
                        .iter()
                        .enumerate()
                        .collect::<BTreeMap<usize, &E::Fr>>(),
                    &self.s,
                )?;
                let g2_e = params.g2.mul(self.e.into_repr());
                if !$pairing!(
                    self.A,
                    (g2_e.add_mixed(&pk.w)).into_affine(), // g2^e + w
                    -params.g2,
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
    use ark_bls12_381::Bls12_381;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::collections::HashSet;
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    macro_rules! test_sig_verif {
        ($keypair:ident, $params:ident, $sig:ident, $rng:ident, $message_count: ident, $messages: ident) => {
            let params = $params::<Bls12_381>::generate_using_rng(&mut $rng, $message_count);
            let keypair = $keypair::<Bls12_381>::generate_using_rng(&mut $rng, &params);
            let start = Instant::now();
            // All messages are known to signer
            let sig = $sig::<Bls12_381>::new(&mut $rng, &$messages, &keypair.secret_key, &params)
                .unwrap();
            println!(
                "Time to sign multi-message of size {} is {:?}",
                $message_count,
                start.elapsed()
            );

            let start = Instant::now();
            sig.verify(&$messages, &keypair.public_key, &params)
                .unwrap();
            println!(
                "Time to verify signature over multi-message of size {} is {:?}",
                $message_count,
                start.elapsed()
            );

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
            assert!(blinded_sig
                .verify(&$messages, &keypair.public_key, &params)
                .is_err());

            let sig = blinded_sig.unblind(&blinding);
            sig.verify(&$messages, &keypair.public_key, &params)
                .unwrap();

            // sig and blinded_sig have same struct so just checking on sig
            test_serialization!($sig, sig);
        };
    }

    #[test]
    fn signature_verification() {
        // Test signing and verification
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 20;
        let messages: Vec<Fr> = (0..message_count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect();

        {
            test_sig_verif!(
                KeypairG2,
                SignatureParamsG1,
                SignatureG1,
                rng,
                message_count,
                messages
            );
        }

        {
            test_sig_verif!(
                KeypairG1,
                SignatureParamsG2,
                SignatureG2,
                rng,
                message_count,
                messages
            );
        }
    }
}
