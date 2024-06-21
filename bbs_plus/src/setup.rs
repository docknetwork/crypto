#![allow(non_snake_case)]

//! Keys and setup parameters
//! # Examples
//!
//! Creating signature parameters and keypair:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use blake2::Blake2b512;
//! use bbs_plus::setup::{SignatureParamsG1, SignatureParamsG2, KeypairG1, KeypairG2, PublicKeyG2, SignatureParams23G1};
//!
//! // For BBS+ signatures
//!
//! let params_g1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_g2 = SignatureParamsG2::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_g1_1 = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(&[1, 2, 3, 4], 5);
//! let params_g2_1 = SignatureParamsG2::<Bls12_381>::new::<Blake2b512>(&[1, 2, 3, 4], 5);
//!
//! let keypair_g2 = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params_g1);
//! let keypair_g1 = KeypairG1::<Bls12_381>::generate_using_rng(&mut rng, &params_g2);
//!
//! // Generate keypair using a secret `seed`. The same seed will return same keypair. The seed
//! // is hashed (along with other things) using the given hash function, the example below use Blake2b512
//! // let seed: &[u8] = <Some secret seed>
//! let keypair_g21 = KeypairG2::<Bls12_381>::generate_using_seed::<Blake2b512>(seed, &params_g1);
//!
//! // public and secret key from `Keypair`
//! let sk = keypair_g2.secret_key;
//! let pk = keypair_g2.public_key;
//!
//! // Another way to generate keypair is
//! let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
//! let pk = PublicKeyG2::public_key_from_secret_key(&sk, &params_g1);
//! KeypairG2 {secret_key: sk, public_key: pk}
//!
//! // For BBS signatures
//!
//! // For BBS, sig params are `SignatureParams23G1` but public key is `PublicKeyG2`
//! let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_1 = SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(&[1, 2, 3, 4], 5);
//!
//! let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params);
//! let keypair_1 = KeypairG2::<Bls12_381>::generate_using_seed_and_bbs23_params::<Blake2b512>(seed, &params);
//!
//! let pk = PublicKeyG2::generate_using_secret_key_and_bbs23_params(&sk, &params);
//! KeypairG2 {secret_key: sk, public_key: pk}
//! ```

use crate::error::BBSPlusError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, rand::RngCore, vec::Vec, UniformRand};
use digest::{Digest, DynDigest};

use zeroize::{Zeroize, ZeroizeOnDrop};

use core::iter::once;
use dock_crypto_utils::{
    affine_group_element_from_byte_slices,
    aliases::*,
    concat_slices,
    hashing_utils::{hash_to_field, projective_group_elem_from_try_and_incr},
    iter::*,
    join,
    misc::{n_projective_group_elements, seq_pairs_satisfy},
    serde_utils::*,
    signature::MultiMessageSignatureParams,
    try_iter::CheckLeft,
};
use itertools::process_results;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Secret key used by the signer to sign messages
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField>(#[serde_as(as = "ArkObjectBytes")] pub F);

impl<F: PrimeField> SecretKey<F> {
    pub const DST: &'static [u8] = b"BBS-SIG-KEYGEN-SALT";
    pub fn generate_using_seed<D>(seed: &[u8]) -> Self
    where
        F: PrimeField,
        D: Default + DynDigest + Clone,
    {
        Self(hash_to_field::<F, D>(Self::DST, seed))
    }
}

macro_rules! impl_multi_msg_sig_params {
    ($name: ident) => {
        impl<E: Pairing> MultiMessageSignatureParams for $name<E> {
            fn supported_message_count(&self) -> usize {
                self.h.len()
            }
        }

        impl<E: Pairing> MultiMessageSignatureParams for &$name<E> {
            fn supported_message_count(&self) -> usize {
                self.h.len()
            }
        }
    };
}

macro_rules! impl_sig_params_prepared {
    ( $group_affine:ident, $group_projective:ident) => {
        /// Commit to given messages using the parameters and the given blinding as a Pedersen commitment.
        /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
        /// an error will be returned.
        /// Eg. if given messages `m_i`, `m_j`, and `m_k` in the iterator, the commitment converts messages to
        /// scalars and multiplies them by the parameter curve points:
        /// `params.h_0 * blinding + params.h_i * m_i + params.h_j * m_j + params.h_k * m_k`
        /// Computes using multi-scalar multiplication
        pub fn commit_to_messages<'a, MI>(
            &self,
            indexed_messages_sorted_by_index: MI,
            blinding: &'a E::ScalarField,
        ) -> Result<E::$group_affine, BBSPlusError>
        where
            MI: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        {
            let (bases, scalars): (Vec<_>, Vec<_>) = process_results(
                pair_valid_items_with_slice::<_, _, _, BBSPlusError, _>(
                    indexed_messages_sorted_by_index,
                    CheckLeft(seq_pairs_satisfy(|a, b| a < b)),
                    &self.h,
                ),
                |iter| iter.chain(once((&self.h_0, blinding))).unzip(),
            )?;

            Ok(E::$group_projective::msm_unchecked(&bases, &scalars).into_affine())
        }

        /// Compute `b` from the paper (equivalently 'A*{e+x}').
        /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
        /// an error will be returned.
        /// Commits to the given messages and adds `self.g1` to it,
        /// `b = g_1 + h_0 * s + sum(h_i * m_i)` for all indices `i` in the map.
        pub fn b<'a, MI>(
            &self,
            indexed_messages_sorted_by_index: MI,
            s: &'a E::ScalarField,
        ) -> Result<E::$group_projective, BBSPlusError>
        where
            MI: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        {
            let commitment = self.commit_to_messages(indexed_messages_sorted_by_index, s)?;
            Ok(commitment + self.g1)
        }
    };
}

macro_rules! impl_sig_params_prepared_bbs23 {
    ( $group_affine:ident, $group_projective:ident) => {
        /// Commit to given messages using the parameters and the given blinding as a Pedersen commitment.
        /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
        /// an error will be returned.
        /// Eg. if given messages `m_i`, `m_j`, and `m_k` in the iterator, the commitment converts messages to
        /// scalars and multiplies them by the parameter curve points:
        /// `params.h_i * m_i + params.h_j * m_j + params.h_k * m_k`
        /// Computes using multi-scalar multiplication
        pub fn commit_to_messages<'a, MI>(
            &self,
            indexed_messages_sorted_by_index: MI,
        ) -> Result<E::$group_affine, BBSPlusError>
        where
            MI: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        {
            let (bases, scalars): (Vec<_>, Vec<_>) = process_results(
                pair_valid_items_with_slice::<_, _, _, BBSPlusError, _>(
                    indexed_messages_sorted_by_index,
                    CheckLeft(seq_pairs_satisfy(|a, b| a < b)),
                    &self.h,
                ),
                |iter| iter.unzip(),
            )?;

            Ok(E::$group_projective::msm_unchecked(&bases, &scalars).into_affine())
        }

        /// Compute `b` from the paper (equivalently 'A*{e+x}').
        /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
        /// an error will be returned.
        /// Commits to the given messages and adds `self.g1` to it,
        /// `b = g_1 + + sum(h_i * m_i)` for all indices `i` in the map.
        pub fn b<'a, MI>(
            &self,
            indexed_messages_sorted_by_index: MI,
        ) -> Result<E::$group_projective, BBSPlusError>
        where
            MI: IntoIterator<Item = (usize, &'a E::ScalarField)>,
        {
            let commitment = self.commit_to_messages(indexed_messages_sorted_by_index)?;
            Ok(commitment + self.g1)
        }
    };
}

macro_rules! impl_sig_params {
    ( $name:ident, $group_affine:ident, $group_projective:ident, $other_group_affine:ident, $other_group_projective:ident ) => {
        /// BBS+ signature params used while signing and verifying. Also used when proving knowledge of signature.
        /// Every signer _can_ create his own params but several signers _can_ share the same parameters if
        /// signing messages of the same size and still have their own public keys.
        /// Size of parameters is proportional to the number of messages
        #[serde_as]
        #[derive(
            Clone,
            PartialEq,
            Eq,
            Debug,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct $name<E: Pairing> {
            #[serde_as(as = "ArkObjectBytes")]
            pub g1: E::$group_affine,
            #[serde_as(as = "ArkObjectBytes")]
            pub g2: E::$other_group_affine,
            #[serde_as(as = "ArkObjectBytes")]
            pub h_0: E::$group_affine,
            /// Vector of size same as the size of multi-message that needs to be signed.
            #[serde_as(as = "Vec<ArkObjectBytes>")]
            pub h: Vec<E::$group_affine>,
        }

        impl<E: Pairing> $name<E> {
            /// Generate params by hashing a known string. The hash function is vulnerable to timing
            /// attack but since all this is public knowledge, it is fine.
            /// This is useful if people need to be convinced that the discrete log of group elements wrt each other is not known.
            pub fn new<D: Digest>(label: &[u8], message_count: u32) -> Self {
                assert_ne!(message_count, 0);

                let ((h, [g1, h_0]), g2) = join!(
                    {
                        let g1 = projective_group_elem_from_try_and_incr::<E::$group_affine, D>(
                            &concat_slices!(label, b" : g1"),
                        );
                        let h_bytes = concat_slices!(label, b" : h_");
                        // h_i for i in 0 to message_count
                        let h = n_projective_group_elements::<E::$group_affine, D>(
                            0..message_count + 1,
                            &h_bytes,
                        );
                        let g1_and_h: Vec<_> = iter::once(g1).chain(h).collect();

                        // Convert all to affine
                        let mut normalized_g1_and_h =
                            E::$group_projective::normalize_batch(&g1_and_h);

                        (
                            normalized_g1_and_h.split_off(2),
                            <[_; 2]>::try_from(normalized_g1_and_h).unwrap(),
                        )
                    },
                    affine_group_element_from_byte_slices!(label, b" : g2")
                );

                Self { g1, g2, h_0, h }
            }

            /// Generate params using a random number generator
            pub fn generate_using_rng<R>(rng: &mut R, message_count: u32) -> Self
            where
                R: RngCore,
            {
                assert_ne!(message_count, 0);
                let h = (0..message_count)
                    .into_iter()
                    .map(|_| E::$group_projective::rand(rng))
                    .collect::<Vec<E::$group_projective>>();
                Self {
                    g1: E::$group_affine::rand(rng),
                    g2: E::$other_group_affine::rand(rng),
                    h_0: E::$group_affine::rand(rng),
                    h: E::$group_projective::normalize_batch(&h),
                }
            }

            /// Check that all group elements are non-zero (returns false if any element is zero).
            /// A verifier on receiving these parameters must first check that they are valid and only
            /// then use them for any signature or proof of knowledge of signature verification.
            pub fn is_valid(&self) -> bool {
                !(self.g1.is_zero()
                    || self.g2.is_zero()
                    || self.h_0.is_zero()
                    || cfg_iter!(self.h).any(|v| v.is_zero()))
            }

            impl_sig_params_prepared!($group_affine, $group_projective);
        }
    };
}

macro_rules! impl_public_key_generation {
    ($gen_function_name: ident, $params:ident) => {
        /// Generate public key from given secret key and signature parameter g_2
        pub fn $gen_function_name(
            secret_key: &SecretKey<E::ScalarField>,
            params: &$params<E>,
        ) -> Self {
            Self(params.g2.mul_bigint(secret_key.0.into_bigint()).into())
        }
    };
}

macro_rules! impl_public_key {
    ( $name:ident, $group:ident, $params:ident ) => {
        /// Public key of the signer. The signer can use the same public key with different
        /// signature parameters to sign different multi-messages, provided that parameter
        /// `g2` is consistent with the 'g2' used to generate the public key.
        #[serde_as]
        #[derive(
            Clone,
            PartialEq,
            Eq,
            Debug,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct $name<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub <E as Pairing>::$group);

        impl<E: Pairing> $name<E>
        where
            E: Pairing,
        {
            impl_public_key_generation!(generate_using_secret_key, $params);

            /// Public key shouldn't be 0. A verifier on receiving this must first check that its
            /// valid and only then use it for any signature or proof of knowledge of signature verification.
            pub fn is_valid(&self) -> bool {
                !self.0.is_zero()
            }
        }
    };
}

macro_rules! impl_keypair_generation {
    ( $gen_using_seed_fn_name:ident, $gen_using_rng_fn_name:ident, $gen_using_sk_fn_name:ident, $pk: ident, $params:ident ) => {
        pub fn $gen_using_seed_fn_name<D>(seed: &[u8], params: &$params<E>) -> Self
        where
            D: DynDigest + Default + Clone,
        {
            let secret_key = SecretKey::<E::ScalarField>::generate_using_seed::<D>(seed);
            let public_key = $pk::$gen_using_sk_fn_name(&secret_key, params);
            Self {
                secret_key,
                public_key,
            }
        }

        pub fn $gen_using_rng_fn_name<R: RngCore>(rng: &mut R, params: &$params<E>) -> Self {
            let secret_key = SecretKey(E::ScalarField::rand(rng));
            let public_key = $pk::$gen_using_sk_fn_name(&secret_key, params);
            Self {
                secret_key,
                public_key,
            }
        }
    };
}

macro_rules! impl_keypair {
    ( $name:ident, $group:ident, $pk: ident, $params:ident ) => {
        #[derive(
            Clone,
            Debug,
            Eq,
            PartialEq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
            Zeroize,
            ZeroizeOnDrop,
        )]
        #[serde(bound = "")]
        pub struct $name<E: Pairing> {
            pub secret_key: SecretKey<E::ScalarField>,
            #[zeroize(skip)]
            pub public_key: $pk<E>,
        }

        /// Create a secret key and corresponding public key
        impl<E: Pairing> $name<E> {
            impl_keypair_generation!(
                generate_using_seed,
                generate_using_rng,
                generate_using_secret_key,
                $pk,
                $params
            );
        }
    };
}

impl_sig_params!(SignatureParamsG1, G1Affine, G1, G2Affine, G2);
impl_multi_msg_sig_params!(SignatureParamsG1);
impl_sig_params!(SignatureParamsG2, G2Affine, G2, G1Affine, G1);
impl_multi_msg_sig_params!(SignatureParamsG2);
impl_public_key!(PublicKeyG2, G2Affine, SignatureParamsG1);
impl_public_key!(PublicKeyG1, G1Affine, SignatureParamsG2);
impl_keypair!(KeypairG2, G2Projective, PublicKeyG2, SignatureParamsG1);
impl_keypair!(KeypairG1, G1Projective, PublicKeyG1, SignatureParamsG2);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedSignatureParamsG1<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g1: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g2: E::G2Prepared,
    #[serde_as(as = "ArkObjectBytes")]
    pub h_0: E::G1Affine,
    /// Vector of size same as the size of multi-message that needs to be signed.
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub h: Vec<E::G1Affine>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedPublicKeyG2<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub E::G2Prepared);

impl<E: Pairing> From<SignatureParamsG1<E>> for PreparedSignatureParamsG1<E> {
    fn from(params: SignatureParamsG1<E>) -> Self {
        Self {
            g1: params.g1,
            g2: E::G2Prepared::from(params.g2),
            h_0: params.h_0,
            h: params.h,
        }
    }
}

impl_multi_msg_sig_params!(PreparedSignatureParamsG1);

impl<E: Pairing> PreparedSignatureParamsG1<E> {
    impl_sig_params_prepared!(G1Affine, G1);
}

impl<E: Pairing> From<PublicKeyG2<E>> for PreparedPublicKeyG2<E> {
    fn from(pk: PublicKeyG2<E>) -> Self {
        Self(E::G2Prepared::from(pk.0))
    }
}

/// BBS signature params used for signing, verifying and proving knowledge of signature.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SignatureParams23G1<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g1: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g2: E::G2Affine,
    /// Vector of size same as the size of multi-message that needs to be signed.
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub h: Vec<E::G1Affine>,
}

/// Signature params for BBS signatures with G2 element prepared for pairing
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedSignatureParams23G1<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g1: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g2: E::G2Prepared,
    /// Vector of size same as the size of multi-message that needs to be signed.
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub h: Vec<E::G1Affine>,
}

impl<E: Pairing> SignatureParams23G1<E> {
    /// Generate params by hashing a known string. The hash function is vulnerable to timing
    /// attack but since all this is public knowledge, it is fine.
    /// This is useful if people need to be convinced that the discrete log of group elements wrt each other is not known.
    pub fn new<D: Digest>(label: &[u8], message_count: u32) -> Self {
        assert_ne!(message_count, 0);
        // Group element by hashing `label`||`g1`, `label`||`g2` and `label`||`h_i` for i in 1 to message_count.
        let (g1, g2, h) = join!(
            affine_group_element_from_byte_slices!(label, b" : g1"),
            affine_group_element_from_byte_slices!(label, b" : g2"),
            {
                let h: Vec<_> = n_projective_group_elements::<E::G1Affine, D>(
                    1..message_count + 1,
                    &concat_slices!(label, b" : h_"),
                )
                .collect();
                E::G1::normalize_batch(&h)
            }
        );

        Self { g1, g2, h }
    }

    /// Generate params using a random number generator
    pub fn generate_using_rng<R>(rng: &mut R, message_count: u32) -> Self
    where
        R: RngCore,
    {
        assert_ne!(message_count, 0);
        let h = (0..message_count)
            .map(|_| E::G1::rand(rng))
            .collect::<Vec<E::G1>>();
        Self {
            g1: E::G1::rand(rng).into(),
            g2: E::G2::rand(rng).into(),
            h: E::G1::normalize_batch(&h),
        }
    }

    /// Check that all group elements are non-zero (returns false if any element is zero).
    /// A verifier on receiving these parameters must first check that they are valid and only
    /// then use them for any signature or proof of knowledge of signature verification.
    pub fn is_valid(&self) -> bool {
        !(self.g1.is_zero() || self.g2.is_zero() || cfg_iter!(self.h).any(|v| v.is_zero()))
    }

    impl_sig_params_prepared_bbs23!(G1Affine, G1);
}

impl_multi_msg_sig_params!(SignatureParams23G1);

impl<E: Pairing> From<SignatureParams23G1<E>> for PreparedSignatureParams23G1<E> {
    fn from(params: SignatureParams23G1<E>) -> Self {
        Self {
            g1: params.g1,
            g2: E::G2Prepared::from(params.g2),
            h: params.h,
        }
    }
}

impl<E: Pairing> PreparedSignatureParams23G1<E> {
    impl_sig_params_prepared_bbs23!(G1Affine, G1);
}

impl_multi_msg_sig_params!(PreparedSignatureParams23G1);

impl<E: Pairing> PublicKeyG2<E> {
    impl_public_key_generation!(
        generate_using_secret_key_and_bbs23_params,
        SignatureParams23G1
    );
}

impl<E: Pairing> KeypairG2<E> {
    impl_keypair_generation!(
        generate_using_seed_and_bbs23_params,
        generate_using_rng_and_bbs23_params,
        generate_using_secret_key_and_bbs23_params,
        PublicKeyG2,
        SignatureParams23G1
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::{
        compute_random_oracle_challenge,
        discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    };

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    macro_rules! test_serz_des {
        ($keypair:ident, $public_key:ident, $params:ident, $rng:ident, $message_count: ident, $fn_name: ident) => {
            let params = $params::<Bls12_381>::generate_using_rng(&mut $rng, $message_count);
            test_serialization!($params<Bls12_381>, params);

            let keypair = $keypair::<Bls12_381>::$fn_name(&mut $rng, &params);
            test_serialization!($keypair<Bls12_381>, keypair);

            let pk = keypair.public_key.clone();
            let sk = keypair.secret_key.clone();
            test_serialization!($public_key<Bls12_381>, pk);
            test_serialization!(SecretKey<<Bls12_381 as Pairing>::ScalarField>, sk);
        };
    }

    macro_rules! test_params {
        ($params:ident, $message_count: ident) => {
            let label_1 = "test1".as_bytes();
            let params_1 = $params::<Bls12_381>::new::<Blake2b512>(&label_1, $message_count);
            assert!(params_1.is_valid());
            assert_eq!(params_1.h.len(), $message_count as usize);

            // Same label should generate same params
            let params_1_again = $params::<Bls12_381>::new::<Blake2b512>(&label_1, $message_count);
            assert_eq!(params_1_again, params_1);

            // Different label should generate different params
            let label_2 = "test2".as_bytes();
            let params_2 = $params::<Bls12_381>::new::<Blake2b512>(&label_2, $message_count);
            assert_ne!(params_1, params_2);
        };
    }

    macro_rules! test_keypair {
        ($keypair:ident, $public_key:ident, $params:ident, $seed_fn_name: ident, $sk_fn_name: ident) => {
            let params = $params::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), 5);
            let seed = [0, 1, 2, 10, 11];

            let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
            assert_eq!(sk, SecretKey::generate_using_seed::<Blake2b512>(&seed));

            let pk = $public_key::<Bls12_381>::$sk_fn_name(&sk, &params);

            let keypair = $keypair::<Bls12_381>::$seed_fn_name::<Blake2b512>(&seed, &params);
            assert_eq!(
                keypair,
                $keypair {
                    secret_key: sk.clone(),
                    public_key: pk
                }
            );
            drop(sk);
            drop(keypair);
        };
    }

    #[test]
    fn keypair() {
        test_keypair!(
            KeypairG2,
            PublicKeyG2,
            SignatureParamsG1,
            generate_using_seed,
            generate_using_secret_key
        );
        test_keypair!(
            KeypairG1,
            PublicKeyG1,
            SignatureParamsG2,
            generate_using_seed,
            generate_using_secret_key
        );
        test_keypair!(
            KeypairG2,
            PublicKeyG2,
            SignatureParams23G1,
            generate_using_seed_and_bbs23_params,
            generate_using_secret_key_and_bbs23_params
        );
    }

    #[test]
    fn serz_deserz() {
        // Test serialization of keypair, secret key, public key and signature params
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        test_serz_des!(
            KeypairG2,
            PublicKeyG2,
            SignatureParamsG1,
            rng,
            message_count,
            generate_using_rng
        );
        test_serz_des!(
            KeypairG1,
            PublicKeyG1,
            SignatureParamsG2,
            rng,
            message_count,
            generate_using_rng
        );
        test_serz_des!(
            KeypairG2,
            PublicKeyG2,
            SignatureParams23G1,
            rng,
            message_count,
            generate_using_rng_and_bbs23_params
        );
    }

    #[test]
    fn params_deterministically() {
        // Test generation of signature params deterministically.
        let message_count = 10;
        test_params!(SignatureParamsG1, message_count);
        test_params!(SignatureParamsG2, message_count);
        test_params!(SignatureParams23G1, message_count);
    }

    #[test]
    fn proof_of_knowledge_of_public_key() {
        macro_rules! check {
            ($group_affine:ident, $public_key:ident, $params:ident) => {
                let mut rng = StdRng::seed_from_u64(0u64);
                let params = $params::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), 5);
                let seed = [0, 1, 2, 10, 11];
                let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
                let pk = $public_key::<Bls12_381>::generate_using_secret_key(&sk, &params);

                let base = &params.g2;
                let witness = sk.0.clone();
                let blinding = Fr::rand(&mut rng);

                let protocol =
                    PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        witness, blinding, base,
                    );

                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(base, &pk.0, &mut chal_contrib_prover)
                    .unwrap();

                test_serialization!(
                    PokDiscreteLogProtocol<<Bls12_381 as Pairing>::$group_affine>,
                    protocol
                );

                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
                let proof = protocol.gen_proof(&challenge_prover);

                let mut chal_contrib_verifier = vec![];
                proof
                    .challenge_contribution(base, &pk.0, &mut chal_contrib_verifier)
                    .unwrap();

                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);
                assert!(proof.verify(&pk.0, base, &challenge_verifier));
                assert_eq!(chal_contrib_prover, chal_contrib_verifier);
                assert_eq!(challenge_prover, challenge_verifier);

                test_serialization!(PokDiscreteLog<<Bls12_381 as Pairing>::$group_affine>, proof);
            };
        }

        check!(G2Affine, PublicKeyG2, SignatureParamsG1);
        check!(G1Affine, PublicKeyG1, SignatureParamsG2);
    }
}
