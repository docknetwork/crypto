#![allow(non_snake_case)]

//! Keys and setup parameters
//! # Examples
//!
//! Creating signature parameters and keypair:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use blake2::Blake2b;
//! use bbs_plus::setup::{SignatureParamsG1, SignatureParamsG2, KeypairG1, KeypairG2};
//!
//! let params_g1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_g2 = SignatureParamsG2::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let params_g1_1 = SignatureParamsG1::<Bls12_381>::new::<Blake2b>(&[1, 2, 3, 4], 5);
//! let params_g2_1 = SignatureParamsG2::<Bls12_381>::new::<Blake2b>(&[1, 2, 3, 4], 5);
//!
//! let keypair_g2 = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &params_g1);
//! let keypair_g1 = KeypairG1::<Bls12_381>::generate_using_rng(&mut rng, &params_g2);
//! ```

use crate::error::BBSPlusError;
use crate::serde_utils::*;
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField, SquareRootField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::collections::BTreeMap;
use ark_std::{
    fmt,
    fmt::Debug,
    io::{Read, Write},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand, Zero,
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use schnorr_pok::{error::SchnorrError, impl_proof_of_knowledge_of_discrete_log};

use dock_crypto_utils::hashing_utils::{
    field_elem_from_seed, projective_group_elem_from_try_and_incr,
};

use ark_std::marker::PhantomData;
#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;

/// Secret key used by the signer to sign messages
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<F: PrimeField + SquareRootField>(pub F);

impl<F: PrimeField + SquareRootField> Serialize for SecretKey<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(self, &mut bytes).map_err(serde::ser::Error::custom)?;
        // println!("In sk ser={:?}", bytes);
        // serializer.serialize_newtype_struct("SecretKey", &bytes)
        serializer.serialize_bytes(&bytes)
        /*let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for element in bytes {
            seq.serialize_element(&element)?;
        }
        seq.end()*/
    }
}

impl<'a, F: PrimeField + SquareRootField> Deserialize<'a> for SecretKey<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct SkVisitor<F: PrimeField + SquareRootField>(PhantomData<F>);

        impl<'a, F: PrimeField + SquareRootField> Visitor<'a> for SkVisitor<F> {
            type Value = SecretKey<F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected SecretKey")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey<F>, E>
            where
                E: serde::de::Error,
            {
                // println!("in visit_bytes");
                let f =
                    CanonicalDeserialize::deserialize(bytes).map_err(serde::de::Error::custom)?;
                Ok(SecretKey(f))
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<SecretKey<F>, D::Error>
            where
                D: Deserializer<'a>,
            {
                // println!("in visit_newtype_struct");
                let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
                // println!("got bytes {:?}", &bytes);
                let f =
                    CanonicalDeserialize::deserialize(bytes).map_err(serde::de::Error::custom)?;
                Ok(SecretKey(f))
                // unimplemented!()
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'a>,
            {
                // println!("in visit_seq {:?}", seq.size_hint());
                let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(32));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                let f = CanonicalDeserialize::deserialize(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?;
                Ok(SecretKey(f))
            }

            /*fn visit_borrowed_bytes<E>(self, v: &'a [u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                println!("in visit_borrowed_bytes");
                unimplemented!()
            }*/
        }

        // deserializer.deserialize_newtype_struct("SecretKey", SkVisitor::<F>(PhantomData))
        deserializer.deserialize_seq(SkVisitor::<F>(PhantomData))
    }
}

// TODO: Add "prepared" version of public key

/// Return `par_iter` or `iter` depending on whether feature `parallel` is enabled
macro_rules! iter {
    ($val:expr) => {{
        #[cfg(feature = "parallel")]
        let it = $val.par_iter();
        #[cfg(not(feature = "parallel"))]
        let it = $val.iter();
        it
    }};
}

/// Return `into_par_iter` or `into_iter` depending on whether feature `parallel` is enabled
macro_rules! into_iter {
    ($val:expr) => {{
        #[cfg(feature = "parallel")]
        let it = $val.into_par_iter();
        #[cfg(not(feature = "parallel"))]
        let it = $val.into_iter();
        it
    }};
}

impl<F: PrimeField + SquareRootField> SecretKey<F> {
    pub fn generate_using_seed<D>(seed: &[u8]) -> Self
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        Self(field_elem_from_seed::<F, D>(
            seed,
            "BBS-SIG-KEYGEN-SALT-".as_bytes(),
        ))
    }
}

macro_rules! impl_sig_params {
    ( $name:ident, $group_affine:ident, $group_projective:ident, $other_group_affine:ident, $other_group_projective:ident ) => {
        /// Signature params used while signing and verifying. Also used when proving knowledge of signature.
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
        pub struct $name<E: PairingEngine> {
            // #[serde(serialize_with = "to_affine_group", deserialize_with = "from_affine_group")]
            #[serde_as(as = "AffineGroupBytes")]
            pub g1: E::$group_affine,
            // #[serde(serialize_with = "to_affine_group", deserialize_with = "from_affine_group")]
            #[serde_as(as = "AffineGroupBytes")]
            pub g2: E::$other_group_affine,
            // #[serde(serialize_with = "to_affine_group", deserialize_with = "from_affine_group")]
            #[serde_as(as = "AffineGroupBytes")]
            pub h_0: E::$group_affine,
            /// Vector of size same as the size of multi-message that needs to be signed.
            // #[serde(skip)]
            #[serde_as(as = "Vec<AffineGroupBytes>")]
            pub h: Vec<E::$group_affine>,
        }

        impl<E: PairingEngine> $name<E> {
            /// Generate params by hashing a known string. The hash function is vulnerable to timing
            /// attack but since all this is public knowledge, it is fine.
            /// This is useful if people need to be convinced that the discrete of group elements wrt each other is not known.
            pub fn new<D: Digest>(label: &[u8], n: usize) -> Self {
                // Need n+2 elements of signature group and 1 element of other group
                let mut sig_group_elems = Vec::with_capacity(n + 2);
                // Group element by hashing label + g1 as string.
                let g1 = projective_group_elem_from_try_and_incr::<E::$group_affine, D>(
                    &to_bytes![label, " : g1".as_bytes()].unwrap(),
                );
                // h_0 and h[i] for i in 1 to n
                let mut h = into_iter!((0..=n))
                    .map(|i| {
                        projective_group_elem_from_try_and_incr::<E::$group_affine, D>(
                            &to_bytes![label, " : h_".as_bytes(), i as u64].unwrap(),
                        )
                    })
                    .collect::<Vec<E::$group_projective>>();
                sig_group_elems.push(g1);
                sig_group_elems.append(&mut h);
                // Convert all to affine
                E::$group_projective::batch_normalization(sig_group_elems.as_mut_slice());
                let mut sig_group_elems = into_iter!(sig_group_elems)
                    .map(|v| v.into())
                    .collect::<Vec<E::$group_affine>>();
                let g1 = sig_group_elems.remove(0);
                let h_0 = sig_group_elems.remove(0);

                let g2 = projective_group_elem_from_try_and_incr::<E::$other_group_affine, D>(
                    &to_bytes![label, " : g2".as_bytes()].unwrap(),
                )
                .into_affine();
                Self {
                    g1,
                    g2,
                    h_0,
                    h: sig_group_elems,
                }
            }

            /// Generate params using a random number generator
            pub fn generate_using_rng<R>(rng: &mut R, n: usize) -> Self
            where
                R: RngCore,
            {
                let h = (0..n)
                    .into_iter()
                    .map(|_| E::$group_projective::rand(rng))
                    .collect::<Vec<E::$group_projective>>();
                Self {
                    g1: E::$group_projective::rand(rng).into(),
                    g2: E::$other_group_projective::rand(rng).into(),
                    h_0: E::$group_projective::rand(rng).into(),
                    h: E::$group_projective::batch_normalization_into_affine(&h),
                }
            }

            /// Check if no group element is zero
            pub fn is_valid(&self) -> bool {
                !(self.g1.is_zero()
                    || self.g2.is_zero()
                    || self.h_0.is_zero()
                    || iter!(self.h).any(|v| v.is_zero()))
            }

            /// Maximum supported messages in the multi-message
            pub fn max_message_count(&self) -> usize {
                self.h.len()
            }

            /// Commit to given messages using the parameters and the given blinding as a Pedersen commitment.
            /// Eg. if given messages `m_i`, `m_j`, and `m_k` in the map, the commitment is
            /// `params.h_0 * blinding + params.h_i * m_i + params.h_j * m_j + params.h_k * m_k`
            /// Computes using multi-scalar multiplication
            pub fn commit_to_messages(
                &self,
                messages: BTreeMap<usize, &E::Fr>,
                blinding: &E::Fr,
            ) -> Result<E::$group_affine, BBSPlusError> {
                #[cfg(feature = "parallel")]
                let (mut bases, mut scalars): (
                    Vec<E::$group_affine>,
                    Vec<<<E as ark_ec::PairingEngine>::Fr as PrimeField>::BigInt>,
                ) = {
                    for (i, _) in messages.iter() {
                        if *i >= self.max_message_count() {
                            return Err(BBSPlusError::InvalidMessageIdx);
                        }
                    }
                    into_iter!(messages)
                        .map(|(i, msg)| (self.h[i].clone(), msg.into_repr()))
                        .unzip()
                };

                #[cfg(not(feature = "parallel"))]
                let (mut bases, mut scalars) = {
                    let mut bases = Vec::with_capacity(messages.len());
                    let mut scalars = Vec::with_capacity(messages.len());
                    for (i, msg) in messages.into_iter() {
                        if i >= self.max_message_count() {
                            return Err(BBSPlusError::InvalidMessageIdx);
                        }
                        bases.push(self.h[i].clone());
                        scalars.push(msg.into_repr());
                    }
                    (bases, scalars)
                };

                bases.push(self.h_0.clone());
                scalars.push(blinding.into_repr());
                Ok(VariableBaseMSM::multi_scalar_mul(&bases, &scalars).into_affine())
            }

            /// Compute `b` from the paper. Commits to the given messages and adds `self.g1` to it
            /// `b = g_1 + h_0 * s + sum(h_i * m_i)` for all indices `i` in the map.
            pub fn b(
                &self,
                messages: BTreeMap<usize, &E::Fr>,
                s: &E::Fr,
            ) -> Result<E::$group_projective, BBSPlusError> {
                let commitment = self.commit_to_messages(messages, s)?;
                Ok(commitment.into_projective().add_mixed(&self.g1))
            }
        }
    };
}

macro_rules! impl_public_key {
    ( $name:ident, $group:ident, $params:ident ) => {
        /// Public key of the signer. The signer can use the same public key with different
        /// signature parameters provided all parameters use same `g2` to sign different sized
        /// multi-messages. This helps the signer minimize his secret key storage.
        #[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
        pub struct $name<E: PairingEngine>(pub <E as PairingEngine>::$group);

        impl<E: PairingEngine> $name<E>
        where
            E: PairingEngine,
        {
            /// Generate public key from given secret key and signature parameters
            pub fn generate_using_secret_key(
                secret_key: &SecretKey<E::Fr>,
                params: &$params<E>,
            ) -> Self {
                Self(params.g2.mul(secret_key.0.into_repr()).into())
            }

            /// Public key shouldn't be 0
            pub fn is_valid(&self) -> bool {
                !self.0.is_zero()
            }
        }

        impl<E: PairingEngine> Serialize for $name<E> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut bytes = vec![];
                CanonicalSerialize::serialize(self, &mut bytes)
                    .map_err(serde::ser::Error::custom)?;
                // serializer.serialize_bytes(&bytes)
                let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
                for element in bytes {
                    seq.serialize_element(&element)?;
                }
                seq.end()
            }
        }

        impl<'a, E: PairingEngine> Deserialize<'a> for $name<E> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'a>,
            {
                struct PkVisitor<E: PairingEngine>(PhantomData<E>);

                impl<'a, E: PairingEngine> Visitor<'a> for PkVisitor<E> {
                    type Value = $name<E>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("expected PublicKey")
                    }

                    fn visit_bytes<Er>(self, bytes: &[u8]) -> Result<$name<E>, Er>
                    where
                        Er: serde::de::Error,
                    {
                        CanonicalDeserialize::deserialize(bytes).map_err(serde::de::Error::custom)
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'a>,
                    {
                        // println!("in visit_seq {:?}", seq.size_hint());
                        let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(48));

                        while let Some(b) = seq.next_element()? {
                            bytes.push(b);
                        }
                        let f = CanonicalDeserialize::deserialize(bytes.as_slice())
                            .map_err(serde::de::Error::custom)?;
                        Ok($name(f))
                    }
                }

                // deserializer.deserialize_bytes(PkVisitor::<E>(PhantomData))
                deserializer.deserialize_seq(PkVisitor::<E>(PhantomData))
            }
        }
    };
}

macro_rules! impl_keypair {
    ( $name:ident, $group:ident, $pk: ident, $params:ident ) => {
        #[derive(Clone, Serialize, Deserialize)]
        pub struct $name<E: PairingEngine> {
            pub secret_key: SecretKey<E::Fr>,
            pub public_key: $pk<E>,
        }

        /// Create a secret key and corresponding public key
        impl<E: PairingEngine> $name<E> {
            pub fn generate_using_seed<D>(seed: &[u8], params: &$params<E>) -> Self
            where
                D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
            {
                let secret_key = SecretKey::<E::Fr>::generate_using_seed::<D>(seed);
                let public_key = $pk::generate_using_secret_key(&secret_key, params);
                Self {
                    secret_key,
                    public_key,
                }
            }

            pub fn generate_using_rng<R: RngCore>(rng: &mut R, params: &$params<E>) -> Self {
                let secret_key = SecretKey(E::Fr::rand(rng));
                let public_key = $pk::generate_using_secret_key(&secret_key, params);
                Self {
                    secret_key,
                    public_key,
                }
            }
        }
    };
}

impl_sig_params!(
    SignatureParamsG1,
    G1Affine,
    G1Projective,
    G2Affine,
    G2Projective
);
impl_sig_params!(
    SignatureParamsG2,
    G2Affine,
    G2Projective,
    G1Affine,
    G1Projective
);
impl_public_key!(PublicKeyG2, G2Affine, SignatureParamsG1);
impl_public_key!(PublicKeyG1, G1Affine, SignatureParamsG2);
impl_keypair!(KeypairG2, G2Projective, PublicKeyG2, SignatureParamsG1);
impl_keypair!(KeypairG1, G1Projective, PublicKeyG1, SignatureParamsG2);
impl_proof_of_knowledge_of_discrete_log!(PoKSecretKeyInPublicKeyG2, PoKSecretKeyInPublicKeyG2Proof);
impl_proof_of_knowledge_of_discrete_log!(PoKSecretKeyInPublicKeyG1, PoKSecretKeyInPublicKeyG1Proof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b;

    macro_rules! test_serz_des {
        ($keypair:ident, $public_key:ident, $params:ident, $rng:ident, $message_count: ident) => {
            let params = $params::<Bls12_381>::generate_using_rng(&mut $rng, $message_count);
            test_serialization!($params<Bls12_381>, params);

            let keypair = $keypair::<Bls12_381>::generate_using_rng(&mut $rng, &params);
            let pk = keypair.public_key;
            test_serialization!($public_key<Bls12_381>, pk);

            let sk_ser = serde_json::to_string(&keypair.secret_key).unwrap();
            println!("serde sk={:?}", sk_ser);
            let sk_deser =
                serde_json::from_str::<SecretKey<<Bls12_381 as PairingEngine>::Fr>>(&sk_ser)
                    .unwrap();
            println!("serde sk deser={:?}", sk_deser);
            assert_eq!(keypair.secret_key, sk_deser);

            let pk_ser = serde_json::to_string(&pk).unwrap();
            println!("serde pk={:?}", pk_ser);
            let pk_deser = serde_json::from_str::<$public_key<Bls12_381>>(&pk_ser).unwrap();
            println!("serde pk deser={:?}", pk_deser);
            assert_eq!(pk, pk_deser);

            let params_ser = serde_json::to_string(&params).unwrap();
            println!("serde params={:?}", params_ser);
            let params_deser = serde_json::from_str::<$params<Bls12_381>>(&params_ser).unwrap();
            println!("serde params deser={:?}", params_deser);
            assert_eq!(params, params_deser);
        };
    }

    macro_rules! test_params {
        ($params:ident, $message_count: ident) => {
            let label_1 = "test1".as_bytes();
            let params_1 = $params::<Bls12_381>::new::<Blake2b>(&label_1, $message_count);
            assert!(params_1.is_valid());
            assert_eq!(params_1.h.len(), $message_count);

            // Same label should generate same params
            let params_1_again = $params::<Bls12_381>::new::<Blake2b>(&label_1, $message_count);
            assert_eq!(params_1_again, params_1);

            // Different label should generate different params
            let label_2 = "test2".as_bytes();
            let params_2 = $params::<Bls12_381>::new::<Blake2b>(&label_2, $message_count);
            assert_ne!(params_1, params_2);
        };
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
            message_count
        );
        test_serz_des!(
            KeypairG1,
            PublicKeyG1,
            SignatureParamsG2,
            rng,
            message_count
        );
    }

    #[test]
    fn params_deterministically() {
        // Test generation of signature params deterministically.
        let message_count = 10;
        test_params!(SignatureParamsG1, message_count);
        test_params!(SignatureParamsG2, message_count);
    }
}
