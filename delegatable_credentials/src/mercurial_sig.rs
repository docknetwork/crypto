//! Mercurial signatures as defined in section 3 of [this paper](https://eprint.iacr.org/2018/923.pdf).
//! Implements 2 variations of the algorithms, one where signature is in group G1 and public key in group G2
//! and the other where signature is in group G2 and public key in group G1

use crate::error::DelegationError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    aliases::{FullDigest, SyncIfParallel},
    hashing_utils::hash_to_field_many,
    msm::WindowTable,
    serde_utils::*,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
pub struct SecretKey<E: Pairing>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<E::ScalarField>);

/// Public key used to verify `Signature`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<E: Pairing>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<E::G2Affine>);

/// Public key used to verify `SignatureG2`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyG1<E: Pairing>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<E::G1Affine>);

/// Prepared version of `PublicKey` for faster pairing checks
#[derive(Clone, Debug)]
pub struct PreparedPublicKey<E: Pairing>(pub Vec<E::G2Prepared>);

/// Signature with 2 elements in group G1 and 1 element in G2
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
)]
pub struct Signature<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub Z: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Y: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Y_tilde: E::G2Affine,
}

/// Signature with 2 elements in group G2 and 1 element in G1
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
pub struct SignatureG2<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub Z: E::G2Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Y: E::G2Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Y_tilde: E::G1Affine,
}

impl<E: Pairing> SecretKey<E> {
    pub const DST: &'static [u8] = b"MERCURIAL-SIG-KEYGEN-SALT";

    pub fn new<R: RngCore>(rng: &mut R, size: u32) -> Result<Self, DelegationError> {
        if size == 0 {
            return Err(DelegationError::NeedNonZeroSize);
        }
        Ok(Self(
            (0..size)
                .map(|_| E::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        ))
    }

    pub fn generate_using_seed<D>(seed: &[u8], size: u32) -> Result<Self, DelegationError>
    where
        D: FullDigest + SyncIfParallel,
    {
        if size == 0 {
            return Err(DelegationError::NeedNonZeroSize);
        }
        Ok(Self(hash_to_field_many::<E::ScalarField, D>(
            Self::DST,
            seed,
            size,
        )))
    }

    /// ConvertSK from the paper.
    pub fn convert(&self, r: &E::ScalarField) -> Self {
        Self(cfg_iter!(self.0).map(|s| *s * r).collect::<Vec<_>>())
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

macro_rules! impl_pubkey {
    ($gen: ty) => {
        pub fn new(secret_key: &SecretKey<E>, g2: &$gen) -> Self {
            let P_tilde_table = WindowTable::new(secret_key.size(), g2.into_group());
            Self(<$gen as AffineRepr>::Group::normalize_batch(
                &P_tilde_table.multiply_many(&secret_key.0),
            ))
        }

        /// ConvertPK from the paper
        pub fn convert(&self, rho: &E::ScalarField) -> Self {
            let r_repr = rho.into_bigint();
            let new_pk = cfg_iter!(self.0)
                .map(|s| s.mul_bigint(r_repr))
                .collect::<Vec<_>>();
            Self(<$gen as AffineRepr>::Group::normalize_batch(&new_pk))
        }

        pub fn size(&self) -> usize {
            self.0.len()
        }
    };
}

impl<E: Pairing> PublicKey<E> {
    impl_pubkey!(E::G2Affine);
}

impl<E: Pairing> PublicKeyG1<E> {
    impl_pubkey!(E::G1Affine);
}

impl<E: Pairing> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(pk: PublicKey<E>) -> Self {
        Self(
            cfg_iter!(pk.0)
                .map(|e| E::G2Prepared::from(*e))
                .collect::<Vec<_>>(),
        )
    }
}

impl<E: Pairing> PreparedPublicKey<E> {
    pub fn size(&self) -> usize {
        self.0.len()
    }
}

macro_rules! impl_signature_struct {
    ( $msg_group: ty, $pkg: ty ) => {
        pub fn new<R: RngCore>(
            rng: &mut R,
            messages: &[$msg_group],
            secret_key: &SecretKey<E>,
            sig_grp_gen: &$msg_group,
            pk_grp_gen: &$pkg,
        ) -> Result<Self, DelegationError> {
            let y = E::ScalarField::rand(rng);
            Self::new_with_given_randomness(&y, messages, secret_key, sig_grp_gen, pk_grp_gen)
        }

        pub fn new_with_given_randomness(
            y: &E::ScalarField,
            messages: &[$msg_group],
            secret_key: &SecretKey<E>,
            sig_grp_gen: &$msg_group,
            pk_grp_gen: &$pkg,
        ) -> Result<Self, DelegationError> {
            if messages.len() > secret_key.size() {
                return Err(DelegationError::MessageCountIncompatibleWithKey(
                    messages.len(),
                    secret_key.size(),
                ));
            }
            // Z = \sum_{i}(m_i * sk_i)*y
            // Y = sig_grp_gen * 1/y
            // Y_tilde = pk_grp_gen * 1/y
            let Z = <$msg_group as AffineRepr>::Group::msm_unchecked(messages, &secret_key.0)
                .mul_bigint(y.into_bigint())
                .into_affine();
            let y_inv = y.inverse().unwrap().into_bigint();
            Ok(Self {
                Z,
                Y: sig_grp_gen.mul_bigint(y_inv).into_affine(),
                Y_tilde: pk_grp_gen.mul_bigint(y_inv).into_affine(),
            })
        }

        /// ConvertSig from the paper
        pub fn convert<R: RngCore>(&self, rng: &mut R, converter: &E::ScalarField) -> Self {
            let psi = E::ScalarField::rand(rng);
            self.convert_with_given_randomness(converter, &psi)
        }

        /// ChangRep from the paper
        pub fn change_rep<R: RngCore>(
            &self,
            rng: &mut R,
            message_converter: &E::ScalarField,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let psi = E::ScalarField::rand(rng);
            self.change_rep_with_given_randomness(message_converter, &psi, messages)
        }

        /// Similar to `Self::change_rep` but the randomizer for signature's `Z` is passed as an argument
        /// rather than generated randomly
        pub fn change_rep_with_given_sig_converter<R: RngCore>(
            &self,
            rng: &mut R,
            message_converter: &E::ScalarField,
            sig_converter: &E::ScalarField,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let psi = E::ScalarField::rand(rng);
            self.change_rep_with_given_sig_converter_and_randomness(
                message_converter,
                sig_converter,
                &psi,
                messages,
            )
        }

        /// ConvertSig from the paper with the randomness provided externally
        pub fn convert_with_given_randomness(
            &self,
            converter: &E::ScalarField,
            psi: &E::ScalarField,
        ) -> Self {
            let psi_inv_repr = psi.inverse().unwrap().into_bigint();
            // Z = Z * converter * psi
            // Y = Y * 1/psi
            // Y_tilde = Y_tilde * 1/psi
            Self {
                Z: self
                    .Z
                    .mul_bigint((*converter * psi).into_bigint())
                    .into_affine(),
                Y: self.Y.mul_bigint(psi_inv_repr).into_affine(),
                Y_tilde: self.Y_tilde.mul_bigint(psi_inv_repr).into_affine(),
            }
        }

        /// ChangRep from the paper with the randomness provided externally
        pub fn change_rep_with_given_randomness(
            &self,
            message_converter: &E::ScalarField,
            psi: &E::ScalarField,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let mu_repr = message_converter.into_bigint();
            // new_msgs_i = messages_i * message_converter
            let new_msgs = cfg_iter!(messages)
                .map(|m| m.mul_bigint(mu_repr))
                .collect::<Vec<_>>();
            let new_sig = self.convert_with_given_randomness(message_converter, psi);
            (
                new_sig,
                <$msg_group as AffineRepr>::Group::normalize_batch(&new_msgs),
            )
        }

        pub fn change_rep_with_given_sig_converter_and_randomness(
            &self,
            message_converter: &E::ScalarField,
            sig_converter: &E::ScalarField,
            psi: &E::ScalarField,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let mu_repr = message_converter.into_bigint();
            let new_msgs = cfg_iter!(messages)
                .map(|m| m.mul_bigint(mu_repr))
                .collect::<Vec<_>>();
            let new_sig =
                self.convert_with_given_randomness(&(*message_converter * *sig_converter), psi);
            (
                new_sig,
                <$msg_group as AffineRepr>::Group::normalize_batch(&new_msgs),
            )
        }
    };
}

impl<E: Pairing> Signature<E> {
    impl_signature_struct!(E::G1Affine, E::G2Affine);

    pub fn verify(
        &self,
        messages: &[E::G1Affine],
        public_key: impl Into<PreparedPublicKey<E>>,
        sig_grp_gen: &E::G1Affine,
        pk_grp_gen: impl Into<E::G2Prepared>,
    ) -> Result<(), DelegationError> {
        let public_key = public_key.into();

        if messages.len() > public_key.size() {
            return Err(DelegationError::MessageCountIncompatibleWithKey(
                messages.len(),
                public_key.size(),
            ));
        }

        let y_tilde_prep = E::G2Prepared::from(self.Y_tilde);

        let mut a = cfg_iter!(messages)
            .map(|e| E::G1Prepared::from(*e))
            .collect::<Vec<_>>();
        let mut b = public_key.0[..messages.len()].to_vec();
        a.push(E::G1Prepared::from(-self.Z.into_group()));
        b.push(y_tilde_prep.clone());
        if !E::multi_pairing(a, b).is_zero() {
            return Err(DelegationError::InvalidSignature);
        }

        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.Y),
                E::G1Prepared::from(-sig_grp_gen.into_group()),
            ],
            [pk_grp_gen.into(), y_tilde_prep],
        )
        .is_zero()
        {
            return Err(DelegationError::InvalidSignature);
        }
        Ok(())
    }
}

impl<E: Pairing> SignatureG2<E> {
    impl_signature_struct!(E::G2Affine, E::G1Affine);

    pub fn verify(
        &self,
        messages: &[E::G2Affine],
        public_key: &PublicKeyG1<E>,
        sig_grp_gen: impl Into<E::G2Prepared>,
        pk_grp_gen: &E::G1Affine,
    ) -> Result<(), DelegationError> {
        if messages.len() > public_key.size() {
            return Err(DelegationError::MessageCountIncompatibleWithKey(
                messages.len(),
                public_key.size(),
            ));
        }

        let mut a = cfg_iter!(public_key.0)
            .map(|e| E::G1Prepared::from(*e))
            .collect::<Vec<_>>();
        let mut b = cfg_iter!(messages)
            .map(|e| E::G2Prepared::from(*e))
            .collect::<Vec<_>>();
        a.push(E::G1Prepared::from(
            (-self.Y_tilde.into_group()).into_affine(),
        ));
        b.push(E::G2Prepared::from(self.Z));
        if !E::multi_pairing(a, b).is_zero() {
            return Err(DelegationError::InvalidSignature);
        }

        if !E::multi_pairing(
            [
                E::G1Prepared::from(*pk_grp_gen),
                E::G1Prepared::from((-self.Y_tilde.into_group()).into_affine()),
            ],
            [E::G2Prepared::from(self.Y), sig_grp_gen.into()],
        )
        .is_zero()
        {
            return Err(DelegationError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::generator_pair;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Fr = <Bls12_381 as Pairing>::ScalarField;
    type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;

    #[test]
    fn sign_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (P1, P2) = generator_pair::<Bls12_381, StdRng>(&mut rng);
        let prep_P2 = G2Prepared::from(P2);

        let count = 5;
        let sk = SecretKey::new(&mut rng, count).unwrap();
        let pk = PublicKey::<Bls12_381>::new(&sk, &P2);
        let prep_pk = PreparedPublicKey::from(pk.clone());
        assert!(
            count as usize == sk.size() && sk.size() == pk.size() && pk.size() == prep_pk.size()
        );

        let msgs = (0..count)
            .map(|_| <Bls12_381 as Pairing>::G1Affine::rand(&mut rng))
            .collect::<Vec<_>>();

        let sig = Signature::new(&mut rng, &msgs, &sk, &P1, &P2).unwrap();
        sig.verify(&msgs, prep_pk.clone(), &P1, prep_P2.clone())
            .unwrap();

        let r1 = Fr::rand(&mut rng);
        let pk1 = pk.convert(&r1);
        let prep_pk1 = PreparedPublicKey::from(pk1.clone());
        assert_eq!(pk1.size(), prep_pk1.size());

        // Original messages with converted signature and public key
        let sig1 = sig.convert(&mut rng, &r1);
        sig1.verify(&msgs, prep_pk1.clone(), &P1, prep_P2.clone())
            .unwrap();

        // Converted messages and signature with original public key
        let r2 = Fr::rand(&mut rng);
        let (sig2, msgs1) = sig.change_rep(&mut rng, &r2, &msgs);
        sig2.verify(&msgs1, prep_pk, &P1, prep_P2.clone()).unwrap();

        let (sig3, msgs2) = sig1.change_rep(&mut rng, &r2, &msgs);
        sig3.verify(&msgs2, prep_pk1.clone(), &P1, prep_P2.clone())
            .unwrap();

        // Messages, signature and public key, all converted
        let (sig4, msgs3) = sig.change_rep_with_given_sig_converter(&mut rng, &r2, &r1, &msgs);
        sig4.verify(&msgs3, prep_pk1, &P1, prep_P2.clone()).unwrap();

        // Switch group for messages and public key

        let pk = PublicKeyG1::<Bls12_381>::new(&sk, &P1);
        let msgs = (0..count)
            .map(|_| <Bls12_381 as Pairing>::G2Affine::rand(&mut rng))
            .collect::<Vec<_>>();

        let sig = SignatureG2::new(&mut rng, &msgs, &sk, &P2, &P1).unwrap();
        sig.verify(&msgs, &pk, prep_P2.clone(), &P1).unwrap();

        // Converted messages and signature with original public key
        let (sig2, msgs1) = sig.change_rep(&mut rng, &r2, &msgs);
        sig2.verify(&msgs1, &pk, prep_P2, &P1).unwrap();
    }
}
