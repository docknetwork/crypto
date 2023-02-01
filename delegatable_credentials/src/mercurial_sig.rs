//! Mercurial signatures as defined in section 3 of [this paper](https://eprint.iacr.org/2018/923.pdf).
//! Implements 2 variations of the algorithms, one where signature is in group G1 and public key in group G2
//! and the other where signature is in group G2 and public key in group G1

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    cfg_into_iter, cfg_iter,
    fmt::Debug,
    format,
    io::{Read, Write},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

use zeroize::Zeroize;

use dock_crypto_utils::{hashing_utils::field_elem_from_seed, serde_utils::*};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use dock_crypto_utils::msm::{variable_base_msm, WindowTable};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::error::DelegationError;

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
)]
pub struct SecretKey<E: PairingEngine>(#[serde_as(as = "Vec<FieldBytes>")] pub Vec<E::Fr>);

impl<E: PairingEngine> Drop for SecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Public key used to verify signatures in group G1
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<E: PairingEngine>(
    #[serde_as(as = "Vec<AffineGroupBytes>")] pub Vec<E::G2Affine>,
);

/// Public key used to verify signatures in group G2
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKeyG1<E: PairingEngine>(
    #[serde_as(as = "Vec<AffineGroupBytes>")] pub Vec<E::G1Affine>,
);

#[derive(Clone, Debug)]
pub struct PreparedPublicKey<E: PairingEngine>(pub Vec<E::G2Prepared>);

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
pub struct Signature<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub Z: E::G1Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub Y: E::G1Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub Y_tilde: E::G2Affine,
}

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
pub struct SignatureG2<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub Z: E::G2Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub Y: E::G2Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub Y_tilde: E::G1Affine,
}

impl<E: PairingEngine> Drop for Signature<E> {
    fn drop(&mut self) {
        self.Z.zeroize();
        self.Y.zeroize();
        self.Y_tilde.zeroize();
    }
}

impl<E: PairingEngine> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R, size: usize) -> Result<Self, DelegationError> {
        if size == 0 {
            return Err(DelegationError::NeedNonZeroSize);
        }
        Ok(Self(
            (0..size).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>(),
        ))
    }

    pub fn generate_using_seed<D>(seed: &[u8], size: usize) -> Result<Self, DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        if size == 0 {
            return Err(DelegationError::NeedNonZeroSize);
        }
        Ok(Self(
            cfg_into_iter!(1..=size)
                .map(|i| {
                    field_elem_from_seed::<E::Fr, D>(
                        seed,
                        format!("MERCURIAL-SIG-KEYGEN-SALT-{}", i).as_bytes(),
                    )
                })
                .collect::<Vec<_>>(),
        ))
    }

    /// ConvertSK from the paper.
    pub fn convert(&self, r: &E::Fr) -> Self {
        Self(cfg_iter!(self.0).map(|s| *s * r).collect::<Vec<_>>())
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

macro_rules! impl_pubkey {
    ($gen: ty) => {
        pub fn new(secret_key: &SecretKey<E>, g2: &$gen) -> Self {
            let P_tilde_table = WindowTable::new(secret_key.size(), g2.into_projective());
            Self(batch_normalize_projective_into_affine(
                P_tilde_table.multiply_many(&secret_key.0),
            ))
        }

        /// ConvertPK from the paper
        pub fn convert(&self, rho: &E::Fr) -> Self {
            let r_repr = rho.into_repr();
            let new_pk = cfg_iter!(self.0).map(|s| s.mul(r_repr)).collect::<Vec<_>>();
            Self(batch_normalize_projective_into_affine(new_pk))
        }

        pub fn size(&self) -> usize {
            self.0.len()
        }
    };
}

impl<E: PairingEngine> PublicKey<E> {
    impl_pubkey!(E::G2Affine);

    pub fn prepared(&self) -> PreparedPublicKey<E> {
        PreparedPublicKey(
            cfg_iter!(self.0)
                .map(|e| E::G2Prepared::from(*e))
                .collect::<Vec<_>>(),
        )
    }
}

impl<E: PairingEngine> PublicKeyG1<E> {
    impl_pubkey!(E::G1Affine);
}

impl<E: PairingEngine> PreparedPublicKey<E> {
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
            let y = E::Fr::rand(rng);
            Self::new_with_given_randomness(&y, messages, secret_key, sig_grp_gen, pk_grp_gen)
        }

        pub fn new_with_given_randomness(
            y: &E::Fr,
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
            let Z = variable_base_msm(messages, &secret_key.0)
                .mul(y.into_repr())
                .into_affine();
            let y_inv = y.inverse().unwrap().into_repr();
            Ok(Self {
                Z,
                Y: sig_grp_gen.mul(y_inv).into_affine(),
                Y_tilde: pk_grp_gen.mul(y_inv).into_affine(),
            })
        }

        /// ConvertSig from the paper
        pub fn convert<R: RngCore>(&self, rng: &mut R, converter: &E::Fr) -> Self {
            let psi = E::Fr::rand(rng);
            self.convert_with_given_randomness(converter, &psi)
        }

        /// ChangRep from the paper
        pub fn change_rep<R: RngCore>(
            &self,
            rng: &mut R,
            message_converter: &E::Fr,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let psi = E::Fr::rand(rng);
            self.change_rep_with_given_randomness(message_converter, &psi, messages)
        }

        /// Similar to `Self::change_rep` but the randomizer for signature's `Z` is passed as an argument
        /// rather than generated randomly
        pub fn change_rep_with_given_sig_converter<R: RngCore>(
            &self,
            rng: &mut R,
            message_converter: &E::Fr,
            sig_converter: &E::Fr,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let psi = E::Fr::rand(rng);
            self.change_rep_with_given_sig_converter_and_randomness(
                message_converter,
                sig_converter,
                &psi,
                messages,
            )
        }

        /// ConvertSig from the paper with the randomness provided externally
        pub fn convert_with_given_randomness(&self, converter: &E::Fr, psi: &E::Fr) -> Self {
            let psi_inv_repr = psi.inverse().unwrap().into_repr();
            Self {
                Z: self.Z.mul((*converter * psi).into_repr()).into_affine(),
                Y: self.Y.mul(psi_inv_repr).into_affine(),
                Y_tilde: self.Y_tilde.mul(psi_inv_repr).into_affine(),
            }
        }

        /// ChangRep from the paper with the randomness provided externally
        pub fn change_rep_with_given_randomness(
            &self,
            message_converter: &E::Fr,
            psi: &E::Fr,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let mu_repr = message_converter.into_repr();
            let new_msgs = cfg_iter!(messages)
                .map(|m| m.mul(mu_repr))
                .collect::<Vec<_>>();
            let new_sig = self.convert_with_given_randomness(message_converter, psi);
            (new_sig, batch_normalize_projective_into_affine(new_msgs))
        }

        pub fn change_rep_with_given_sig_converter_and_randomness(
            &self,
            message_converter: &E::Fr,
            sig_converter: &E::Fr,
            psi: &E::Fr,
            messages: &[$msg_group],
        ) -> (Self, Vec<$msg_group>) {
            let mu_repr = message_converter.into_repr();
            let new_msgs = cfg_iter!(messages)
                .map(|m| m.mul(mu_repr))
                .collect::<Vec<_>>();
            let new_sig =
                self.convert_with_given_randomness(&(*message_converter * *sig_converter), psi);
            (new_sig, batch_normalize_projective_into_affine(new_msgs))
        }
    };
}

impl<E: PairingEngine> Signature<E> {
    impl_signature_struct!(E::G1Affine, E::G2Affine);

    pub fn verify(
        &self,
        messages: &[E::G1Affine],
        public_key: &PublicKey<E>,
        sig_grp_gen: &E::G1Affine,
        pk_grp_gen: &E::G2Affine,
    ) -> Result<(), DelegationError> {
        return self.verify_using_prepared_public_key(
            messages,
            &public_key.prepared(),
            sig_grp_gen,
            pk_grp_gen,
        );
    }

    pub fn verify_using_prepared_public_key(
        &self,
        messages: &[E::G1Affine],
        public_key: &PreparedPublicKey<E>,
        sig_grp_gen: &E::G1Affine,
        pk_grp_gen: &E::G2Affine,
    ) -> Result<(), DelegationError> {
        if messages.len() > public_key.size() {
            return Err(DelegationError::MessageCountIncompatibleWithKey(
                messages.len(),
                public_key.size(),
            ));
        }

        let mut pairs1 = cfg_iter!(messages)
            .map(|e| E::G1Prepared::from(*e))
            .zip(cfg_iter!(public_key.0).map(|e| e.clone()))
            .collect::<Vec<_>>();
        let y_tilde_prep = E::G2Prepared::from(self.Y_tilde);
        pairs1.push((E::G1Prepared::from(-self.Z), y_tilde_prep.clone()));
        if !E::product_of_pairings(pairs1.iter()).is_one() {
            return Err(DelegationError::InvalidSignature);
        }

        let pairs2 = [
            (
                E::G1Prepared::from(self.Y),
                E::G2Prepared::from(*pk_grp_gen),
            ),
            (E::G1Prepared::from(-*sig_grp_gen), y_tilde_prep),
        ];
        if !E::product_of_pairings(pairs2.iter()).is_one() {
            return Err(DelegationError::InvalidSignature);
        }
        return Ok(());
    }
}

impl<E: PairingEngine> SignatureG2<E> {
    impl_signature_struct!(E::G2Affine, E::G1Affine);

    pub fn verify(
        &self,
        messages: &[E::G2Affine],
        public_key: &PublicKeyG1<E>,
        sig_grp_gen: &E::G2Affine,
        pk_grp_gen: &E::G1Affine,
    ) -> Result<(), DelegationError> {
        if messages.len() > public_key.size() {
            return Err(DelegationError::MessageCountIncompatibleWithKey(
                messages.len(),
                public_key.size(),
            ));
        }

        let mut pairs1 = cfg_iter!(public_key.0)
            .map(|e| E::G1Prepared::from(*e))
            .zip(cfg_iter!(messages).map(|e| E::G2Prepared::from(*e)))
            .collect::<Vec<_>>();
        pairs1.push((
            E::G1Prepared::from(-self.Y_tilde),
            E::G2Prepared::from(self.Z),
        ));
        if !E::product_of_pairings(pairs1.iter()).is_one() {
            return Err(DelegationError::InvalidSignature);
        }

        let pairs2 = [
            (
                E::G1Prepared::from(*pk_grp_gen),
                E::G2Prepared::from(self.Y),
            ),
            (
                E::G1Prepared::from(-self.Y_tilde),
                E::G2Prepared::from(*sig_grp_gen),
            ),
        ];
        if !E::product_of_pairings(pairs2.iter()).is_one() {
            return Err(DelegationError::InvalidSignature);
        }
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::generator_pair;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn sign_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (P1, P2) = generator_pair::<Bls12_381, StdRng>(&mut rng);

        let count = 5;
        let sk = SecretKey::new(&mut rng, count).unwrap();
        let pk = PublicKey::<Bls12_381>::new(&sk, &P2);
        let prep_pk = pk.prepared();
        assert!(count == sk.size() && sk.size() == pk.size() && pk.size() == prep_pk.size());

        let msgs = (0..count)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let sig = Signature::new(&mut rng, &msgs, &sk, &P1, &P2).unwrap();
        sig.verify(&msgs, &pk, &P1, &P2).unwrap();
        sig.verify_using_prepared_public_key(&msgs, &prep_pk, &P1, &P2)
            .unwrap();

        let r1 = Fr::rand(&mut rng);
        let pk1 = pk.convert(&r1);
        let prep_pk1 = pk1.prepared();
        assert_eq!(pk1.size(), prep_pk1.size());

        // Original messages with converted signature and public key
        let sig1 = sig.convert(&mut rng, &r1);
        sig1.verify(&msgs, &pk1, &P1, &P2).unwrap();
        sig1.verify_using_prepared_public_key(&msgs, &prep_pk1, &P1, &P2)
            .unwrap();

        // Converted messages and signature with original public key
        let r2 = Fr::rand(&mut rng);
        let (sig2, msgs1) = sig.change_rep(&mut rng, &r2, &msgs);
        sig2.verify(&msgs1, &pk, &P1, &P2).unwrap();
        sig2.verify_using_prepared_public_key(&msgs1, &prep_pk, &P1, &P2)
            .unwrap();

        let (sig3, msgs2) = sig1.change_rep(&mut rng, &r2, &msgs);
        sig3.verify(&msgs2, &pk1, &P1, &P2).unwrap();
        sig3.verify_using_prepared_public_key(&msgs2, &prep_pk1, &P1, &P2)
            .unwrap();

        // Messages, signature and public key, all converted
        let (sig4, msgs3) = sig.change_rep_with_given_sig_converter(&mut rng, &r2, &r1, &msgs);
        sig4.verify(&msgs3, &pk1, &P1, &P2).unwrap();
        sig4.verify_using_prepared_public_key(&msgs3, &prep_pk1, &P1, &P2)
            .unwrap();

        // Switch group for messages and public key

        let pk = PublicKeyG1::<Bls12_381>::new(&sk, &P1);
        let msgs = (0..count)
            .map(|_| <Bls12_381 as PairingEngine>::G2Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let sig = SignatureG2::new(&mut rng, &msgs, &sk, &P2, &P1).unwrap();
        sig.verify(&msgs, &pk, &P2, &P1).unwrap();

        // Converted messages and signature with original public key
        let (sig2, msgs1) = sig.change_rep(&mut rng, &r2, &msgs);
        sig2.verify(&msgs1, &pk, &P2, &P1).unwrap();
    }
}
