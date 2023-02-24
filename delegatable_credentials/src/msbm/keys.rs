use crate::error::DelegationError;
use crate::mercurial_sig::{PreparedPublicKey, PublicKey, SecretKey};
use crate::msbm::sps_eq_uc_sig::Signature;
use crate::set_commitment::SetCommitmentSRS;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::ops::Neg;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use ark_std::{cfg_iter, vec, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use dock_crypto_utils::ec::{
    batch_normalize_projective_into_affine, pairing_product_with_g2_prepared,
};
use dock_crypto_utils::hashing_utils::field_elem_from_seed;
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Secret key of the form `(x_0, (x_1, x_2, x_3, ..., x_n))`. The key `(x_1, x_2, x_3, ..., x_n)` is the
/// secret key for the Mercurial signature scheme
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct RootIssuerSecretKey<E: PairingEngine>(pub E::Fr, pub SecretKey<E>);

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct RootIssuerPublicKey<E: PairingEngine> {
    /// `x_0*P1`
    pub X_0: E::G1Affine,
    /// `x_0*P2`
    pub X_0_hat: E::G2Affine,
    /// Mercurial signature public key corresponding to secret key `(x_1, x_2, x_3, ..., x_n)`
    pub X: PublicKey<E>,
}

#[derive(Clone, Debug)]
pub struct PreparedRootIssuerPublicKey<E: PairingEngine> {
    pub X_0: E::G1Affine,
    pub X_0_hat: E::G2Prepared,
    pub X: PreparedPublicKey<E>,
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserSecretKey<E: PairingEngine>(pub E::Fr);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserPublicKey<E: PairingEngine>(pub E::G1Affine);

/// Key to update the credential, i.e. extend it with more commitments
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UpdateKey<E: PairingEngine> {
    /// 0-based commitment index in the credential from which this key can add commitments
    pub start_index: usize,
    pub max_attributes_per_commitment: usize,
    /// One key for each commitment index in the signature
    pub keys: Vec<Vec<E::G1Affine>>,
}

impl<E: PairingEngine> RootIssuerSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R, size: usize) -> Result<Self, DelegationError> {
        let m_sk = SecretKey::new(rng, size)?;
        Ok(Self(E::Fr::rand(rng), m_sk))
    }

    pub fn generate_using_seed<D>(seed: &[u8], size: usize) -> Result<Self, DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let m_sk = SecretKey::generate_using_seed::<D>(seed, size)?;
        Ok(Self(
            field_elem_from_seed::<E::Fr, D>(seed, "MERCURIAL-SIG-KEYGEN-SALT-0".as_bytes()),
            m_sk,
        ))
    }
}

impl<E: PairingEngine> Drop for RootIssuerSecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
        self.1 .0.zeroize();
    }
}

impl<E: PairingEngine> RootIssuerPublicKey<E> {
    pub fn new(secret_key: &RootIssuerSecretKey<E>, P1: &E::G1Affine, P2: &E::G2Affine) -> Self {
        let x_0 = secret_key.0.into_repr();
        Self {
            X_0: P1.mul(x_0).into_affine(),
            X_0_hat: P2.mul(x_0).into_affine(),
            X: PublicKey::new(&secret_key.1, P2),
        }
    }

    pub fn prepared(&self) -> PreparedRootIssuerPublicKey<E> {
        PreparedRootIssuerPublicKey {
            X_0: self.X_0,
            X_0_hat: E::G2Prepared::from(self.X_0_hat),
            X: self.X.prepared(),
        }
    }
}

impl<E: PairingEngine> Drop for UserSecretKey<E> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<E: PairingEngine> UserSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(E::Fr::rand(rng))
    }

    pub fn randomize(&self, psi: &E::Fr, chi: &E::Fr) -> Self {
        Self((self.0 + chi) * psi)
    }
}

impl<E: PairingEngine> UserPublicKey<E> {
    pub fn new(secret_key: &UserSecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(P1.mul(secret_key.0.into_repr()).into_affine())
    }

    pub fn randomize<R: RngCore>(&self, rng: &mut R, P1: &E::G1Affine) -> (Self, E::Fr, E::Fr) {
        let psi = E::Fr::rand(rng);
        let chi = E::Fr::rand(rng);
        (
            self.randomize_using_given_randomness(&psi, &chi, P1),
            psi,
            chi,
        )
    }

    pub fn randomize_using_given_randomness(
        &self,
        psi: &E::Fr,
        chi: &E::Fr,
        P1: &E::G1Affine,
    ) -> Self {
        // (upk + (P1 * chi)) * psi
        Self(
            P1.mul(chi.into_repr())
                .add_mixed(&self.0)
                .mul(psi.into_repr())
                .into_affine(),
        )
    }
}

impl<E: PairingEngine> Drop for UpdateKey<E> {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

impl<E: PairingEngine> UpdateKey<E> {
    pub fn randomize(&self, r: &E::Fr) -> Self {
        let r_repr = r.into_repr();
        Self {
            start_index: self.start_index,
            max_attributes_per_commitment: self.max_attributes_per_commitment,
            keys: cfg_iter!(self.keys)
                .map(|k| {
                    let j = cfg_iter!(k).map(|j| j.mul(r_repr)).collect::<Vec<_>>();
                    batch_normalize_projective_into_affine(j)
                })
                .collect::<Vec<_>>(),
        }
    }

    pub fn verify(
        &self,
        sig: &Signature<E>,
        public_key: &RootIssuerPublicKey<E>,
        t: usize,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self._verify(
            sig,
            cfg_iter!(public_key.X.0[self.start_index..=self.end_index()])
                .map(|p| E::G2Prepared::from(*p))
                .collect(),
            t,
            srs,
        )
    }

    pub fn verify_using_prepared_key(
        &self,
        sig: &Signature<E>,
        public_key: &PreparedRootIssuerPublicKey<E>,
        t: usize,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self._verify(
            sig,
            public_key.X.0[self.start_index..=self.end_index()].to_vec(),
            t,
            srs,
        )
    }

    pub fn get_key_for_index(&self, index: usize) -> &[E::G1Affine] {
        &self.keys[index - self.start_index]
    }

    /// Largest 0-based index supported by this update key
    pub fn end_index(&self) -> usize {
        self.start_index + self.keys.len() - 1
    }

    pub fn trim_key(&self, start: usize, end: usize) -> Self {
        Self {
            start_index: start,
            max_attributes_per_commitment: self.max_attributes_per_commitment,
            keys: self.keys[(start - self.start_index)..(end - self.start_index + 1)].to_vec(),
        }
    }

    fn _verify(
        &self,
        sig: &Signature<E>,
        x_prep: Vec<E::G2Prepared>,
        t: usize,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let sum = cfg_iter!(srs.P1[0..t]).sum::<E::G1Affine>();
        let mut a = vec![sum; x_prep.len()];
        let mut b = x_prep;
        a.push(
            self.keys
                .iter()
                .fold(E::G1Affine::zero(), |sum, v| {
                    sum + cfg_iter!(v).sum::<E::G1Affine>()
                })
                .neg(),
        );
        b.push(E::G2Prepared::from(sig.comm_sig.Y_tilde));
        if !pairing_product_with_g2_prepared::<E>(&a, &b).is_one() {
            return Err(DelegationError::InvalidUpdateKey);
        }
        Ok(())
    }
}
