use crate::{
    error::DelegationError,
    mercurial_sig::{PreparedPublicKey, PublicKey, SecretKey},
    msbm::sps_eq_uc_sig::Signature,
    set_commitment::SetCommitmentSRS,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dock_crypto_utils::{
    aliases::{FullDigest, SyncIfParallel},
    hashing_utils::hash_to_field,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Secret key of the form `(x_0, (x_1, x_2, x_3, ..., x_n))`. The key `(x_1, x_2, x_3, ..., x_n)` is the
/// secret key for the Mercurial signature scheme
#[derive(
    Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct RootIssuerSecretKey<E: Pairing>(pub E::ScalarField, pub SecretKey<E>);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RootIssuerPublicKey<E: Pairing> {
    /// `x_0*P1`
    pub X_0: E::G1Affine,
    /// `x_0*P2`
    pub X_0_hat: E::G2Affine,
    /// Mercurial signature public key corresponding to secret key `(x_1, x_2, x_3, ..., x_n)`
    pub X: PublicKey<E>,
}

#[derive(Clone, Debug)]
pub struct PreparedRootIssuerPublicKey<E: Pairing> {
    pub X_0: E::G1Affine,
    pub X_0_hat: E::G2Prepared,
    pub X: PreparedPublicKey<E>,
}

#[derive(
    Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct UserSecretKey<E: Pairing>(pub E::ScalarField);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserPublicKey<E: Pairing>(pub E::G1Affine);

/// Key to update the credential, i.e. extend it with more commitments
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct UpdateKey<E: Pairing> {
    /// 0-based commitment index in the credential from which this key can add commitments
    #[zeroize(skip)]
    pub start_index: u32,
    #[zeroize(skip)]
    pub max_attributes_per_commitment: u32,
    /// One key for each commitment index in the signature
    pub keys: Vec<Vec<E::G1Affine>>,
}

impl<E: Pairing> RootIssuerSecretKey<E> {
    pub const DST: &'static [u8] = b"MERCURIAL-SIG-KEYGEN-SALT-0";

    pub fn new<R: RngCore>(rng: &mut R, size: u32) -> Result<Self, DelegationError> {
        let m_sk = SecretKey::new(rng, size)?;
        Ok(Self(E::ScalarField::rand(rng), m_sk))
    }

    pub fn generate_using_seed<D>(seed: &[u8], size: u32) -> Result<Self, DelegationError>
    where
        D: FullDigest + SyncIfParallel,
    {
        let m_sk = SecretKey::generate_using_seed::<D>(seed, size)?;
        Ok(Self(
            hash_to_field::<E::ScalarField, D>(Self::DST, seed),
            m_sk,
        ))
    }
}

impl<E: Pairing> RootIssuerPublicKey<E> {
    pub fn new(secret_key: &RootIssuerSecretKey<E>, P1: &E::G1Affine, P2: &E::G2Affine) -> Self {
        let x_0 = secret_key.0.into_bigint();
        Self {
            X_0: P1.mul_bigint(x_0).into_affine(),
            X_0_hat: P2.mul_bigint(x_0).into_affine(),
            X: PublicKey::new(&secret_key.1, P2),
        }
    }
}

impl<E: Pairing> From<RootIssuerPublicKey<E>> for PreparedRootIssuerPublicKey<E> {
    fn from(pk: RootIssuerPublicKey<E>) -> Self {
        Self {
            X_0: pk.X_0,
            X_0_hat: E::G2Prepared::from(pk.X_0_hat),
            X: PreparedPublicKey::from(pk.X),
        }
    }
}

impl<E: Pairing> UserSecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(E::ScalarField::rand(rng))
    }

    pub fn randomize(&self, psi: &E::ScalarField, chi: &E::ScalarField) -> Self {
        Self((self.0 + chi) * psi)
    }
}

impl<E: Pairing> UserPublicKey<E> {
    pub fn new(secret_key: &UserSecretKey<E>, P1: &E::G1Affine) -> Self {
        Self(P1.mul_bigint(secret_key.0.into_bigint()).into_affine())
    }

    pub fn randomize<R: RngCore>(
        &self,
        rng: &mut R,
        P1: &E::G1Affine,
    ) -> (Self, E::ScalarField, E::ScalarField) {
        let psi = E::ScalarField::rand(rng);
        let chi = E::ScalarField::rand(rng);
        (
            self.randomize_using_given_randomness(&psi, &chi, P1),
            psi,
            chi,
        )
    }

    pub fn randomize_using_given_randomness(
        &self,
        psi: &E::ScalarField,
        chi: &E::ScalarField,
        P1: &E::G1Affine,
    ) -> Self {
        // (upk + (P1 * chi)) * psi
        Self(
            (P1.mul_bigint(chi.into_bigint()) + self.0)
                .mul_bigint(psi.into_bigint())
                .into_affine(),
        )
    }
}

impl<E: Pairing> UpdateKey<E> {
    pub fn randomize(&self, r: &E::ScalarField) -> Self {
        let r_repr = r.into_bigint();
        Self {
            start_index: self.start_index,
            max_attributes_per_commitment: self.max_attributes_per_commitment,
            keys: cfg_iter!(self.keys)
                .map(|k| {
                    let j = cfg_iter!(k)
                        .map(|j| j.mul_bigint(r_repr))
                        .collect::<Vec<_>>();
                    E::G1::normalize_batch(&j)
                })
                .collect::<Vec<_>>(),
        }
    }

    pub fn verify(
        &self,
        sig: &Signature<E>,
        public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        t: u32,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let public_key = public_key.into();
        self._verify(
            sig,
            public_key.X.0[self.start_index as usize..=self.end_index() as usize].to_vec(),
            t,
            srs,
        )
    }

    pub fn get_key_for_index(&self, index: u32) -> &[E::G1Affine] {
        &self.keys[index as usize - self.start_index as usize]
    }

    /// Largest 0-based index supported by this update key
    pub fn end_index(&self) -> u32 {
        self.start_index + self.keys.len() as u32 - 1
    }

    pub fn trim_key(&self, start_index: u32, end_index: u32) -> Self {
        Self {
            start_index,
            max_attributes_per_commitment: self.max_attributes_per_commitment,
            keys: self.keys[(start_index - self.start_index) as usize
                ..(end_index - self.start_index + 1) as usize]
                .to_vec(),
        }
    }

    fn _verify(
        &self,
        sig: &Signature<E>,
        x_prep: Vec<E::G2Prepared>,
        t: u32,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let sum = cfg_iter!(srs.P1[0..t as usize])
            .sum::<E::G1>()
            .into_affine();
        let mut a = vec![sum; x_prep.len()];
        let mut b = x_prep;
        a.push(
            // -\sum_{i}(\sum_{k}(k[i][j]))
            self.keys
                .iter()
                .fold(E::G1::zero(), |sum, v| sum + cfg_iter!(v).sum::<E::G1>())
                .neg()
                .into_affine(),
        );
        b.push(E::G2Prepared::from(sig.comm_sig.Y_tilde));
        if !E::multi_pairing(a, b).is_zero() {
            return Err(DelegationError::InvalidUpdateKey);
        }
        Ok(())
    }
}
