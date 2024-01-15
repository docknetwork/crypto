use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Zeroize,
    ZeroizeOnDrop,
    Serialize,
    Deserialize,
)]
pub struct SecretKey<F: PrimeField> {
    pub sig: short_group_sig::bb_sig::SecretKey<F>,
    pub accum: crate::setup::SecretKey<F>,
}

#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PublicKey<E: Pairing> {
    pub sig: short_group_sig::bb_sig::PublicKeyG2<E>,
    pub accum: crate::setup::PublicKey<E>,
}

#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SetupParams<E: Pairing> {
    pub sig: short_group_sig::common::SignatureParams<E>,
    pub accum: crate::setup::SetupParams<E>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedPublicKey<E: Pairing> {
    pub sig: short_group_sig::bb_sig::PreparedPublicKeyG2<E>,
    pub accum: crate::setup::PreparedPublicKey<E>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedSetupParams<E: Pairing> {
    pub sig: short_group_sig::common::SignatureParamsWithPairing<E>,
    pub accum: crate::setup::PreparedSetupParams<E>,
}

impl<E: Pairing> From<SetupParams<E>> for PreparedSetupParams<E> {
    fn from(params: SetupParams<E>) -> Self {
        Self {
            sig: params.sig.into(),
            accum: params.accum.into(),
        }
    }
}

impl<E: Pairing> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(pk: PublicKey<E>) -> Self {
        Self {
            sig: pk.sig.into(),
            accum: pk.accum.into(),
        }
    }
}

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self {
            sig: short_group_sig::bb_sig::SecretKey::new(rng),
            accum: crate::setup::SecretKey::new(rng),
        }
    }
}

impl<E: Pairing> SetupParams<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        Self {
            sig: short_group_sig::common::SignatureParams::new::<D>(label),
            accum: crate::setup::SetupParams::new::<D>(label),
        }
    }
}

impl<E: Pairing> PublicKey<E> {
    pub fn new(secret_key: &SecretKey<E::ScalarField>, setup_params: &SetupParams<E>) -> Self {
        Self {
            sig: short_group_sig::bb_sig::PublicKeyG2::generate_using_secret_key(
                &secret_key.sig,
                &setup_params.sig,
            ),
            accum: crate::setup::PublicKey::new_from_secret_key(
                &secret_key.accum,
                &setup_params.accum,
            ),
        }
    }
}
