use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    affine_group_element_from_byte_slices, concat_slices,
    hashing_utils::affine_group_elem_from_try_and_incr, serde_utils::ArkObjectBytes,
};
use schnorr_pok::{error::SchnorrError, SchnorrChallengeContributor};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Public parameters for creating and verifying BB signatures
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SignatureParams<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g1: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g2: E::G2Affine,
}

/// `SignatureParams` with pre-computation done for protocols to be more efficient
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureParamsWithPairing<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub g2_prepared: E::G2Prepared,
    /// pairing e(g1, g2)
    pub g1g2: PairingOutput<E>,
}

impl<E: Pairing> SignatureParams<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g1 =
            affine_group_elem_from_try_and_incr::<E::G1Affine, D>(&concat_slices![label, b" : g1"]);
        let g2 =
            affine_group_elem_from_try_and_incr::<E::G2Affine, D>(&concat_slices![label, b" : g2"]);
        Self { g1, g2 }
    }

    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self {
            g1: E::G1::rand(rng).into(),
            g2: E::G2::rand(rng).into(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !(self.g1.is_zero() || self.g2.is_zero())
    }
}

impl<E: Pairing> From<SignatureParams<E>> for SignatureParamsWithPairing<E> {
    fn from(params: SignatureParams<E>) -> Self {
        let g1g2 = E::pairing(params.g1, params.g2);
        Self {
            g1: params.g1,
            g2: params.g2,
            g2_prepared: E::G2Prepared::from(params.g2),
            g1g2,
        }
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for SignatureParams<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.g1
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for SignatureParamsWithPairing<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.g1
    }
}

/// The public parameters used during the proof of knowledge of signature are called `ProvingKey`. These are mutually
/// agreed upon by the prover and verifier and can be same or different between different provers and verifiers
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProvingKey<G: AffineRepr> {
    /// Called `u` in the paper
    #[serde_as(as = "ArkObjectBytes")]
    pub X: G,
    /// Called `v` in the paper
    #[serde_as(as = "ArkObjectBytes")]
    pub Y: G,
    /// Called `h` in the paper
    #[serde_as(as = "ArkObjectBytes")]
    pub Z: G,
}

impl<G: AffineRepr> ProvingKey<G> {
    /// Generate using a random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> ProvingKey<G> {
        ProvingKey {
            X: G::Group::rand(rng).into(),
            Y: G::Group::rand(rng).into(),
            Z: G::Group::rand(rng).into(),
        }
    }

    /// Generate by hashing known strings
    pub fn generate_using_hash<D: Digest>(label: &[u8]) -> ProvingKey<G> {
        // 3 G1 elements
        ProvingKey {
            X: affine_group_element_from_byte_slices![label, b" : X"],
            Y: affine_group_element_from_byte_slices![label, b" : Y"],
            Z: affine_group_element_from_byte_slices![label, b" : Z"],
        }
    }
}

impl<G: AffineRepr> AsRef<ProvingKey<G>> for ProvingKey<G> {
    fn as_ref(&self) -> &ProvingKey<G> {
        &self
    }
}

impl<G: AffineRepr> SchnorrChallengeContributor for ProvingKey<G> {
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.X.serialize_compressed(&mut writer)?;
        self.Y.serialize_compressed(&mut writer)?;
        self.Z
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}
