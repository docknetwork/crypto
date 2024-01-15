use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, vec::Vec};
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol for proving knowledge of discrete log
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
pub struct PokDiscreteLogProtocol<G: AffineRepr> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    blinding: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    witness: G::ScalarField,
}

/// Proof of knowledge of discrete log
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PokDiscreteLog<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response: G::ScalarField,
}

impl<G> PokDiscreteLogProtocol<G>
where
    G: AffineRepr,
{
    pub fn init(witness: G::ScalarField, blinding: G::ScalarField, base: &G) -> Self {
        let t = base.mul_bigint(blinding.into_bigint()).into_affine();
        Self {
            t,
            blinding,
            witness,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(base, y, &self.t, writer)
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> PokDiscreteLog<G> {
        let response = self.blinding + (self.witness * *challenge);
        PokDiscreteLog {
            t: self.t,
            response,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        base: &G,
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        base.serialize_compressed(&mut writer)?;
        y.serialize_compressed(&mut writer)?;
        t.serialize_compressed(writer).map_err(|e| e.into())
    }
}

impl<G> PokDiscreteLog<G>
where
    G: AffineRepr,
{
    pub fn challenge_contribution<W: Write>(
        &self,
        base: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokDiscreteLogProtocol::compute_challenge_contribution(base, y, &self.t, writer)
    }

    /// `base*response - y*challenge == t`
    pub fn verify(&self, y: &G, base: &G, challenge: &G::ScalarField) -> bool {
        let mut expected = base.mul_bigint(self.response.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }
}
