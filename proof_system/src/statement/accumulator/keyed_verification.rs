use crate::statement::Statement;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::setup::SecretKey;

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VBAccumulatorMembershipKV<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: G,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VBAccumulatorMembershipKVFullVerifier<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: G,
    pub secret_key: SecretKey<G::ScalarField>,
}

impl<G: AffineRepr> VBAccumulatorMembershipKV<G> {
    pub fn new<E: Pairing<G1Affine = G>>(accumulator_value: G) -> Statement<E> {
        Statement::VBAccumulatorMembershipKV(Self { accumulator_value })
    }
}

impl<G: AffineRepr> VBAccumulatorMembershipKVFullVerifier<G> {
    pub fn new<E: Pairing<G1Affine = G>>(
        accumulator_value: G,
        secret_key: SecretKey<G::ScalarField>,
    ) -> Statement<E> {
        Statement::VBAccumulatorMembershipKVFullVerifier(Self {
            accumulator_value,
            secret_key,
        })
    }
}
