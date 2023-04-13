use alloc::vec::Vec;
use ark_ec::AffineRepr;

use ark_serialize::*;

use serde::{de::DeserializeOwned, Serialize};
use utils::aliases::CanonicalSerDe;

use schnorr_pok::{error::SchnorrError, SchnorrChallengeContributor, SchnorrCommitment};

/// Combines value with the `SchnorrCommitment` **including blindings**.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[serde(bound = "V: Serialize + DeserializeOwned")]
pub struct WithSchnorrAndBlindings<G: AffineRepr, V: CanonicalSerDe> {
    pub schnorr: SchnorrCommitment<G>,
    pub value: V,
}

impl<G: AffineRepr, V: CanonicalSerDe> WithSchnorrAndBlindings<G, V> {
    /// Combines value with the `SchnorrCommitment` **including blindings**.
    pub fn new(value: V, schnorr: SchnorrCommitment<G>) -> Self {
        Self { value, schnorr }
    }
}

impl<G, V> SchnorrChallengeContributor for WithSchnorrAndBlindings<G, V>
where
    G: AffineRepr,
    V: CanonicalSerDe,
{
    /// The commitment's contribution to the overall challenge of the protocol.
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.value
            .serialize_compressed(&mut writer)
            .map_err(SchnorrError::Serialization)?;
        self.schnorr.challenge_contribution(&mut writer)
    }
}

impl<G: AffineRepr, V: CanonicalSerDe> From<(V, SchnorrCommitment<G>)>
    for WithSchnorrAndBlindings<G, V>
{
    fn from((value, schnorr): (V, SchnorrCommitment<G>)) -> Self {
        Self { value, schnorr }
    }
}

impl<G: AffineRepr, V: CanonicalSerDe> From<WithSchnorrAndBlindings<G, V>>
    for (V, SchnorrCommitment<G>)
{
    fn from(WithSchnorrAndBlindings { value, schnorr }: WithSchnorrAndBlindings<G, V>) -> Self {
        (value, schnorr)
    }
}
