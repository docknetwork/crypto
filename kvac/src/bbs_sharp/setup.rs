use crate::error::KVACError;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    affine_group_element_from_byte_slices, concat_slices,
    iter::pair_valid_items_with_slice,
    join,
    misc::{n_projective_group_elements, seq_pairs_satisfy},
    serde_utils::ArkObjectBytes,
    signature::MultiMessageSignatureParams,
    try_iter::CheckLeft,
};
use itertools::process_results;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Public parameters used by the MAC creator and verifier
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MACParams<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g_0: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub g: G,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub g_vec: Vec<G>,
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
    ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField>(#[serde_as(as = "ArkObjectBytes")] pub F);

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

impl<G: AffineRepr> MACParams<G> {
    pub fn new<D: Digest>(label: &[u8], message_count: u32) -> Self {
        assert_ne!(message_count, 0);
        // Group element by hashing `label`||`g_0`, `label`||`g`, and `label`||`g_i` for i in 1 to message_count.
        let (g_0, g, g_vec) = join!(
            affine_group_element_from_byte_slices!(label, b" : g_0"),
            affine_group_element_from_byte_slices!(label, b" : g"),
            {
                let g: Vec<_> = n_projective_group_elements::<G, D>(
                    1..message_count + 1,
                    &concat_slices!(label, b" : g_"),
                )
                .collect();
                G::Group::normalize_batch(&g)
            }
        );

        Self { g_0, g, g_vec }
    }

    pub fn commit_to_messages<'a, MI>(
        &self,
        indexed_messages_sorted_by_index: MI,
    ) -> Result<G, KVACError>
    where
        MI: IntoIterator<Item = (usize, &'a G::ScalarField)>,
    {
        let (bases, scalars): (Vec<_>, Vec<_>) = process_results(
            pair_valid_items_with_slice::<_, _, _, KVACError, _>(
                indexed_messages_sorted_by_index,
                CheckLeft(seq_pairs_satisfy(|a, b| a < b)),
                &self.g_vec,
            ),
            |iter| iter.unzip(),
        )?;

        Ok(G::Group::msm_unchecked(&bases, &scalars).into_affine())
    }

    /// Used to create whats called `B` in the paper. `B = g_0 + user_public_key + \sum_i{g_i * m_i}`
    pub fn b<'a, MI>(
        &self,
        indexed_messages_sorted_by_index: MI,
        user_public_key: &'a PublicKey<G>,
    ) -> Result<G::Group, KVACError>
    where
        MI: IntoIterator<Item = (usize, &'a G::ScalarField)>,
    {
        let commitment = self.commit_to_messages(indexed_messages_sorted_by_index)?;
        Ok(commitment + self.g_0 + user_public_key.0)
    }
}

impl<G: AffineRepr> MultiMessageSignatureParams for MACParams<G> {
    fn supported_message_count(&self) -> usize {
        self.g_vec.len()
    }
}

impl<G: AffineRepr> MultiMessageSignatureParams for &MACParams<G> {
    fn supported_message_count(&self) -> usize {
        self.g_vec.len()
    }
}

impl<F: PrimeField> SecretKey<F> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }
}

impl<G: AffineRepr> PublicKey<G> {
    pub fn new<'a>(sk: &SecretKey<G::ScalarField>, g: impl Into<&'a G>) -> Self {
        Self((g.into().mul_bigint(sk.0.into_bigint())).into_affine())
    }

    /// Return `pk + g * blinding`
    pub fn get_blinded<'a>(&self, blinding: &G::ScalarField, g: impl Into<&'a G>) -> Self {
        Self((g.into().mul_bigint(blinding.into_bigint()) + self.0).into_affine())
    }
}

impl<F: PrimeField> AsRef<F> for SecretKey<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<G> for PublicKey<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<MACParams<G>> for MACParams<G> {
    fn as_ref(&self) -> &MACParams<G> {
        &self
    }
}
