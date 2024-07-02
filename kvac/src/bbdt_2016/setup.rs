use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, rand::RngCore, vec::Vec};
use core::iter::once;
use digest::{Digest, DynDigest};
use dock_crypto_utils::{
    affine_group_element_from_byte_slices, concat_slices,
    hashing_utils::hash_to_field,
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

use crate::error::KVACError;

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
    #[serde_as(as = "ArkObjectBytes")]
    pub h: G,
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

/// An optional key that can be used to verify that the MAC is correctly constructed without verifying it or when the MAC
/// is used as a signature
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

impl<G: AffineRepr> MACParams<G> {
    pub fn new<D: Digest>(label: &[u8], message_count: u32) -> Self {
        assert_ne!(message_count, 0);
        // Group element by hashing `label`||`g_0`, `label`||`g`, `label`||`h` , and `label`||`g_i` for i in 1 to message_count.
        let (g_0, g, h, g_vec) = join!(
            affine_group_element_from_byte_slices!(label, b" : g_0"),
            affine_group_element_from_byte_slices!(label, b" : g"),
            affine_group_element_from_byte_slices!(label, b" : h"),
            {
                let h: Vec<_> = n_projective_group_elements::<G, D>(
                    1..message_count + 1,
                    &concat_slices!(label, b" : g_"),
                )
                .collect();
                G::Group::normalize_batch(&h)
            }
        );

        Self { g_0, g, h, g_vec }
    }

    /// Commit to given messages using the parameters and the given blinding as a Pedersen commitment.
    /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
    /// an error will be returned.
    /// Eg. if given messages `m_i`, `m_j`, and `m_k` in the iterator, the commitment converts messages to
    /// scalars and multiplies them by the parameter curve points:
    /// `params.g * blinding + params.g_vec_i * m_i + params.g_vec_j * m_j + params.g_vec_k * m_k`
    /// Computes using multi-scalar multiplication
    pub fn commit_to_messages<'a, MI>(
        &self,
        indexed_messages_sorted_by_index: MI,
        blinding: &'a G::ScalarField,
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
            |iter| iter.chain(once((&self.g, blinding))).unzip(),
        )?;

        Ok(G::Group::msm_unchecked(&bases, &scalars).into_affine())
    }

    /// Compute `b = A*{e+x}`
    /// `indexed_messages_sorted_by_index` must produce items sorted by unique indices, otherwise,
    /// an error will be returned.
    /// Commits to the given messages and adds `self.h` to it,
    /// `b = h + sum(g_vec_i * m_i)` for all indices `i` in the map.
    pub fn b<'a, MI>(
        &self,
        indexed_messages_sorted_by_index: MI,
        s: &'a G::ScalarField,
    ) -> Result<G::Group, KVACError>
    where
        MI: IntoIterator<Item = (usize, &'a G::ScalarField)>,
    {
        let commitment = self.commit_to_messages(indexed_messages_sorted_by_index, s)?;
        Ok(commitment + self.h)
    }

    pub fn is_valid(&self) -> bool {
        !(self.g_0.is_zero()
            || self.g.is_zero()
            || self.h.is_zero()
            || cfg_iter!(self.g_vec).any(|v| v.is_zero()))
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
    pub const DST: &'static [u8] = b"BDDT16-MAC-KEYGEN-SALT";

    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }

    pub fn generate_using_seed<D: DynDigest + Default + Clone>(seed: &[u8]) -> Self {
        Self(hash_to_field::<F, D>(Self::DST, seed))
    }
}

impl<G: AffineRepr> PublicKey<G> {
    pub fn new<'a>(sk: &SecretKey<G::ScalarField>, g_0: impl Into<&'a G>) -> Self {
        Self((g_0.into().mul_bigint(sk.0.into_bigint())).into_affine())
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
