use crate::error::KVACError;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{
    affine_group_element_from_byte_slices, concat_slices,
    iter::pair_valid_items_with_slice,
    join,
    misc::{n_projective_group_elements, seq_pairs_satisfy},
    signature::MultiMessageSignatureParams,
    try_iter::CheckLeft,
};
use itertools::process_results;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Public parameters used by the MAC creator and verifier
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MACParams<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g_0: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g_tilde: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub g: G,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    pub g_vec: Vec<G>,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey<F: PrimeField>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub F,
);

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserPublicKey<G: AffineRepr>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub G,
);

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignerPublicKey<G: AffineRepr>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub G,
);

/// Designated verifier proof of knowledge of a public key.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DesignatedVerifierPoKOfPublicKey<G: AffineRepr> {
    /// The commitment to randomness
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub t: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub challenge: G::ScalarField,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub response: G::ScalarField,
}

impl<G: AffineRepr> MACParams<G> {
    pub fn new<D: Digest>(label: &[u8], message_count: u32) -> Self {
        assert_ne!(message_count, 0);
        // Group element by hashing `label`||`g_0`, `label`||`g`, `label`||`g_tilde`, and `label`||`g_i` for i in 1 to message_count.
        let (g_0, g, g_tilde, g_vec) = join!(
            affine_group_element_from_byte_slices!(label, b" : g_0"),
            affine_group_element_from_byte_slices!(label, b" : g_tilde"),
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

        Self {
            g_0,
            g,
            g_tilde,
            g_vec,
        }
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
        user_public_key: &'a UserPublicKey<G>,
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

impl<G: AffineRepr> UserPublicKey<G> {
    pub fn new<'a>(sk: &SecretKey<G::ScalarField>, g: impl Into<&'a G>) -> Self {
        Self((g.into().mul_bigint(sk.0.into_bigint())).into_affine())
    }

    pub fn new_from_params(sk: &SecretKey<G::ScalarField>, params: &MACParams<G>) -> Self {
        Self::new(sk, &params.g)
    }

    /// Return `pk + g * blinding`
    pub fn get_blinded_for_schnorr_sig<'a>(
        &self,
        blinding: &G::ScalarField,
        g: impl Into<&'a G>,
    ) -> Self {
        Self((g.into().mul_bigint(blinding.into_bigint()) + self.0).into_affine())
    }

    /// Return `pk * blinding`
    pub fn get_blinded_for_ecdsa(&self, blinding: &G::ScalarField) -> Self {
        Self(self.0.mul_bigint(blinding.into_bigint()).into_affine())
    }
}

impl<G: AffineRepr> SignerPublicKey<G> {
    pub fn new<'a>(sk: &SecretKey<G::ScalarField>, g_tilde: impl Into<&'a G>) -> Self {
        Self((g_tilde.into().mul_bigint(sk.0.into_bigint())).into_affine())
    }

    pub fn new_from_params(sk: &SecretKey<G::ScalarField>, params: &MACParams<G>) -> Self {
        Self::new(sk, &params.g_tilde)
    }
}

impl<G: AffineRepr> DesignatedVerifierPoKOfPublicKey<G> {
    pub fn new<'a, R: RngCore>(
        rng: &mut R,
        public_key: impl Into<&'a G>,
        g: impl Into<&'a G>,
    ) -> Self {
        let challenge = G::ScalarField::rand(rng);
        let response = G::ScalarField::rand(rng);
        let g = g.into();
        let pk = public_key.into();
        let t = (*g * response - *pk * challenge).into_affine();
        Self {
            t,
            challenge,
            response,
        }
    }

    pub fn verify<'a>(
        &self,
        public_key: impl Into<&'a G>,
        g: impl Into<&'a G>,
    ) -> Result<(), KVACError> {
        let g = g.into();
        let pk = public_key.into();
        if (*g * self.response - *pk * self.challenge).into_affine() != self.t {
            return Err(KVACError::InvalidPoKOfPublicKey);
        }
        Ok(())
    }
}

impl<F: PrimeField> AsRef<F> for SecretKey<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<G> for UserPublicKey<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<G> for SignerPublicKey<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: AffineRepr> AsRef<MACParams<G>> for MACParams<G> {
    fn as_ref(&self) -> &MACParams<G> {
        self
    }
}
