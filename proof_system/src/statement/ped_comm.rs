use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::ProofSystemError;
use crate::setup_params::SetupParams;
use crate::statement::Statement;
use dock_crypto_utils::serde_utils::*;

/// Proving knowledge of scalars `s_i` in Pedersen commitment `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitment<G: AffineRepr> {
    /// The Pedersen commitment `C` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: G,
    /// Commitment key `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "Option<Vec<ArkObjectBytes>>")]
    pub key: Option<Vec<G>>,
    pub key_ref: Option<usize>,
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineRepr> PedersenCommitment<G> {
    pub fn new_statement_from_params<E: Pairing>(key: Vec<G>, commitment: G) -> Statement<E, G> {
        Statement::PedersenCommitment(Self {
            commitment,
            key: Some(key),
            key_ref: None,
        })
    }

    pub fn new_statement_from_params_refs<E: Pairing>(
        key_ref: usize,
        commitment: G,
    ) -> Statement<E, G> {
        Statement::PedersenCommitment(Self {
            commitment,
            key: None,
            key_ref: Some(key_ref),
        })
    }

    pub fn get_commitment_key<'a, E: Pairing>(
        &'a self,
        setup_params: &'a [SetupParams<E, G>],
        st_idx: usize,
    ) -> Result<&'a Vec<G>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.key,
            self.key_ref,
            PedersenCommitmentKey,
            IncompatiblePedCommSetupParamAtIndex,
            st_idx
        )
    }
}
