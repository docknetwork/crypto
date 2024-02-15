use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
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

macro_rules! impl_common_funcs {
    ($fn_from_params: ident, $fn_from_params_refs: ident, $fn_get_comm_key: ident, $group: ident, $stmt_variant: ident, $setup_param_variant: ident) => {
        pub fn $fn_from_params<E: Pairing<$group = G>>(key: Vec<G>, commitment: G) -> Statement<E> {
            Statement::$stmt_variant(Self {
                commitment,
                key: Some(key),
                key_ref: None,
            })
        }

        pub fn $fn_from_params_refs<E: Pairing<$group = G>>(
            key_ref: usize,
            commitment: G,
        ) -> Statement<E> {
            Statement::$stmt_variant(Self {
                commitment,
                key: None,
                key_ref: Some(key_ref),
            })
        }

        pub fn $fn_get_comm_key<'a, E: Pairing<$group = G>>(
            &'a self,
            setup_params: &'a [SetupParams<E>],
            st_idx: usize,
        ) -> Result<&'a Vec<G>, ProofSystemError> {
            extract_param!(
                setup_params,
                &self.key,
                self.key_ref,
                $setup_param_variant,
                IncompatiblePedCommSetupParamAtIndex,
                st_idx
            )
        }
    };
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineRepr> PedersenCommitment<G> {
    impl_common_funcs!(
        new_statement_from_params,
        new_statement_from_params_refs,
        get_commitment_key,
        G1Affine,
        PedersenCommitment,
        PedersenCommitmentKey
    );

    impl_common_funcs!(
        new_statement_from_params_g2,
        new_statement_from_params_refs_g2,
        get_commitment_key_g2,
        G2Affine,
        PedersenCommitmentG2,
        PedersenCommitmentKeyG2
    );
}
