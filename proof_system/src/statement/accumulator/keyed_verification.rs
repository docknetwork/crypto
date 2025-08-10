use crate::statement::Statement;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use vb_accumulator::setup::SecretKey;

macro_rules! impl_struct_and_funcs {
    ($(#[$doc:meta])*
    $name:ident, $name_full_verifier: ident, $stmt_variant: ident, $stmt_full_verifier_variant: ident) => {
        #[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[cfg_attr(feature = "serde", serde(bound = ""))]
        pub struct $name<G: AffineRepr> {
            #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
            pub accumulator_value: G,
        }

        #[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[cfg_attr(feature = "serde", serde(bound = ""))]
        pub struct $name_full_verifier<G: AffineRepr> {
            #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
            pub accumulator_value: G,
            pub secret_key: SecretKey<G::ScalarField>,
        }

        impl<G: AffineRepr> $name<G> {
            pub fn new<E: Pairing<G1Affine = G>>(accumulator_value: G) -> Statement<E> {
                Statement::$stmt_variant(Self { accumulator_value })
            }
        }

        impl<G: AffineRepr> $name_full_verifier<G> {
            pub fn new<E: Pairing<G1Affine = G>>(
                accumulator_value: G,
                secret_key: SecretKey<G::ScalarField>,
            ) -> Statement<E> {
                Statement::$stmt_full_verifier_variant(Self {
                    accumulator_value,
                    secret_key,
                })
            }
        }
    };
}

impl_struct_and_funcs!(
    VBAccumulatorMembershipKV,
    VBAccumulatorMembershipKVFullVerifier,
    VBAccumulatorMembershipKV,
    VBAccumulatorMembershipKVFullVerifier
);

impl_struct_and_funcs!(
    KBUniversalAccumulatorMembershipKV,
    KBUniversalAccumulatorMembershipKVFullVerifier,
    KBUniversalAccumulatorMembershipKV,
    KBUniversalAccumulatorMembershipKVFullVerifier
);

impl_struct_and_funcs!(
    KBUniversalAccumulatorNonMembershipKV,
    KBUniversalAccumulatorNonMembershipKVFullVerifier,
    KBUniversalAccumulatorNonMembershipKV,
    KBUniversalAccumulatorNonMembershipKVFullVerifier
);
