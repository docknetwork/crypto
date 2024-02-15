#![allow(non_snake_case)]

//! Membership and non-membership protocols using CDH approach with BB and weak-BB signatures

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::common::ProvingKey;
use vb_accumulator::{
    kb_positive_accumulator::setup::{PublicKey as KBAccumPk, SetupParams as KBAccumParams},
    prelude::{PublicKey, SetupParams as AccumParams},
};

macro_rules! impl_cdh_struct_and_funcs {
    ($(#[$doc:meta])*
    $prover_name:ident, $verifier_name: ident, $prover_statement_type: ident, $verifier_statement_type: ident) => {
        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        #[serde(bound = "")]
        pub struct $prover_name<E: Pairing> {
            #[serde_as(as = "ArkObjectBytes")]
            pub accumulator_value: E::G1Affine,
        }

        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        #[serde(bound = "")]
        pub struct $verifier_name<E: Pairing> {
            #[serde_as(as = "ArkObjectBytes")]
            pub accumulator_value: E::G1Affine,
            pub params: Option<AccumParams<E>>,
            pub public_key: Option<PublicKey<E>>,
            pub params_ref: Option<usize>,
            pub public_key_ref: Option<usize>,
        }

        impl<E: Pairing> $prover_name<E> {
            pub fn new(accumulator_value: E::G1Affine) -> Statement<E> {
                Statement::$prover_statement_type(Self { accumulator_value })
            }
        }

        impl<E: Pairing> $verifier_name<E> {
            pub fn new_statement_from_params(
                params: AccumParams<E>,
                public_key: PublicKey<E>,
                accumulator_value: E::G1Affine,
            ) -> Statement<E> {
                Statement::$verifier_statement_type(Self {
                    accumulator_value,
                    params: Some(params),
                    public_key: Some(public_key),
                    params_ref: None,
                    public_key_ref: None,
                })
            }

            pub fn new_statement_from_params_ref(
                params_ref: usize,
                public_key_ref: usize,
                accumulator_value: E::G1Affine,
            ) -> Statement<E> {
                Statement::$verifier_statement_type(Self {
                    accumulator_value,
                    params: None,
                    public_key: None,
                    params_ref: Some(params_ref),
                    public_key_ref: Some(public_key_ref),
                })
            }

            impl_pk_and_param_getters!(
                AccumParams,
                VbAccumulatorParams,
                PublicKey,
                VbAccumulatorPublicKey
            );
        }
    };
}

impl_cdh_struct_and_funcs!(
    ///
    VBAccumulatorMembershipCDHProver,
    VBAccumulatorMembershipCDHVerifier,
    VBAccumulatorMembershipCDHProver,
    VBAccumulatorMembershipCDHVerifier
);

impl_cdh_struct_and_funcs!(
    ///
    KBUniversalAccumulatorMembershipCDHProver,
    KBUniversalAccumulatorMembershipCDHVerifier,
    KBUniversalAccumulatorMembershipCDHProver,
    KBUniversalAccumulatorMembershipCDHVerifier
);

impl_cdh_struct_and_funcs!(
    ///
    KBUniversalAccumulatorNonMembershipCDHProver,
    KBUniversalAccumulatorNonMembershipCDHVerifier,
    KBUniversalAccumulatorNonMembershipCDHProver,
    KBUniversalAccumulatorNonMembershipCDHVerifier
);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VBAccumulatorNonMembershipCDHProver<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Q: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub params_ref: Option<usize>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VBAccumulatorNonMembershipCDHVerifier<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator_value: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub Q: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
}

impl<E: Pairing> VBAccumulatorNonMembershipCDHProver<E> {
    pub fn new_statement_from_params(
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
        params: AccumParams<E>,
    ) -> Statement<E> {
        Statement::VBAccumulatorNonMembershipCDHProver(Self {
            accumulator_value,
            Q,
            params: Some(params),
            params_ref: None,
        })
    }

    pub fn new_statement_from_params_ref(
        params_ref: usize,
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
    ) -> Statement<E> {
        Statement::VBAccumulatorNonMembershipCDHProver(Self {
            accumulator_value,
            Q,
            params: None,
            params_ref: Some(params_ref),
        })
    }

    pub fn get_params<'a>(
        &'a self,
        setup_params: &'a [SetupParams<E>],
        st_idx: usize,
    ) -> Result<&'a AccumParams<E>, ProofSystemError> {
        extract_param!(
            setup_params,
            &self.params,
            self.params_ref,
            VbAccumulatorParams,
            IncompatibleAccumulatorSetupParamAtIndex,
            st_idx
        )
    }
}

impl<E: Pairing> VBAccumulatorNonMembershipCDHVerifier<E> {
    pub fn new_statement_from_params(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
    ) -> Statement<E> {
        Statement::VBAccumulatorNonMembershipCDHVerifier(Self {
            accumulator_value,
            Q,
            params: Some(params),
            public_key: Some(public_key),
            params_ref: None,
            public_key_ref: None,
        })
    }

    pub fn new_statement_from_params_ref(
        params_ref: usize,
        public_key_ref: usize,
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
    ) -> Statement<E> {
        Statement::VBAccumulatorNonMembershipCDHVerifier(Self {
            accumulator_value,
            Q,
            params: None,
            public_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
        })
    }

    impl_pk_and_param_getters!(
        AccumParams,
        VbAccumulatorParams,
        PublicKey,
        VbAccumulatorPublicKey
    );
}

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving membership
    /// in KB positive accumulator.
    KBPositiveAccumulatorMembershipCDH,
    KBAccumParams,
    KBPositiveAccumulatorParams,
    KBAccumPk,
    KBPositiveAccumulatorPublicKey,
    KBPositiveAccumulatorMembershipCDH,
    ProvingKey,
    BBSigProvingKey
);
