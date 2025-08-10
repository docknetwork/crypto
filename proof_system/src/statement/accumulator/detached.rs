use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use vb_accumulator::prelude::{
    MembershipProvingKey, NonMembershipProvingKey, PublicKey, SetupParams as AccumParams,
};

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DetachedAccumulatorMembershipProver<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<MembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: Pairing> DetachedAccumulatorMembershipProver<E> {
    /// Create a statement by passing the accumulator params, public key and proving key directly.
    pub fn new_statement_from_params(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorMembershipProver(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
    pub fn new_statement_from_params_ref(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorMembershipProver(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    impl_getters!(
        AccumParams,
        VbAccumulatorParams,
        PublicKey,
        VbAccumulatorPublicKey,
        MembershipProvingKey,
        VbAccumulatorMemProvingKey
    );
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DetachedAccumulatorMembershipVerifier<E: Pairing> {
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<MembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: Pairing> DetachedAccumulatorMembershipVerifier<E> {
    /// Create a statement by passing the accumulator params, public key and proving key directly.
    pub fn new_statement_from_params(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: MembershipProvingKey<E::G1Affine>,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorMembershipVerifier(Self {
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
    pub fn new_statement_from_params_ref(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorMembershipVerifier(Self {
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    impl_getters!(
        AccumParams,
        VbAccumulatorParams,
        PublicKey,
        VbAccumulatorPublicKey,
        MembershipProvingKey,
        VbAccumulatorMemProvingKey
    );
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DetachedAccumulatorNonMembershipProver<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub accumulator_value: E::G1Affine,
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<NonMembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: Pairing> DetachedAccumulatorNonMembershipProver<E> {
    /// Create a statement by passing the accumulator params, public key and proving key directly.
    pub fn new_statement_from_params(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorNonMembershipProver(Self {
            accumulator_value,
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
    pub fn new_statement_from_params_ref(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
        accumulator_value: E::G1Affine,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorNonMembershipProver(Self {
            accumulator_value,
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    impl_getters!(
        AccumParams,
        VbAccumulatorParams,
        PublicKey,
        VbAccumulatorPublicKey,
        NonMembershipProvingKey,
        VbAccumulatorNonMemProvingKey
    );
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DetachedAccumulatorNonMembershipVerifier<E: Pairing> {
    pub params: Option<AccumParams<E>>,
    pub public_key: Option<PublicKey<E>>,
    pub proving_key: Option<NonMembershipProvingKey<E::G1Affine>>,
    pub params_ref: Option<usize>,
    pub public_key_ref: Option<usize>,
    pub proving_key_ref: Option<usize>,
}

impl<E: Pairing> DetachedAccumulatorNonMembershipVerifier<E> {
    /// Create a statement by passing the accumulator params, public key and proving key directly.
    pub fn new_statement_from_params(
        params: AccumParams<E>,
        public_key: PublicKey<E>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorNonMembershipVerifier(Self {
            params: Some(params),
            public_key: Some(public_key),
            proving_key: Some(proving_key),
            params_ref: None,
            public_key_ref: None,
            proving_key_ref: None,
        })
    }

    /// Create a statement by passing the indices of accumulator params, public key and proving key in `SetupParams`.
    pub fn new_statement_from_params_ref(
        params_ref: usize,
        public_key_ref: usize,
        proving_key_ref: usize,
    ) -> Statement<E> {
        Statement::DetachedAccumulatorNonMembershipVerifier(Self {
            params: None,
            public_key: None,
            proving_key: None,
            params_ref: Some(params_ref),
            public_key_ref: Some(public_key_ref),
            proving_key_ref: Some(proving_key_ref),
        })
    }

    impl_getters!(
        AccumParams,
        VbAccumulatorParams,
        PublicKey,
        VbAccumulatorPublicKey,
        NonMembershipProvingKey,
        VbAccumulatorNonMemProvingKey
    );
}
