#[macro_use]
mod macros;
#[macro_use]
pub mod cdh;
pub mod detached;
pub mod keyed_verification;

use crate::{error::ProofSystemError, setup_params::SetupParams, statement::Statement};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::common::ProvingKey;
use vb_accumulator::{
    kb_positive_accumulator::setup::{PublicKey as KBAccumPk, SetupParams as KBAccumParams},
    prelude::{
        MembershipProvingKey, NonMembershipProvingKey, PublicKey, SetupParams as AccumParams,
    },
};

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving membership
    /// in positive and universal VB accumulator.
    VBAccumulatorMembership,
    AccumParams,
    VbAccumulatorParams,
    PublicKey,
    VbAccumulatorPublicKey,
    VBAccumulatorMembership,
    MembershipProvingKey,
    VbAccumulatorMemProvingKey
);

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving non-membership
    /// in universal VB accumulator.
    VBAccumulatorNonMembership,
    AccumParams,
    VbAccumulatorParams,
    PublicKey,
    VbAccumulatorPublicKey,
    VBAccumulatorNonMembership,
    NonMembershipProvingKey,
    VbAccumulatorNonMemProvingKey
);

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving membership
    /// in universal KB accumulator.
    KBUniversalAccumulatorMembership,
    AccumParams,
    VbAccumulatorParams,
    PublicKey,
    VbAccumulatorPublicKey,
    KBUniversalAccumulatorMembership,
    ProvingKey,
    BBSigProvingKey
);

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving non-membership
    /// in universal K accumulator.
    KBUniversalAccumulatorNonMembership,
    AccumParams,
    VbAccumulatorParams,
    PublicKey,
    VbAccumulatorPublicKey,
    KBUniversalAccumulatorNonMembership,
    ProvingKey,
    BBSigProvingKey
);

impl_struct_and_funcs!(
    /// Public values like setup params, public key, proving key and accumulator for proving membership
    /// in positive KB accumulator.
    KBPositiveAccumulatorMembership,
    KBAccumParams,
    KBPositiveAccumulatorParams,
    KBAccumPk,
    KBPositiveAccumulatorPublicKey,
    KBPositiveAccumulatorMembership,
    ProvingKey,
    BBSigProvingKey
);

pub use detached::*;
