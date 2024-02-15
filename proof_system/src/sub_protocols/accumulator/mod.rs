#[macro_use]
mod macros;
pub mod cdh;
pub mod detached;
pub mod keyed_verification;

use crate::{error::ProofSystemError, statement_proof::StatementProof};
use ark_ec::pairing::Pairing;

use ark_std::{io::Write, rand::RngCore};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use short_group_sig::common::ProvingKey;
use vb_accumulator::{
    kb_positive_accumulator::{
        proofs::{
            KBPositiveAccumulatorMembershipProof, KBPositiveAccumulatorMembershipProofProtocol,
        },
        setup::{
            PreparedPublicKey as KBPreparedPublicKey, PreparedSetupParams as KBPreparedAccumParams,
            PublicKey as KBPublicKey, SetupParams as KBAccumParams,
        },
    },
    kb_universal_accumulator::proofs::{
        KBUniversalAccumulatorMembershipProof,
        KBUniversalAccumulatorMembershipProofProtocol as KBUniMemProtocol,
        KBUniversalAccumulatorNonMembershipProof,
        KBUniversalAccumulatorNonMembershipProofProtocol as KBUniNonMemProtocol,
    },
    prelude::{
        MembershipProof, MembershipProofProtocol, MembershipProvingKey, NonMembershipProof,
        NonMembershipProofProtocol, NonMembershipProvingKey, PreparedPublicKey,
        PreparedSetupParams, PublicKey, SetupParams as AccumParams,
    },
};

impl_struct_and_funcs!(
    /// To prove membership in VB accumulator
    VBAccumulatorMembershipSubProtocol,
    AccumParams,
    PublicKey,
    PreparedSetupParams,
    PreparedPublicKey,
    MembershipProvingKey,
    MembershipProofProtocol,
    Membership,
    E::G1Affine,
    VBAccumulatorMembership,
    MembershipProof,
    VBAccumProofContributionFailed
);

impl_struct_and_funcs!(
    /// To prove non-membership in VB accumulator
    VBAccumulatorNonMembershipSubProtocol,
    AccumParams,
    PublicKey,
    PreparedSetupParams,
    PreparedPublicKey,
    NonMembershipProvingKey,
    NonMembershipProofProtocol,
    NonMembership,
    E::G1Affine,
    VBAccumulatorNonMembership,
    NonMembershipProof,
    VBAccumProofContributionFailed
);

impl_struct_and_funcs!(
    /// To prove membership in KB universal accumulator
    KBUniversalAccumulatorMembershipSubProtocol,
    AccumParams,
    PublicKey,
    PreparedSetupParams,
    PreparedPublicKey,
    ProvingKey,
    KBUniMemProtocol,
    KBUniMembership,
    E::G1Affine,
    KBUniversalAccumulatorMembership,
    KBUniversalAccumulatorMembershipProof,
    KBAccumProofContributionFailed
);

impl_struct_and_funcs!(
    /// To prove non-membership in KB universal accumulator
    KBUniversalAccumulatorNonMembershipSubProtocol,
    AccumParams,
    PublicKey,
    PreparedSetupParams,
    PreparedPublicKey,
    ProvingKey,
    KBUniNonMemProtocol,
    KBUniNonMembership,
    E::G1Affine,
    KBUniversalAccumulatorNonMembership,
    KBUniversalAccumulatorNonMembershipProof,
    KBAccumProofContributionFailed
);

impl_struct_and_funcs!(
    /// To prove membership in KB universal accumulator
    KBPositiveAccumulatorMembershipSubProtocol,
    KBAccumParams,
    KBPublicKey,
    KBPreparedAccumParams,
    KBPreparedPublicKey,
    ProvingKey,
    KBPositiveAccumulatorMembershipProofProtocol,
    KBPosMembership,
    E,
    KBPositiveAccumulatorMembership,
    KBPositiveAccumulatorMembershipProof,
    KBAccumProofContributionFailed
);
