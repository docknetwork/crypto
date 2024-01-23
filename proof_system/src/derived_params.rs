//! Parameters derived from other parameters during proof generation and verification. Used to prevent repeatedly
//! creating these parameters.

use crate::{
    statement::bound_check_smc::{SmcParamsAndCommitmentKey, SmcParamsWithPairingAndCommitmentKey},
    sub_protocols::saver::SaverProtocol,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{collections::BTreeMap, marker::PhantomData, vec, vec::Vec};
use bbs_plus::setup::{
    PreparedPublicKeyG2 as PreparedBBSPlusPk,
    PreparedSignatureParams23G1 as PreparedBBSSigParams23,
    PreparedSignatureParamsG1 as PreparedBBSPlusSigParams, PublicKeyG2 as BBSPlusPk,
    SignatureParams23G1 as BBSSigParams23, SignatureParamsG1 as BBSPlusSigParams,
};
use coconut_crypto::setup::{
    PreparedPublicKey as PreparedPSPk, PreparedSignatureParams as PreparedPSSigParams,
    PublicKey as PSPk, SignatureParams as PSSigParams,
};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use legogroth16::{
    PreparedVerifyingKey as LegoPreparedVerifyingKey, VerifyingKey as LegoVerifyingKey,
};
use saver::{
    prelude::{
        ChunkedCommitmentGens, EncryptionGens, EncryptionKey, PreparedEncryptionGens,
        PreparedEncryptionKey,
    },
    saver_groth16::{
        PreparedVerifyingKey as SaverPreparedVerifyingKey, VerifyingKey as SaverVerifyingKey,
    },
};
use smc_range_proof::prelude::MemberCommitmentKey;
use vb_accumulator::{
    kb_positive_accumulator::setup::{
        PreparedPublicKey as KBPreparedPublicKey, PreparedSetupParams as KBPreparedAccumParams,
        PublicKey as KBAccumPublicKey, SetupParams as KBAccumParams,
    },
    setup::{
        PreparedPublicKey as PreparedAccumPk, PreparedSetupParams as PreparedAccumParams,
        PublicKey as AccumPk, SetupParams as AccumParams,
    },
};

/// Allows creating a new derived parameter from reference to original parameter
pub trait DerivedParams<'a, Ref, DP> {
    fn new_derived(orig: &Ref) -> DP;
}

pub struct DerivedParamsTracker<'a, Ref: PartialEq, DP, E> {
    /// References to the original parameter to which the derivation is applied
    origs_ref: Vec<&'a Ref>,
    /// The newly created derived param. The key in the map is reference to the original parameter and serves
    /// as a unique identifier for the derived param.
    derived_params: BTreeMap<usize, DP>,
    /// Maps a statement identifier to a derived parameter identifier.
    derived_params_for_statement: BTreeMap<usize, usize>,
    phantom: PhantomData<E>,
}

/// Maps statement identifiers to derived params
pub struct StatementDerivedParams<DP> {
    derived_params: BTreeMap<usize, DP>,
    derived_params_for_statement: BTreeMap<usize, usize>,
}

impl<'a, Ref: PartialEq, DP, E> DerivedParamsTracker<'a, Ref, DP, E>
where
    DerivedParamsTracker<'a, Ref, DP, E>: DerivedParams<'a, Ref, DP>,
{
    pub fn new() -> Self {
        Self {
            origs_ref: vec![],
            derived_params: BTreeMap::new(),
            derived_params_for_statement: BTreeMap::new(),
            phantom: PhantomData,
        }
    }

    pub fn find(&self, orig: &Ref) -> Option<usize> {
        self.origs_ref.iter().position(|v: &&Ref| **v == *orig)
    }

    /// Creates a new derived param for the statement index if need be else store the reference to
    /// old parameter.
    pub fn on_new_statement_idx(&mut self, orig: &'a Ref, s_idx: usize) {
        if let Some(k) = self.find(orig) {
            self.derived_params_for_statement.insert(s_idx, k);
        } else {
            let derived = Self::new_derived(orig);
            self.derived_params.insert(self.origs_ref.len(), derived);
            self.derived_params_for_statement
                .insert(s_idx, self.origs_ref.len());
            self.origs_ref.push(orig);
        }
    }

    /// Finished tracking derived params, return map of statement to derived params
    pub fn finish(self) -> StatementDerivedParams<DP> {
        StatementDerivedParams {
            derived_params: self.derived_params,
            derived_params_for_statement: self.derived_params_for_statement,
        }
    }
}

impl<DP> StatementDerivedParams<DP> {
    pub fn get(&self, s_idx: usize) -> Option<&DP> {
        self.derived_params
            .get(self.derived_params_for_statement.get(&s_idx)?)
    }
}

/// To derive commitment key from `LegoVerifyingKey`
impl<'a, E: Pairing> DerivedParams<'a, LegoVerifyingKey<E>, Vec<E::G1Affine>>
    for DerivedParamsTracker<'a, LegoVerifyingKey<E>, Vec<E::G1Affine>, E>
{
    fn new_derived(vk: &LegoVerifyingKey<E>) -> Vec<E::G1Affine> {
        vk.get_commitment_key_for_witnesses()
    }
}

/// To derive commitment key from `EncryptionKey`
impl<'a, E: Pairing> DerivedParams<'a, EncryptionKey<E>, Vec<E::G1Affine>>
    for DerivedParamsTracker<'a, EncryptionKey<E>, Vec<E::G1Affine>, E>
{
    fn new_derived(ek: &EncryptionKey<E>) -> Vec<E::G1Affine> {
        SaverProtocol::encryption_comm_key(ek)
    }
}

impl<'a, E: Pairing>
    DerivedParams<
        'a,
        (&ChunkedCommitmentGens<E::G1Affine>, u8),
        (Vec<E::G1Affine>, Vec<E::G1Affine>),
    >
    for DerivedParamsTracker<
        'a,
        (&ChunkedCommitmentGens<E::G1Affine>, u8),
        (Vec<E::G1Affine>, Vec<E::G1Affine>),
        E,
    >
{
    fn new_derived(
        (comm_gens, chunk_bit_size): &(&ChunkedCommitmentGens<E::G1Affine>, u8),
    ) -> (Vec<E::G1Affine>, Vec<E::G1Affine>) {
        SaverProtocol::<E>::chunked_comm_keys(comm_gens, *chunk_bit_size)
    }
}

/// To derive commitment key from a Pedersen commitment. Used with generators for Bulletproofs++
impl<'a, E: Pairing, G: AffineRepr> DerivedParams<'a, (G, G), [G; 2]>
    for DerivedParamsTracker<'a, (G, G), [G; 2], E>
{
    fn new_derived(ck: &(G, G)) -> [G; 2] {
        [ck.0, ck.1]
    }
}

impl<'a, E: Pairing> DerivedParams<'a, MemberCommitmentKey<E::G1Affine>, [E::G1Affine; 2]>
    for DerivedParamsTracker<'a, MemberCommitmentKey<E::G1Affine>, [E::G1Affine; 2], E>
{
    fn new_derived(ck: &MemberCommitmentKey<E::G1Affine>) -> [E::G1Affine; 2] {
        [ck.g, ck.h]
    }
}

impl<'a, E: Pairing, G: AffineRepr> DerivedParams<'a, PedersenCommitmentKey<G>, [G; 2]>
    for DerivedParamsTracker<'a, PedersenCommitmentKey<G>, [G; 2], E>
{
    fn new_derived(ck: &PedersenCommitmentKey<G>) -> [G; 2] {
        [ck.g, ck.h]
    }
}

macro_rules! impl_derived_for_prepared_ref {
    ($(#[$doc:meta])*
    $unprepared: ident, $prepared: ident) => {
        impl<'a, E: Pairing> DerivedParams<'a, $unprepared<E>, $prepared<E>>
            for DerivedParamsTracker<'a, $unprepared<E>, $prepared<E>, E>
        {
            fn new_derived(gens: &$unprepared<E>) -> $prepared<E> {
                $prepared::from(gens.clone())
            }
        }
    };
}

macro_rules! impl_derived_for_prepared {
    ($(#[$doc:meta])*
    $unprepared: ident, $prepared: ident) => {
        $(#[$doc])*
        impl<'a, E: Pairing> DerivedParams<'a, $unprepared<E>, $prepared<E>>
            for DerivedParamsTracker<'a, $unprepared<E>, $prepared<E>, E>
        {
            fn new_derived(gens: &$unprepared<E>) -> $prepared<E> {
                $prepared::from(gens)
            }
        }
    };
}

impl_derived_for_prepared_ref!(
    /// To derive prepared encryption generators from `EncryptionGens`
    EncryptionGens,
    PreparedEncryptionGens
);

impl_derived_for_prepared_ref!(
    /// To derive prepared encryption key from `EncryptionKey`
    EncryptionKey,
    PreparedEncryptionKey
);

impl_derived_for_prepared_ref!(SaverVerifyingKey, SaverPreparedVerifyingKey);

impl_derived_for_prepared!(
    /// To derive prepared verification key from `LegoVerifyingKey`
    LegoVerifyingKey,
    LegoPreparedVerifyingKey
);

impl_derived_for_prepared_ref!(
    /// To derive prepared signature params from BBS+ signature params
    BBSPlusSigParams,
    PreparedBBSPlusSigParams
);

impl_derived_for_prepared_ref!(
    /// To derive prepared signature params from BBS signature params
    BBSSigParams23,
    PreparedBBSSigParams23
);

impl_derived_for_prepared_ref!(
    /// To derive prepared signature params from BBS+ signature params
    PSSigParams,
    PreparedPSSigParams
);

impl_derived_for_prepared_ref!(
    /// To derive prepared PS public key from PS public key
    BBSPlusPk,
    PreparedBBSPlusPk
);

impl_derived_for_prepared_ref!(
    /// To derive prepared PS public key from PS public key
    PSPk,
    PreparedPSPk
);

impl_derived_for_prepared_ref!(AccumParams, PreparedAccumParams);

impl_derived_for_prepared_ref!(AccumPk, PreparedAccumPk);

impl_derived_for_prepared_ref!(KBAccumParams, KBPreparedAccumParams);

impl_derived_for_prepared_ref!(KBAccumPublicKey, KBPreparedPublicKey);

impl_derived_for_prepared_ref!(
    /// To derive params with prepared G2 and pairing from `SetMembershipCheckParams`
    SmcParamsAndCommitmentKey,
    SmcParamsWithPairingAndCommitmentKey
);
