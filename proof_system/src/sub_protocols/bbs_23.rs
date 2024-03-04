use ark_ec::pairing::Pairing;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore};
use bbs_plus::prelude::{
    BBSPlusError, PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol, PreparedPublicKeyG2,
    PreparedSignatureParams23G1, PublicKeyG2, SignatureParams23G1,
};
use dock_crypto_utils::{
    expect_equality,
    iter::take_while_satisfy,
    misc::seq_inc_by_n_from,
    randomized_pairing_check::RandomizedPairingChecker,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
    try_iter::CheckLeft,
};
use itertools::Itertools;

use crate::{error::ProofSystemError, statement_proof::StatementProof};

use super::merge_indexed_messages_with_blindings;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoKBBSSigG1SubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub revealed_messages: &'a BTreeMap<usize, E::ScalarField>,
    pub signature_params: &'a SignatureParams23G1<E>,
    pub public_key: Option<&'a PublicKeyG2<E>>,
    pub protocol: Option<PoKOfSignature23G1Protocol<E>>,
}

impl<'a, E: Pairing> PoKBBSSigG1SubProtocol<'a, E> {
    impl_bbs_subprotocol!(
        SignatureParams23G1,
        PoKBBSSignature23G1,
        PoKOfSignature23G1Protocol,
        PoKBBSSignature23G1,
        PoKOfSignature23G1Proof,
        PreparedSignatureParams23G1
    );
}
