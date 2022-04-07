use crate::error::ProofSystemError;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::vec::Vec;
use bbs_plus::prelude::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};
use legogroth16::data_structures::{
    ProvingKey as LegoSnarkProvingKey, VerifyingKey as LegoSnarkVerifyingKey,
};
use saver::prelude::{
    ChunkedCommitmentGens, DecryptionKey, EncryptionGens, EncryptionKey,
    ProvingKey as SaverSnarkProvingKey, VerifyingKey as SaverSnarkVerifyingKey,
};
use vb_accumulator::prelude::{
    MembershipProvingKey, NonMembershipProvingKey, PublicKey as AccumPublicKey,
    SetupParams as AccumParams,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SetupParams<E: PairingEngine, G: AffineCurve> {
    BBSPlusSignatureParams(BBSSignatureParamsG1<E>),
    BBSPlusPublicKey(BBSPublicKeyG2<E>),
    VbAccumulatorParams(AccumParams<E>),
    VbAccumulatorPublicKey(AccumPublicKey<E::G2Affine>),
    VbAccumulatorMemProvingKey(MembershipProvingKey<E::G1Affine>),
    VbAccumulatorNonMemProvingKey(NonMembershipProvingKey<E::G1Affine>),
    PedersenCommitmentKey(Vec<G>),
    SaverEncryptionGens(EncryptionGens<E>),
    SaverCommitmentGens(ChunkedCommitmentGens<E::G1Affine>),
    SaverEncryptionKey(EncryptionKey<E>),
    SaverDecryptionKey(DecryptionKey<E>),
    SaverProvingKey(SaverSnarkProvingKey<E>),
    SaverVerifyingKey(SaverSnarkVerifyingKey<E>),
    LegoSnarkProvingKey(LegoSnarkProvingKey<E>),
    LegoSnarkVerifyingKey(LegoSnarkVerifyingKey<E>),
}

/*pub fn get_bbs_sig_params<E: PairingEngine, G: AffineCurve>(setup_params: &[SetupParams<E, G>], idx: usize) -> Result<&BBSSignatureParamsG1<E>, ProofSystemError> {
    if idx < setup_params.len() {
        match &setup_params[idx] {
            SetupParams::BBSPlusSignatureParams(p) => Ok(p),
            _ => Err(ProofSystemError::IncompatibleBBSPlusSetupParamAtIndex(idx))
        }
    } else {
        Err(ProofSystemError::InvalidSetupParamsIndex(idx))
    }
}

pub fn get_bbs_public_key<E: PairingEngine, G: AffineCurve>(setup_params: &[SetupParams<E, G>], idx: usize) -> Result<&BBSPublicKeyG2<E>, ProofSystemError> {
    if idx < setup_params.len() {
        match &setup_params[idx] {
            SetupParams::BBSPlusPublicKey(p) => Ok(p),
            _ => Err(ProofSystemError::IncompatibleBBSPlusSetupParamAtIndex(idx))
        }
    } else {
        Err(ProofSystemError::InvalidSetupParamsIndex(idx))
    }
}*/
