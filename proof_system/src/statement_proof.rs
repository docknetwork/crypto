use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use bbs_plus::prelude::PoKOfSignatureG1Proof;
use dock_crypto_utils::serde_utils::*;
use saver::encryption::Ciphertext;
use schnorr_pok::SchnorrResponse;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::prelude::{MembershipProof, NonMembershipProof};

use crate::error::ProofSystemError;
use crate::util::{LegoProofBytes, ProofBytes};
pub use serialization::*;

/// Proof corresponding to one `Statement`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum StatementProof<E: PairingEngine, G: AffineCurve> {
    PoKBBSSignatureG1(PoKOfSignatureG1Proof<E>),
    AccumulatorMembership(MembershipProof<E>),
    AccumulatorNonMembership(NonMembershipProof<E>),
    PedersenCommitment(PedersenCommitmentProof<G>),
    Saver(SaverProof<E>),
    BoundCheckLegoGroth16(BoundCheckLegoGroth16Proof<E>),
    R1CSLegoGroth16(R1CSLegoGroth16Proof<E>),
    SaverWithAggregation(SaverProofWhenAggregatingSnarks<E>),
    BoundCheckLegoGroth16WithAggregation(BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E>),
    R1CSLegoGroth16WithAggregation(R1CSLegoGroth16ProofWhenAggregatingSnarks<E>),
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitmentProof<G: AffineCurve> {
    #[serde_as(as = "AffineGroupBytes")]
    pub t: G,
    pub response: SchnorrResponse<G>,
}

impl<G: AffineCurve> PedersenCommitmentProof<G> {
    pub fn new(t: G, response: SchnorrResponse<G>) -> Self {
        Self { t, response }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProof<E: PairingEngine> {
    pub ciphertext: Ciphertext<E>,
    #[serde_as(as = "ProofBytes")]
    pub snark_proof: saver::saver_groth16::Proof<E>,
    #[serde_as(as = "AffineGroupBytes")]
    pub comm_chunks: E::G1Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub comm_combined: E::G1Affine,
    pub sp_ciphertext: PedersenCommitmentProof<E::G1Affine>,
    pub sp_chunks: PedersenCommitmentProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> SaverProof<E> {
    pub fn get_schnorr_response_for_combined_message(&self) -> Result<&E::Fr, ProofSystemError> {
        self.sp_combined
            .response
            .get_response(0)
            .map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProofWhenAggregatingSnarks<E: PairingEngine> {
    pub ciphertext: Ciphertext<E>,
    #[serde_as(as = "AffineGroupBytes")]
    pub comm_chunks: E::G1Affine,
    #[serde_as(as = "AffineGroupBytes")]
    pub comm_combined: E::G1Affine,
    pub sp_ciphertext: PedersenCommitmentProof<E::G1Affine>,
    pub sp_chunks: PedersenCommitmentProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> SaverProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_combined_message(&self) -> Result<&E::Fr, ProofSystemError> {
        self.sp_combined
            .response
            .get_response(0)
            .map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16Proof<E: PairingEngine> {
    #[serde_as(as = "LegoProofBytes")]
    pub snark_proof: legogroth16::Proof<E>,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> BoundCheckLegoGroth16Proof<E> {
    pub fn get_schnorr_response_for_message(&self) -> Result<&E::Fr, ProofSystemError> {
        self.sp.response.get_response(0).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: E::G1Affine,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_message(&self) -> Result<&E::Fr, ProofSystemError> {
        self.sp.response.get_response(0).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSLegoGroth16Proof<E: PairingEngine> {
    #[serde_as(as = "LegoProofBytes")]
    pub snark_proof: legogroth16::Proof<E>,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> R1CSLegoGroth16Proof<E> {
    pub fn get_schnorr_response_for_message(
        &self,
        index: usize,
    ) -> Result<&E::Fr, ProofSystemError> {
        self.sp.response.get_response(index).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSLegoGroth16ProofWhenAggregatingSnarks<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: E::G1Affine,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: PairingEngine> R1CSLegoGroth16ProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_message(
        &self,
        index: usize,
    ) -> Result<&E::Fr, ProofSystemError> {
        self.sp.response.get_response(index).map_err(|e| e.into())
    }
}

mod serialization {
    use super::{
        AffineCurve, CanonicalDeserialize, CanonicalSerialize, PairingEngine, Read,
        SerializationError, StatementProof, Write,
    };

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for StatementProof<E, G> {
        impl_serialize_statement_proof!();
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for StatementProof<E, G> {
        impl_deserialize_statement_proof!();
    }
}
