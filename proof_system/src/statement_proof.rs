use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::prelude::PoKOfSignatureG1Proof;
use coconut_crypto::SignaturePoK as PSSignaturePoK;
use dock_crypto_utils::serde_utils::*;
use saver::encryption::Ciphertext;
use schnorr_pok::SchnorrResponse;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::prelude::{MembershipProof, NonMembershipProof};

use crate::error::ProofSystemError;
pub use serialization::*;

/// Proof corresponding to one `Statement`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum StatementProof<E: Pairing, G: AffineRepr> {
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
    PoKPSSignature(PSSignaturePoK<E>),
}

macro_rules! delegate {
    ($([$idx: ident])?$self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                SaverWithAggregation,
                BoundCheckLegoGroth16WithAggregation,
                R1CSLegoGroth16WithAggregation,
                PoKPSSignature
            : $($tt)+
        }
    }};
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                SaverWithAggregation,
                BoundCheckLegoGroth16WithAggregation,
                R1CSLegoGroth16WithAggregation,
                PoKPSSignature
            : $($tt)+
        }

        $err
    }};
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitmentProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    pub response: SchnorrResponse<G>,
}

impl<G: AffineRepr> PedersenCommitmentProof<G> {
    pub fn new(t: G, response: SchnorrResponse<G>) -> Self {
        Self { t, response }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProof<E: Pairing> {
    pub ciphertext: Ciphertext<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub snark_proof: saver::saver_groth16::Proof<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_chunks: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_combined: E::G1Affine,
    pub sp_ciphertext: PedersenCommitmentProof<E::G1Affine>,
    pub sp_chunks: PedersenCommitmentProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> SaverProof<E> {
    pub fn get_schnorr_response_for_combined_message(
        &self,
    ) -> Result<&E::ScalarField, ProofSystemError> {
        self.sp_combined
            .response
            .get_response(0)
            .map_err(|e| e.into())
    }

    pub fn for_aggregation(&self) -> SaverProofWhenAggregatingSnarks<E> {
        SaverProofWhenAggregatingSnarks {
            ciphertext: self.ciphertext.clone(),
            comm_chunks: self.comm_chunks,
            comm_combined: self.comm_combined,
            sp_ciphertext: self.sp_ciphertext.clone(),
            sp_chunks: self.sp_chunks.clone(),
            sp_combined: self.sp_combined.clone(),
        }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SaverProofWhenAggregatingSnarks<E: Pairing> {
    pub ciphertext: Ciphertext<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_chunks: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm_combined: E::G1Affine,
    pub sp_ciphertext: PedersenCommitmentProof<E::G1Affine>,
    pub sp_chunks: PedersenCommitmentProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> SaverProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_combined_message(
        &self,
    ) -> Result<&E::ScalarField, ProofSystemError> {
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
pub struct BoundCheckLegoGroth16Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub snark_proof: legogroth16::Proof<E>,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> BoundCheckLegoGroth16Proof<E> {
    pub fn get_schnorr_response_for_message(&self) -> Result<&E::ScalarField, ProofSystemError> {
        self.sp.response.get_response(0).map_err(|e| e.into())
    }

    pub fn for_aggregation(&self) -> BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E> {
        BoundCheckLegoGroth16ProofWhenAggregatingSnarks {
            commitment: self.snark_proof.d,
            sp: self.sp.clone(),
        }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: E::G1Affine,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_message(&self) -> Result<&E::ScalarField, ProofSystemError> {
        self.sp.response.get_response(0).map_err(|e| e.into())
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSLegoGroth16Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub snark_proof: legogroth16::Proof<E>,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> R1CSLegoGroth16Proof<E> {
    pub fn get_schnorr_response_for_message(
        &self,
        index: usize,
    ) -> Result<&E::ScalarField, ProofSystemError> {
        self.sp.response.get_response(index).map_err(|e| e.into())
    }

    pub fn for_aggregation(&self) -> R1CSLegoGroth16ProofWhenAggregatingSnarks<E> {
        R1CSLegoGroth16ProofWhenAggregatingSnarks {
            commitment: self.snark_proof.d,
            sp: self.sp.clone(),
        }
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct R1CSLegoGroth16ProofWhenAggregatingSnarks<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: E::G1Affine,
    pub sp: PedersenCommitmentProof<E::G1Affine>,
}

impl<E: Pairing> R1CSLegoGroth16ProofWhenAggregatingSnarks<E> {
    pub fn get_schnorr_response_for_message(
        &self,
        index: usize,
    ) -> Result<&E::ScalarField, ProofSystemError> {
        self.sp.response.get_response(index).map_err(|e| e.into())
    }
}

mod serialization {
    use super::{
        AffineRepr, CanonicalDeserialize, CanonicalSerialize, Pairing, Read, SerializationError,
        StatementProof, Write,
    };
    use ark_serialize::{Compress, Valid, Validate};

    impl<E: Pairing, G: AffineRepr> Valid for StatementProof<E, G> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalSerialize for StatementProof<E, G> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            delegate!([idx]self with variant as s {
                CanonicalSerialize::serialize_with_mode(&idx, &mut writer, compress)?;
                CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
            })
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            delegate!([idx]self with variant as s {
                idx.serialized_size(compress) + s.serialized_size(compress)
            })
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalDeserialize for StatementProof<E, G> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let idx: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

            delegate_reverse!(
                idx or else Err(SerializationError::InvalidData) => with variant as build
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate).map(build)
            )
        }
    }
}
