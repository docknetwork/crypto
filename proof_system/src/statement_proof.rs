use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::vec::Vec;
use bbs_plus::prelude::PoKOfSignatureG1Proof;
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
            comm_chunks: self.comm_chunks.clone(),
            comm_combined: self.comm_combined.clone(),
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
            commitment: self.snark_proof.d.clone(),
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
            commitment: self.snark_proof.d.clone(),
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
            match self {
                Self::PoKBBSSignatureG1(s) => s.check(),
                Self::AccumulatorMembership(s) => s.check(),
                Self::AccumulatorNonMembership(s) => s.check(),
                Self::PedersenCommitment(s) => s.check(),
                Self::Saver(s) => s.check(),
                Self::BoundCheckLegoGroth16(s) => s.check(),
                Self::R1CSLegoGroth16(s) => s.check(),
                Self::SaverWithAggregation(s) => s.check(),
                Self::BoundCheckLegoGroth16WithAggregation(s) => s.check(),
                Self::R1CSLegoGroth16WithAggregation(s) => s.check(),
            }
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalSerialize for StatementProof<E, G> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::AccumulatorMembership(s) => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::AccumulatorNonMembership(s) => {
                    CanonicalSerialize::serialize_with_mode(&2u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::PedersenCommitment(s) => {
                    CanonicalSerialize::serialize_with_mode(&3u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::Saver(s) => {
                    CanonicalSerialize::serialize_with_mode(&4u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::BoundCheckLegoGroth16(s) => {
                    CanonicalSerialize::serialize_with_mode(&5u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::R1CSLegoGroth16(s) => {
                    CanonicalSerialize::serialize_with_mode(&6u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::SaverWithAggregation(s) => {
                    CanonicalSerialize::serialize_with_mode(&7u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    CanonicalSerialize::serialize_with_mode(&8u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    CanonicalSerialize::serialize_with_mode(&9u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::Saver(s) => 4u8.serialized_size(compress) + s.serialized_size(compress),
                Self::BoundCheckLegoGroth16(s) => {
                    5u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::R1CSLegoGroth16(s) => {
                    6u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::SaverWithAggregation(s) => {
                    7u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::BoundCheckLegoGroth16WithAggregation(s) => {
                    8u8.serialized_size(compress) + s.serialized_size(compress)
                }
                Self::R1CSLegoGroth16WithAggregation(s) => {
                    9u8.serialized_size(compress) + s.serialized_size(compress)
                }
            }
        }
    }

    impl<E: Pairing, G: AffineRepr> CanonicalDeserialize for StatementProof<E, G> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                4u8 => Ok(Self::Saver(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                5u8 => Ok(Self::BoundCheckLegoGroth16(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                6u8 => Ok(Self::R1CSLegoGroth16(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                7u8 => Ok(Self::SaverWithAggregation(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                8u8 => Ok(Self::BoundCheckLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                9u8 => Ok(Self::R1CSLegoGroth16WithAggregation(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
