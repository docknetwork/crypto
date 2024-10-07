use crate::{
    error::ProofSystemError,
    sub_protocols::verifiable_encryption_tz_21::{dkgith_decls, rdkgith_decls},
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::prelude::{PoKOfSignature23G1Proof, PoKOfSignatureG1Proof};
use bulletproofs_plus_plus::prelude::ProofArbitraryRange;
use coconut_crypto::SignaturePoK as PSSignaturePoK;
use dock_crypto_utils::{ecies, serde_utils::ArkObjectBytes};
use kvac::bbdt_2016::proof_cdh::PoKOfMAC;
use saver::encryption::Ciphertext;
use schnorr_pok::{partial::PartialSchnorrResponse, SchnorrResponse};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::{
    kb_positive_accumulator::{
        proofs::KBPositiveAccumulatorMembershipProof,
        proofs_cdh::KBPositiveAccumulatorMembershipProof as KBPositiveAccumulatorMembershipProofCDH,
    },
    kb_universal_accumulator::proofs::{
        KBUniversalAccumulatorMembershipProof, KBUniversalAccumulatorNonMembershipProof,
    },
    prelude::{MembershipProof, NonMembershipProof},
};

/// Proof corresponding to one `Statement`
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum StatementProof<E: Pairing> {
    PoKBBSSignatureG1(PoKOfSignatureG1Proof<E>),
    VBAccumulatorMembership(MembershipProof<E>),
    VBAccumulatorNonMembership(NonMembershipProof<E>),
    PedersenCommitment(PedersenCommitmentProof<E::G1Affine>),
    Saver(SaverProof<E>),
    BoundCheckLegoGroth16(BoundCheckLegoGroth16Proof<E>),
    R1CSLegoGroth16(R1CSLegoGroth16Proof<E>),
    SaverWithAggregation(SaverProofWhenAggregatingSnarks<E>),
    BoundCheckLegoGroth16WithAggregation(BoundCheckLegoGroth16ProofWhenAggregatingSnarks<E>),
    R1CSLegoGroth16WithAggregation(R1CSLegoGroth16ProofWhenAggregatingSnarks<E>),
    PoKPSSignature(PSSignaturePoK<E>),
    PoKBBSSignature23G1(PoKOfSignature23G1Proof<E>),
    BoundCheckBpp(BoundCheckBppProof<E::G1Affine>),
    BoundCheckSmc(BoundCheckSmcProof<E>),
    BoundCheckSmcWithKV(BoundCheckSmcWithKVProof<E>),
    Inequality(InequalityProof<E::G1Affine>),
    DetachedAccumulatorMembership(DetachedAccumulatorMembershipProof<E>),
    DetachedAccumulatorNonMembership(DetachedAccumulatorNonMembershipProof<E>),
    KBUniversalAccumulatorMembership(KBUniversalAccumulatorMembershipProof<E>),
    KBUniversalAccumulatorNonMembership(KBUniversalAccumulatorNonMembershipProof<E>),
    VBAccumulatorMembershipCDH(vb_accumulator::proofs_cdh::MembershipProof<E>),
    VBAccumulatorNonMembershipCDH(vb_accumulator::proofs_cdh::NonMembershipProof<E>),
    KBUniversalAccumulatorMembershipCDH(vb_accumulator::kb_universal_accumulator::proofs_cdh::KBUniversalAccumulatorMembershipProof<E>),
    KBUniversalAccumulatorNonMembershipCDH(vb_accumulator::kb_universal_accumulator::proofs_cdh::KBUniversalAccumulatorNonMembershipProof<E>),
    KBPositiveAccumulatorMembership(#[serde_as(as = "ArkObjectBytes")] KBPositiveAccumulatorMembershipProof<E>),
    KBPositiveAccumulatorMembershipCDH(#[serde_as(as = "ArkObjectBytes")] KBPositiveAccumulatorMembershipProofCDH<E>),
    PoKOfBBDT16MAC(PoKOfMAC<E::G1Affine>),
    PedersenCommitmentG2(PedersenCommitmentProof<E::G2Affine>),
    VBAccumulatorMembershipKV(vb_accumulator::proofs_keyed_verification::MembershipProof<E::G1Affine>),
    KBUniversalAccumulatorMembershipKV(vb_accumulator::kb_universal_accumulator::proofs_keyed_verification::KBUniversalAccumulatorMembershipProof<E::G1Affine>),
    KBUniversalAccumulatorNonMembershipKV(vb_accumulator::kb_universal_accumulator::proofs_keyed_verification::KBUniversalAccumulatorNonMembershipProof<E::G1Affine>),
    PoKBBSSignature23IETFG1(bbs_plus::proof_23_ietf::PoKOfSignature23G1Proof<E>),
    PedersenCommitmentPartial(PedersenCommitmentPartialProof<E::G1Affine>),
    PedersenCommitmentG2Partial(PedersenCommitmentPartialProof<E::G2Affine>),
    VeTZ21(VeTZ21Proof<E::G1Affine>),
    VeTZ21Robust(VeTZ21RobustProof<E::G1Affine>),
}

macro_rules! delegate {
    ($([$idx: ident])?$self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                PoKBBSSignatureG1,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                SaverWithAggregation,
                BoundCheckLegoGroth16WithAggregation,
                R1CSLegoGroth16WithAggregation,
                PoKPSSignature,
                PoKBBSSignature23G1,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKV,
                Inequality,
                DetachedAccumulatorMembership,
                DetachedAccumulatorNonMembership,
                KBUniversalAccumulatorMembership,
                KBUniversalAccumulatorNonMembership,
                VBAccumulatorMembershipCDH,
                VBAccumulatorNonMembershipCDH,
                KBUniversalAccumulatorMembershipCDH,
                KBUniversalAccumulatorNonMembershipCDH,
                KBPositiveAccumulatorMembership,
                KBPositiveAccumulatorMembershipCDH,
                PoKOfBBDT16MAC,
                PedersenCommitmentG2,
                VBAccumulatorMembershipKV,
                KBUniversalAccumulatorMembershipKV,
                KBUniversalAccumulatorNonMembershipKV,
                PoKBBSSignature23IETFG1,
                PedersenCommitmentPartial,
                PedersenCommitmentG2Partial,
                VeTZ21,
                VeTZ21Robust
            : $($tt)+
        }
    }};
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                PoKBBSSignatureG1,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                Saver,
                BoundCheckLegoGroth16,
                R1CSLegoGroth16,
                SaverWithAggregation,
                BoundCheckLegoGroth16WithAggregation,
                R1CSLegoGroth16WithAggregation,
                PoKPSSignature,
                PoKBBSSignature23G1,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKV,
                Inequality,
                DetachedAccumulatorMembership,
                DetachedAccumulatorNonMembership,
                KBUniversalAccumulatorMembership,
                KBUniversalAccumulatorNonMembership,
                VBAccumulatorMembershipCDH,
                VBAccumulatorNonMembershipCDH,
                KBUniversalAccumulatorMembershipCDH,
                KBUniversalAccumulatorNonMembershipCDH,
                KBPositiveAccumulatorMembership,
                KBPositiveAccumulatorMembershipCDH,
                PoKOfBBDT16MAC,
                PedersenCommitmentG2,
                VBAccumulatorMembershipKV,
                KBUniversalAccumulatorMembershipKV,
                KBUniversalAccumulatorNonMembershipKV,
                PoKBBSSignature23IETFG1,
                PedersenCommitmentPartial,
                PedersenCommitmentG2Partial,
                VeTZ21,
                VeTZ21Robust
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

    pub fn get_resp_for_message(&self, idx: usize) -> Result<&G::ScalarField, ProofSystemError> {
        let r = self.response.get_response(idx)?;
        Ok(r)
    }
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitmentPartialProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    pub response: PartialSchnorrResponse<G>,
}

impl<G: AffineRepr> PedersenCommitmentPartialProof<G> {
    pub fn new(t: G, response: PartialSchnorrResponse<G>) -> Self {
        Self { t, response }
    }

    pub fn get_resp_for_message(&self, idx: usize) -> Result<&G::ScalarField, ProofSystemError> {
        let r = self.response.get_response(idx)?;
        Ok(r)
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
    pub sp_chunks: PedersenCommitmentPartialProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentPartialProof<E::G1Affine>,
}

impl<E: Pairing> SaverProof<E> {
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
    pub sp_chunks: PedersenCommitmentPartialProof<E::G1Affine>,
    pub sp_combined: PedersenCommitmentPartialProof<E::G1Affine>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub snark_proof: legogroth16::Proof<E>,
    pub sp: PedersenCommitmentPartialProof<E::G1Affine>,
}

impl<E: Pairing> BoundCheckLegoGroth16Proof<E> {
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
    pub sp: PedersenCommitmentPartialProof<E::G1Affine>,
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

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckBppProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub bpp_proof: ProofArbitraryRange<G>,
    pub sp1: PedersenCommitmentPartialProof<G>,
    pub sp2: PedersenCommitmentPartialProof<G>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundCheckSmcInnerProof<E: Pairing> {
    CCS(smc_range_proof::prelude::CCSArbitraryRangeProof<E>),
    CLS(smc_range_proof::prelude::CLSRangeProof<E>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundCheckSmcWithKVInnerProof<E: Pairing> {
    CCS(smc_range_proof::prelude::CCSArbitraryRangeWithKVProof<E>),
    CLS(smc_range_proof::prelude::CLSRangeProofWithKV<E>),
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckSmcProof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub proof: BoundCheckSmcInnerProof<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm: E::G1Affine,
    pub sp: PedersenCommitmentPartialProof<E::G1Affine>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckSmcWithKVProof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub proof: BoundCheckSmcWithKVInnerProof<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm: E::G1Affine,
    pub sp: PedersenCommitmentPartialProof<E::G1Affine>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct InequalityProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub proof: schnorr_pok::inequality::InequalityProof<G>,
    #[serde_as(as = "ArkObjectBytes")]
    pub comm: G,
    pub sp: PedersenCommitmentPartialProof<G>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct DetachedAccumulatorMembershipProof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator: E::G1Affine,
    pub accum_proof: MembershipProof<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub challenge: E::ScalarField,
    /// Encrypted opening
    // TODO: Make constants as generic
    #[serde_as(as = "ArkObjectBytes")]
    pub encrypted: ecies::Encryption<E::G2Affine, 32, 24>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct DetachedAccumulatorNonMembershipProof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub accumulator: E::G1Affine,
    pub accum_proof: NonMembershipProof<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub challenge: E::ScalarField,
    /// Encrypted opening
    // TODO: Make constants as generic
    #[serde_as(as = "ArkObjectBytes")]
    pub encrypted: ecies::Encryption<E::G2Affine, 32, 24>,
}

/// Verifiable Encryption using DKGith protocol in the scheme TZ21
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VeTZ21Proof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub ve_proof: dkgith_decls::Proof<G>,
    /// The commitment to the encrypted messages
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: G,
    pub sp: PedersenCommitmentPartialProof<G>,
}

/// Verifiable Encryption using Robust DKGith protocol in the scheme TZ21
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct VeTZ21RobustProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub ve_proof: rdkgith_decls::Proof<G>,
    /// The commitment to the encrypted messages
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: G,
    pub sp: PedersenCommitmentPartialProof<G>,
}

mod serialization {
    use super::{
        CanonicalDeserialize, CanonicalSerialize, Pairing, Read, SerializationError,
        StatementProof, Write,
    };
    use crate::statement_proof::{BoundCheckSmcInnerProof, BoundCheckSmcWithKVInnerProof};
    use ark_serialize::{Compress, Valid, Validate};

    impl<E: Pairing> Valid for StatementProof<E> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing> CanonicalSerialize for StatementProof<E> {
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

    impl<E: Pairing> CanonicalDeserialize for StatementProof<E> {
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

    macro_rules! impl_serz_for_bound_check_inner {
        ( $name:ident) => {
            impl<E: Pairing> Valid for $name<E> {
                fn check(&self) -> Result<(), SerializationError> {
                    match self {
                        Self::CCS(c) => c.check(),
                        Self::CLS(c) => c.check(),
                    }
                }
            }

            impl<E: Pairing> CanonicalSerialize for $name<E> {
                fn serialize_with_mode<W: Write>(
                    &self,
                    mut writer: W,
                    compress: Compress,
                ) -> Result<(), SerializationError> {
                    match self {
                        Self::CCS(c) => {
                            CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                            CanonicalSerialize::serialize_with_mode(c, &mut writer, compress)
                        }
                        Self::CLS(c) => {
                            CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                            CanonicalSerialize::serialize_with_mode(c, &mut writer, compress)
                        }
                    }
                }

                fn serialized_size(&self, compress: Compress) -> usize {
                    match self {
                        Self::CCS(c) => 0u8.serialized_size(compress) + c.serialized_size(compress),
                        Self::CLS(c) => 1u8.serialized_size(compress) + c.serialized_size(compress),
                    }
                }
            }

            impl<E: Pairing> CanonicalDeserialize for $name<E> {
                fn deserialize_with_mode<R: Read>(
                    mut reader: R,
                    compress: Compress,
                    validate: Validate,
                ) -> Result<Self, SerializationError> {
                    let t: u8 = CanonicalDeserialize::deserialize_with_mode(
                        &mut reader,
                        compress,
                        validate,
                    )?;
                    match t {
                        0u8 => Ok(Self::CCS(CanonicalDeserialize::deserialize_with_mode(
                            &mut reader,
                            compress,
                            validate,
                        )?)),
                        1u8 => Ok(Self::CLS(CanonicalDeserialize::deserialize_with_mode(
                            &mut reader,
                            compress,
                            validate,
                        )?)),
                        _ => Err(SerializationError::InvalidData),
                    }
                }
            }
        };
    }

    impl_serz_for_bound_check_inner!(BoundCheckSmcInnerProof);
    impl_serz_for_bound_check_inner!(BoundCheckSmcWithKVInnerProof);
}
