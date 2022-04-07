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

mod serialization {
    use super::{
        AffineCurve, CanonicalDeserialize, CanonicalSerialize, PairingEngine, Read,
        SerializationError, StatementProof, Write,
    };
    use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
    use legogroth16::Proof as LegoProof;
    use saver::saver_groth16::Proof;
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for StatementProof<E, G> {
        impl_serialize!();
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for StatementProof<E, G> {
        impl_deserialize!();
    }

    impl_for_groth16_struct!(ProofBytes, Proof, "expected Proof");
    impl_for_groth16_struct!(LegoProofBytes, LegoProof, "expected LegoProofBytes");
}
