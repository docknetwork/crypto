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

mod serialization {
    use super::{CanonicalDeserialize, CanonicalSerialize, PairingEngine};
    use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
    use saver::saver_groth16::Proof;
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    pub struct ProofBytes;

    impl<E: PairingEngine> SerializeAs<Proof<E>> for ProofBytes {
        fn serialize_as<S>(elem: &Proof<E>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];
            CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de, E: PairingEngine> DeserializeAs<'de, Proof<E>> for ProofBytes {
        fn deserialize_as<D>(deserializer: D) -> Result<Proof<E>, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct PVisitor<E: PairingEngine>(PhantomData<E>);

            impl<'a, E: PairingEngine> Visitor<'a> for PVisitor<E> {
                type Value = Proof<E>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("expected Proof")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'a>,
                {
                    let mut bytes = Vec::<u8>::new();
                    while let Some(b) = seq.next_element()? {
                        bytes.push(b);
                    }
                    let p: Proof<E> = CanonicalDeserialize::deserialize(bytes.as_slice())
                        .map_err(serde::de::Error::custom)?;
                    Ok(p)
                }
            }
            deserializer.deserialize_seq(PVisitor::<E>(PhantomData))
        }
    }
}
