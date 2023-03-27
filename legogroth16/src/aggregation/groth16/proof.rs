use crate::aggregation::{
    commitment::PairCommitment, error::AggregationError, kzg::KZGOpening, srs,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};

/// AggregateProof contains all elements to verify n aggregated Groth16 proofs
/// using inner pairing product arguments. This proof can be created by any
/// party in possession of valid Groth16 proofs.
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct AggregateProof<E: Pairing> {
    /// commitment to A and B using the pair commitment scheme needed to verify
    /// TIPP relation.
    pub com_ab: PairCommitment<E>,
    /// commit to C separate since we use it only in MIPP
    pub com_c: PairCommitment<E>,
    /// $A^r * B = Z$ is the left value on the aggregated Groth16 equation
    pub z_ab: PairingOutput<E>,
    /// $C^r$ is used on the right side of the aggregated Groth16 equation
    pub z_c: E::G1Affine,
    pub tmipp: TippMippProof<E>,
}

impl<E: Pairing> PartialEq for AggregateProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.com_ab == other.com_ab
            && self.com_c == other.com_c
            && self.z_ab == other.z_ab
            && self.z_c == other.z_c
            && self.tmipp == other.tmipp
    }
}

impl<E: Pairing> AggregateProof<E> {
    /// Performs some high level checks on the length of vectors and others to
    /// make sure all items in the proofs are consistent with each other.
    pub fn parsing_check(&self) -> Result<(), AggregationError> {
        let gipa = &self.tmipp.gipa;
        // 1. Check length of the proofs
        if gipa.nproofs < 2 || gipa.nproofs as usize > srs::MAX_SRS_SIZE {
            return Err(AggregationError::InvalidProof(
                "Proof length out of bounds".to_string(),
            ));
        }
        // 2. Check if it's a power of two
        if !gipa.nproofs.is_power_of_two() {
            return Err(AggregationError::InvalidProof(
                "Proof length not a power of two".to_string(),
            ));
        }
        // 3. Check all vectors are of the same length and of the correct length
        let ref_len = (gipa.nproofs as f32).log2().ceil() as usize;
        let all_same = ref_len == gipa.comms_ab.len()
            && ref_len == gipa.comms_c.len()
            && ref_len == gipa.z_ab.len()
            && ref_len == gipa.z_c.len();
        if !all_same {
            return Err(AggregationError::InvalidProof(
                "Proof vectors unequal sizes".to_string(),
            ));
        }
        Ok(())
    }
}

/// It contains all elements derived in the GIPA loop for both TIPP and MIPP at
/// the same time. Serialization is done manually here for better inspection
/// (CanonicalSerialization is implemented manually, not via the macro).
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct GipaProof<E: Pairing> {
    pub nproofs: u32,
    pub comms_ab: Vec<(PairCommitment<E>, PairCommitment<E>)>,
    pub comms_c: Vec<(PairCommitment<E>, PairCommitment<E>)>,
    pub z_ab: Vec<(PairingOutput<E>, PairingOutput<E>)>,
    pub z_c: Vec<(E::G1Affine, E::G1Affine)>,
    pub final_a: E::G1Affine,
    pub final_b: E::G2Affine,
    pub final_c: E::G1Affine,
    /// final commitment keys $v$ and $w$ - there is only one element at the
    /// end for v1 and v2 hence it's a tuple.
    pub final_vkey: (E::G2Affine, E::G2Affine),
    pub final_wkey: (E::G1Affine, E::G1Affine),
}

impl<E: Pairing> PartialEq for GipaProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.nproofs == other.nproofs
            && self.comms_ab == other.comms_ab
            && self.comms_c == other.comms_c
            && self.z_ab == other.z_ab
            && self.z_c == other.z_c
            && self.final_a == other.final_a
            && self.final_b == other.final_b
            && self.final_c == other.final_c
            && self.final_vkey == other.final_vkey
            && self.final_wkey == other.final_wkey
    }
}

impl<E: Pairing> GipaProof<E> {
    fn log_proofs(nproofs: usize) -> usize {
        (nproofs as f32).log2().ceil() as usize
    }

    pub fn is_valid(&self) -> bool {
        let log_proofs = Self::log_proofs(self.nproofs as usize);
        self.comms_ab.len() == log_proofs
            && self.comms_c.len() == log_proofs
            && self.z_ab.len() == log_proofs
            && self.z_c.len() == log_proofs
    }
}

/// It contains the GIPA recursive elements as well as the KZG openings for v
/// and w
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct TippMippProof<E: Pairing> {
    pub gipa: GipaProof<E>,
    pub vkey_opening: KZGOpening<E::G2Affine>,
    pub wkey_opening: KZGOpening<E::G1Affine>,
}

impl<E: Pairing> PartialEq for TippMippProof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.gipa == other.gipa
            && self.vkey_opening == other.vkey_opening
            && self.wkey_opening == other.wkey_opening
    }
}
