use crate::hashing_utils::field_elem_from_seed;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_std::{io::Write, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

// TODO: remove commented out lines (usually just a challenge from rng) from tests (left in to help adjust tests correctly)

/// Struct to carry the bytes representing the transcript
#[derive(Debug, CanonicalSerialize, Clone)]
pub struct Transcript {
    pub transcript_bytes: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Transcript {
        Transcript {
            transcript_bytes: Vec::new(),
        }
    }

    pub fn append_bytes(&mut self, new_bytes: &[u8]) {
        self.transcript_bytes.append(&mut new_bytes.to_vec());
    }

    pub fn hash<F, D>(&self) -> F
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let result = field_elem_from_seed::<F, D>(self.transcript_bytes.as_slice(), &[]);
        result
    }

    pub fn hash_twice<F, D>(&self) -> (F, F)
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let result1 = field_elem_from_seed::<F, D>(self.transcript_bytes.clone().as_slice(), &[0]);
        let result2 = field_elem_from_seed::<F, D>(self.transcript_bytes.clone().as_slice(), &[1]);
        (result1, result2)
    }
}

impl Write for Transcript {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ark_std::io::Error> {
        self.transcript_bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), ark_std::io::Error> {
        Ok(())
    }
}

pub trait ChallengeContributor {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SerializationError>;
}
