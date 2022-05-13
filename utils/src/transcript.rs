use crate::hashing_utils::field_elem_from_seed;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_std::{io::Write, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

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

    pub fn hash<F, D>(&mut self, label: Option<&[u8]>) -> F
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        match label {
            Some(l) => field_elem_from_seed::<F, D>(self.transcript_bytes.as_slice(), l),
            None => field_elem_from_seed::<F, D>(self.transcript_bytes.as_slice(), &[]),
        }
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
