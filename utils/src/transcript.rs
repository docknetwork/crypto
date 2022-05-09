use crate::hashing_utils::field_elem_from_seed;
use crate::serde_utils::ArkSerializationError;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_std::io::{Error, ErrorKind};
use ark_std::{io::Write, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use serde::Serialize;

/// Struct to carry the bytes representing the transcript
#[derive(Debug, CanonicalSerialize)]
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
}

impl Write for Transcript {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ark_std::io::Error> {
        let mut bytes_pushed = 0;
        for i in 0..buf.len() {
            // Should anything be added here to deal with the possibility of this `push()` failing? Although it is a
            // vector we are pushing to and I don't know if one can make that fail
            self.transcript_bytes.push(buf[i]);
            bytes_pushed += 1;
        }
        if bytes_pushed == 0 {
            return Err(Error::new(ErrorKind::WriteZero, "No bytes copied"));
        }
        Ok(bytes_pushed)
    }

    fn flush(&mut self) -> Result<(), ark_std::io::Error> {
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub enum ChallengeError {
    InvalidContribution,
    #[serde(with = "ArkSerializationError")]
    Serialization(SerializationError),
}

impl From<SerializationError> for ChallengeError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

pub trait ChallengeContributor {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ChallengeError>;
}
