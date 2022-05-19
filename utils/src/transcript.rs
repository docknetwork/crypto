use crate::hashing_utils::field_elem_from_seed;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_std::{io::Write, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

/// Struct to carry the bytes representing the transcript allowing hashing to create challenges easily
#[derive(Debug, CanonicalSerialize, Clone)]
pub struct Transcript {
    pub bytes: Vec<u8>,
}

impl Transcript {
    pub fn new() -> Transcript {
        Transcript {
            bytes: Vec::new(),
        }
    }

    pub fn append_bytes(&mut self, new_bytes: &[u8]) {
        self.bytes.extend_from_slice(new_bytes);
    }

    pub fn hash<F, D>(&mut self, label: Option<&[u8]>) -> F
    where
        F: PrimeField,
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let salt = label.unwrap_or(&[]);
        field_elem_from_seed::<F, D>(self.bytes.as_slice(), salt)
    }
}

impl Write for Transcript {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ark_std::io::Error> {
        self.append_bytes(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), ark_std::io::Error> {
        Ok(())
    }
}

pub trait ChallengeContributor {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SerializationError>;
}
