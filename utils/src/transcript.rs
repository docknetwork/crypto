//! Merlin transcripts

use ark_ec::AffineRepr;
use ark_ff::fields::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    io::{Result as ArkResult, Write},
    vec,
    vec::Vec,
};
pub use merlin::Transcript as Merlin;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// must be specific to the application.
pub fn new_merlin_transcript(label: &'static [u8]) -> impl Transcript + Clone + Write {
    MerlinTranscript::new(label)
}

#[derive(
    Clone, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MerlinTranscript {
    merlin: Merlin,
    next_label: Vec<u8>,
}

impl MerlinTranscript {
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            merlin: Merlin::new(label),
            next_label: b"".to_vec(),
        }
    }

    pub fn set_label(&mut self, label: &'static [u8]) {
        self.next_label = label.to_vec();
    }
}

/// Transcript is the application level transcript to derive the challenges
/// needed for Fiat Shamir during aggregation. It is given to the
/// prover/verifier so that the transcript can be fed with any other data first.
/// Taken from <https://github.com/nikkolasg/snarkpack>
pub trait Transcript {
    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], element: &S);
    fn append_without_static_label<S: CanonicalSerialize>(&mut self, label: &[u8], element: &S);
    fn append_message(&mut self, label: &'static [u8], bytes: &[u8]);
    fn append_message_without_static_label(&mut self, label: &[u8], bytes: &[u8]);
    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F;
    fn challenge_scalar_without_static_label<F: Field>(&mut self, label: &[u8]) -> F;
    fn challenge_scalars<F: Field>(&mut self, label: &'static [u8], count: usize) -> Vec<F>;
    fn challenge_scalars_without_static_label<F: Field>(
        &mut self,
        label: &[u8],
        count: usize,
    ) -> Vec<F>;
    fn challenge_group_elem<G: AffineRepr>(&mut self, label: &'static [u8]) -> G;
    fn challenge_group_elem_without_static_label<G: AffineRepr>(&mut self, label: &[u8]) -> G;
}

impl Transcript for MerlinTranscript {
    fn append_without_static_label<S: CanonicalSerialize>(&mut self, label: &[u8], element: &S) {
        let mut buff: Vec<u8> = vec![0; element.compressed_size()];
        element
            .serialize_compressed(&mut buff)
            .expect("serialization failed");
        self.merlin
            .append_message_with_non_static_label(label, &buff);
    }

    fn append_message_without_static_label(&mut self, label: &[u8], bytes: &[u8]) {
        self.merlin
            .append_message_with_non_static_label(label, bytes)
    }

    fn challenge_scalar_without_static_label<F: Field>(&mut self, label: &[u8]) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = [0; 64];
        self.merlin
            .challenge_bytes_with_non_static_label(label, &mut buf);
        let mut counter = 0;
        loop {
            let c = F::from_random_bytes(&buf);
            if let Some(chal) = c {
                if let Some(c_inv) = chal.inverse() {
                    return c_inv;
                }
            }

            buf[0] = counter;
            counter += 1;
            self.merlin
                .challenge_bytes_with_non_static_label(label, &mut buf);
        }
    }

    fn challenge_scalars_without_static_label<F: Field>(
        &mut self,
        label: &[u8],
        count: usize,
    ) -> Vec<F> {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = vec![0; count * 64];
        self.merlin
            .challenge_bytes_with_non_static_label(label, &mut buf);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let mut counter = 0;
            let start = i * 64;
            let end = (i + 1) * 64;
            loop {
                let c = F::from_random_bytes(&buf[start..end]);
                if let Some(chal) = c {
                    if let Some(c_inv) = chal.inverse() {
                        out.push(c_inv);
                        break;
                    }
                }
                buf[start] = counter;
                counter += 1;
                self.merlin
                    .challenge_bytes_with_non_static_label(label, &mut buf[start..end]);
            }
        }
        out
    }

    fn challenge_group_elem_without_static_label<G: AffineRepr>(&mut self, label: &[u8]) -> G {
        let mut buf = [0; 64];
        self.merlin
            .challenge_bytes_with_non_static_label(label, &mut buf);
        let mut counter = 0;
        loop {
            let c = G::from_random_bytes(&buf);
            if let Some(chal) = c {
                return chal;
            }

            buf[0] = counter;
            counter += 1;
            self.merlin
                .challenge_bytes_with_non_static_label(label, &mut buf);
        }
    }

    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], element: &S) {
        let mut buff: Vec<u8> = vec![0; element.compressed_size()];
        element
            .serialize_compressed(&mut buff)
            .expect("serialization failed");
        self.merlin.append_message(label, &buff);
    }

    fn append_message(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.merlin.append_message(label, bytes)
    }

    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = [0; 64];
        self.merlin.challenge_bytes(label, &mut buf);
        let mut counter = 0;
        loop {
            let c = F::from_random_bytes(&buf);
            if let Some(chal) = c {
                if let Some(c_inv) = chal.inverse() {
                    return c_inv;
                }
            }

            buf[0] = counter;
            counter += 1;
            self.merlin.challenge_bytes(label, &mut buf);
        }
    }

    fn challenge_scalars<F: Field>(&mut self, label: &'static [u8], count: usize) -> Vec<F> {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = vec![0; count * 64];
        self.merlin.challenge_bytes(label, &mut buf);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let mut counter = 0;
            let start = i * 64;
            let end = (i + 1) * 64;
            loop {
                let c = F::from_random_bytes(&buf[start..end]);
                if let Some(chal) = c {
                    if let Some(c_inv) = chal.inverse() {
                        out.push(c_inv);
                        break;
                    }
                }
                buf[start] = counter;
                counter += 1;
                self.merlin.challenge_bytes(label, &mut buf[start..end]);
            }
        }
        out
    }

    fn challenge_group_elem<G: AffineRepr>(&mut self, label: &'static [u8]) -> G {
        let mut buf = [0; 64];
        self.merlin.challenge_bytes(label, &mut buf);
        let mut counter = 0;
        loop {
            let c = G::from_random_bytes(&buf);
            if let Some(chal) = c {
                return chal;
            }

            buf[0] = counter;
            counter += 1;
            self.merlin.challenge_bytes(label, &mut buf);
        }
    }
}

impl Write for MerlinTranscript {
    fn write(&mut self, data: &[u8]) -> ArkResult<usize> {
        self.merlin
            .append_message_with_non_static_label(&self.next_label, data);
        Ok(data.len())
    }

    #[inline]
    fn flush(&mut self) -> ArkResult<()> {
        Ok(())
    }
}

// TODO: Impl Write trait for Merlin
// TODO: Support domain-separator function that adds a label to transcript. One approach is to have MerlinTranscript struct
// that has a mutable field called write_label set which is used in call to `append_message`

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::Group;

    #[test]
    fn transcript() {
        let mut transcript = new_merlin_transcript(b"test");
        transcript.append(b"point", &G1Projective::generator());
        let f1 = transcript.challenge_scalar::<Fr>(b"scalar");
        let mut transcript2 = new_merlin_transcript(b"test");
        transcript2.append(b"point", &G1Projective::generator());
        let f2 = transcript2.challenge_scalar::<Fr>(b"scalar");
        assert_eq!(f1, f2);
    }
}
