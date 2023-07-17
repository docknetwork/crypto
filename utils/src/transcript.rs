use ark_ec::AffineRepr;
use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::{vec, vec::Vec};
pub use merlin::Transcript as Merlin;

/// must be specific to the application.
pub fn new_merlin_transcript(label: &'static [u8]) -> impl Transcript {
    Merlin::new(label)
}

/// Transcript is the application level transcript to derive the challenges
/// needed for Fiat Shamir during aggregation. It is given to the
/// prover/verifier so that the transcript can be fed with any other data first.
/// Taken from <https://github.com/nikkolasg/snarkpack>
pub trait Transcript {
    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], point: &S);
    fn append_message(&mut self, label: &'static [u8], bytes: &[u8]);
    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F;
    fn challenge_scalars<F: Field>(&mut self, label: &'static [u8], count: usize) -> Vec<F>;
    fn challenge_group_elem<G: AffineRepr>(&mut self, label: &'static [u8]) -> G;
}

impl Transcript for Merlin {
    fn append<S: CanonicalSerialize>(&mut self, label: &'static [u8], element: &S) {
        let mut buff: Vec<u8> = vec![0; element.compressed_size()];
        element
            .serialize_compressed(&mut buff)
            .expect("serialization failed");
        self.append_message(label, &buff);
    }

    fn append_message(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.append_message(label, bytes)
    }

    fn challenge_scalar<F: Field>(&mut self, label: &'static [u8]) -> F {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
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
            self.challenge_bytes(label, &mut buf);
        }
    }

    fn challenge_scalars<F: Field>(&mut self, label: &'static [u8], count: usize) -> Vec<F> {
        // Reduce a double-width scalar to ensure a uniform distribution
        // TODO: It assumes 32 byte field element. Make it generic
        let mut buf = vec![0; count * 64];
        self.challenge_bytes(label, &mut buf);
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
                self.challenge_bytes(label, &mut buf[start..end]);
            }
        }
        out
    }

    fn challenge_group_elem<G: AffineRepr>(&mut self, label: &'static [u8]) -> G {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        let mut counter = 0;
        loop {
            let c = G::from_random_bytes(&buf);
            if let Some(chal) = c {
                return chal;
            }

            buf[0] = counter;
            counter += 1;
            self.challenge_bytes(label, &mut buf);
        }
    }
}

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
