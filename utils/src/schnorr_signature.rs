use crate::{hashing_utils::field_elem_from_try_and_incr, serde_utils::ArkObjectBytes};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Signature<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub response: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub challenge: G::ScalarField,
}

impl<G: AffineRepr> Signature<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        message: &[u8],
        secret_key: &G::ScalarField,
        gen: &G,
    ) -> Self {
        let r = G::ScalarField::rand(rng);
        let t = (*gen * r).into_affine();
        let challenge = Self::compute_challenge::<D>(&t, message);
        let response = r + challenge * secret_key;
        Self {
            response,
            challenge,
        }
    }

    pub fn verify<D: Digest>(&self, message: &[u8], public_key: &G, gen: &G) -> bool {
        let t = (*gen * self.response - *public_key * self.challenge).into_affine();
        let challenge = Self::compute_challenge::<D>(&t, message);
        challenge == self.challenge
    }

    pub fn compute_challenge<D: Digest>(t: &G, message: &[u8]) -> G::ScalarField {
        let mut challenge_bytes = vec![];
        t.serialize_compressed(&mut challenge_bytes).unwrap();
        challenge_bytes.extend_from_slice(&message);
        // TODO: This probably is not how the standard implementation of Schnorr signature generates the field element
        // from the bytes
        field_elem_from_try_and_incr::<G::ScalarField, D>(&challenge_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256r1::{Affine, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use sha2::Sha256;

    #[test]
    fn sig_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message = vec![1, 2, 3, 4];
        let gen = Affine::rand(&mut rng);
        let sk = Fr::rand(&mut rng);
        let pk = (gen * sk).into_affine();
        let sig = Signature::new::<_, Sha256>(&mut rng, &message, &sk, &gen);
        assert!(sig.verify::<Sha256>(&message, &pk, &gen));
    }
}
