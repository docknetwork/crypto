use crate::hashing_utils::field_elem_from_try_and_incr;
#[cfg(feature = "serde")]
use crate::serde_utils::ArkObjectBytes;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub response: G::ScalarField,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub challenge: G::ScalarField,
}

impl<G: AffineRepr> Signature<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        message: &[u8],
        secret_key: &G::ScalarField,
        g: &G,
    ) -> Self {
        let r = G::ScalarField::rand(rng);
        let t = (*g * r).into_affine();
        let challenge = Self::compute_challenge::<D>(&t, message);
        let response = r + challenge * secret_key;
        Self {
            response,
            challenge,
        }
    }

    pub fn verify<D: Digest>(&self, message: &[u8], public_key: &G, g: &G) -> bool {
        let t = (*g * self.response - *public_key * self.challenge).into_affine();
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
        let g = Affine::rand(&mut rng);
        let sk = Fr::rand(&mut rng);
        let pk = (g * sk).into_affine();
        let sig = Signature::new::<_, Sha256>(&mut rng, &message, &sk, &g);
        assert!(sig.verify::<Sha256>(&message, &pk, &g));
    }
}
