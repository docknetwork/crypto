use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_secp256r1::{Affine, Fr, G_GENERATOR_X, G_GENERATOR_Y};
use ark_std::{rand::RngCore, UniformRand, Zero};

/// ECDSA signature
pub struct Signature {
    pub rand_x_coord: Fr,
    pub response: Fr,
}

impl Signature {
    /// Create new signature given that the message has already been hashed into a scalar
    pub fn new_prehashed<R: RngCore>(rng: &mut R, hashed_message: Fr, secret_key: Fr) -> Self {
        let g = Self::generator();
        // r = k * g
        let mut r = Affine::zero();
        // x coordinate of r
        let mut rand_x_coord = Fr::zero();
        // response = 1/k * (message + secret_key * rand_x_coord)
        let mut response = Fr::zero();
        // response should be invertible
        while r.is_zero() || rand_x_coord.is_zero() || response.is_zero() {
            let mut k = Fr::rand(rng);
            // k should be invertible
            while k.is_zero() {
                k = Fr::rand(rng);
            }
            r = (g * k).into_affine();
            rand_x_coord = Fr::from(r.x.into_bigint());
            response = k.inverse().unwrap() * (hashed_message + secret_key * rand_x_coord);
        }
        Self {
            rand_x_coord,
            response,
        }
    }

    /// Verify the signature given that the message has already been hashed into a scalar
    pub fn verify_prehashed(&self, hashed_message: Fr, public_key: Affine) -> bool {
        let g = Self::generator();
        let resp_inv = if let Some(inv) = self.response.inverse() {
            inv
        } else {
            return false;
        };
        let gc = g * (resp_inv * hashed_message);
        let yr = public_key * (resp_inv * self.rand_x_coord);
        self.rand_x_coord == Fr::from((gc + yr).into_affine().x.into_bigint())
    }

    /// Chosen generator of the group
    pub fn generator() -> Affine {
        Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn sig_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message = Fr::rand(&mut rng);
        let g = Signature::generator();
        let sk = Fr::rand(&mut rng);
        let pk = (g * sk).into_affine();
        let sig = Signature::new_prehashed(&mut rng, message, sk);
        assert!(sig.verify_prehashed(message, pk));
    }
}
