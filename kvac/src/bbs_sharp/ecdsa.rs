use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{rand::RngCore, UniformRand, Zero};

use crate::error::KVACError;

/// ECDSA signature over a short Weierstrass curve
pub struct Signature<C: SWCurveConfig> {
    pub rand_x_coord: C::ScalarField,
    pub response: C::ScalarField,
}

impl<C: SWCurveConfig> Signature<C>
where
    C::BaseField: PrimeField,
{
    /// Create new signature given that the message has already been hashed into a scalar
    pub fn new_prehashed<R: RngCore>(
        rng: &mut R,
        hashed_message: C::ScalarField,
        secret_key: C::ScalarField,
    ) -> Self {
        let g = Self::generator();
        // r = k * g
        let mut r = Affine::<C>::default();
        // x coordinate of r
        let mut rand_x_coord = C::ScalarField::ZERO;
        // response = 1/k * (message + secret_key * rand_x_coord)
        let mut response = C::ScalarField::ZERO;
        // response should be invertible
        while r.is_zero() || rand_x_coord.is_zero() || response.is_zero() {
            let mut k = C::ScalarField::rand(rng);
            // k should be invertible
            while k.is_zero() {
                k = C::ScalarField::rand(rng);
            }
            r = (g * k).into_affine();
            rand_x_coord =
                C::ScalarField::from_le_bytes_mod_order(&r.x.into_bigint().to_bytes_le());
            response = k.inverse().unwrap() * (hashed_message + secret_key * rand_x_coord);
        }
        Self {
            rand_x_coord,
            response,
        }
    }

    /// Verify the signature given that the message has already been hashed into a scalar
    pub fn verify_prehashed(
        &self,
        hashed_message: C::ScalarField,
        public_key: Affine<C>,
    ) -> Result<(), KVACError> {
        let g = Self::generator();
        let resp_inv = self.response.inverse().ok_or(KVACError::CannotInvert0)?;
        let gc = g * (resp_inv * hashed_message);
        let yr = public_key * (resp_inv * self.rand_x_coord);
        let expected_r_x = (gc + yr).into_affine().x;
        if self.rand_x_coord
            != C::ScalarField::from_le_bytes_mod_order(&expected_r_x.into_bigint().to_bytes_le())
        {
            return Err(KVACError::InvalidEcdsaSignature);
        }
        Ok(())
    }

    /// Chosen generator of the group
    pub fn generator() -> Affine<C> {
        C::GENERATOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256r1::Config;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn sig_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        type Secp256r1 = Config;
        type Fr = <Secp256r1 as ark_ec::CurveConfig>::ScalarField;
        let message = Fr::rand(&mut rng);
        let g = Signature::<Secp256r1>::generator();
        let sk = Fr::rand(&mut rng);
        let pk = (g * sk).into_affine();
        let sig = Signature::<Secp256r1>::new_prehashed(&mut rng, message, sk);
        sig.verify_prehashed(message, pk).unwrap();
    }
}
