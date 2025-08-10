//! Asymmetric Dodis-Yampolskiy VRF

use crate::{error::SyraError, setup::PreparedSetupParams};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, vec::Vec};
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PRF output
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output<E: Pairing>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub PairingOutput<E>,
);

/// Proof of correct PRF output
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Proof<E: Pairing>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub E::G1Affine,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub E::G2Affine,
);

impl<E: Pairing> Output<E> {
    pub fn generate<'a>(
        message: E::ScalarField,
        secret_key: impl Into<&'a E::ScalarField>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> (Self, Proof<E>) {
        let params = params.into();
        let exp = (message + secret_key.into()).inverse().unwrap();
        let out = params.pairing * exp;
        let proof = Proof((params.g * exp).into(), (params.g_hat * exp).into());
        (Self(out), proof)
    }
}

impl<E: Pairing> Proof<E> {
    pub fn verify<'a>(
        &self,
        message: E::ScalarField,
        output: &Output<E>,
        public_key: impl Into<&'a E::G2Affine>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), SyraError> {
        let params = params.into();
        let prep_0 = E::G1Prepared::from(self.0);
        let prep_1 = E::G2Prepared::from(self.1);
        if E::pairing(prep_0.clone(), (params.g_hat * message) + public_key.into())
            != params.pairing
        {
            return Err(SyraError::InvalidProof);
        }
        if E::pairing(prep_0.clone(), params.g_hat) != output.0 {
            return Err(SyraError::InvalidProof);
        }
        if !E::multi_pairing(
            [E::G1Prepared::from(params.g), prep_0],
            [prep_1, params.g_hat.into_group().neg().into().into()],
        )
        .is_zero()
        {
            return Err(SyraError::InvalidProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    use crate::setup::{IssuerPublicKey, IssuerSecretKey, SetupParams};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn output_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
        let sk = IssuerSecretKey::new(&mut rng);
        let pk = IssuerPublicKey::new(&mut rng, &sk, &params);

        let message = Fr::rand(&mut rng);
        let start = Instant::now();
        let (out, proof) = Output::generate(message.clone(), sk.as_ref(), params.clone());
        println!("Time to create VRF output {:?}", start.elapsed());

        let start = Instant::now();
        proof.verify(message, &out, pk.as_ref(), params).unwrap();
        println!("Time to verify VRF output {:?}", start.elapsed());
    }
}
