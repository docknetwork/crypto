use crate::setup::SecretKey;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use digest::Digest;
use dock_crypto_utils::{affine_group_element_from_byte_slices, serde_utils::ArkObjectBytes};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Public key for accumulator manager
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

/// Setup parameters for accumulators
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SetupParams<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

impl<G: AffineRepr> SetupParams<G> {
    /// Generate params by hashing a known string. The hash function is vulnerable to timing
    /// attack but since all this is public knowledge, it is fine.
    /// This is useful if people need to be convinced that the discrete log of group elements wrt each other is not known.
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        Self(affine_group_element_from_byte_slices!(label, b" : P"))
    }

    /// Params shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }
}

impl<G: AffineRepr> AsRef<G> for SetupParams<G> {
    fn as_ref(&self) -> &G {
        &self.0
    }
}

impl<G: AffineRepr> PublicKey<G> {
    /// Generate public key from given secret key and signature parameters
    pub fn new_from_secret_key(
        secret_key: &SecretKey<G::ScalarField>,
        setup_params: &SetupParams<G>,
    ) -> Self {
        Self(
            setup_params
                .0
                .mul_bigint(secret_key.0.into_bigint())
                .into_affine(),
        )
    }

    /// Public key shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::{
        compute_random_oracle_challenge,
        discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    };

    #[test]
    fn proof_of_knowledge_of_public_key() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = SetupParams::<G1Affine>::new::<Blake2b512>(b"test");
        assert!(params.is_valid());

        let seed = [0, 1, 2, 10, 11];
        let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
        let pk = PublicKey::new_from_secret_key(&sk, &params);
        assert!(pk.is_valid());

        let base = &params.0;
        let witness = sk.0;
        let blinding = Fr::rand(&mut rng);

        let protocol = PokDiscreteLogProtocol::<G1Affine>::init(witness, blinding, base);

        let mut chal_contrib_prover = vec![];
        protocol
            .challenge_contribution(base, &pk.0, &mut chal_contrib_prover)
            .unwrap();

        test_serialization!(PokDiscreteLogProtocol::<G1Affine>, protocol);

        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_contrib_verifier = vec![];
        proof
            .challenge_contribution(base, &pk.0, &mut chal_contrib_verifier)
            .unwrap();

        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);
        assert!(proof.verify(&pk.0, base, &challenge_verifier));
        assert_eq!(chal_contrib_prover, chal_contrib_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        test_serialization!(PokDiscreteLog<G1Affine>, proof);
    }
}
