#![allow(non_snake_case)]

//! Keys and setup parameters. Described in section 2 of the paper
//! # Examples
//!
//! Creating setup parameters and keypair:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use blake2::Blake2b512;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let params_1 = SetupParams::<Bls12_381>::new::<Blake2b512>(&[1, 2, 3, 4]);
//!
//! // Generate keypair using random number generator
//! let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
//!
//! // Generate keypair using a secret `seed`. The same seed will return same keypair. The seed
//! // is hashed (along with other things) using the given hash function, the example below use Blake2b512
//! // let seed: &[u8] = <Some secret seed>
//! let keypair_1 = Keypair::<Bls12_381>::generate_using_seed::<Blake2b512>(seed, &params);
//!
//! // Another way to generate keypair is
//! let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
//! let pk = Keypair::public_key_from_secret_key(&sk, &params);
//! Keypair {secret_key: sk, public_key: pk}
//!
//! ```

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, io::Write, rand::RngCore, vec::Vec, UniformRand};
use zeroize::{Zeroize, ZeroizeOnDrop};

use digest::{Digest, DynDigest};
use schnorr_pok::{error::SchnorrError, SchnorrChallengeContributor};

use dock_crypto_utils::{
    affine_group_element_from_byte_slices, concat_slices,
    hashing_utils::{hash_to_field, projective_group_elem_from_try_and_incr},
    join,
    serde_utils::*,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::common::ProvingKey;

/// Secret key for accumulator manager
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField>(#[serde_as(as = "ArkObjectBytes")] pub F);

/// Public key for accumulator manager
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PublicKey<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub E::G2Affine);

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct Keypair<E: Pairing> {
    pub secret_key: SecretKey<E::ScalarField>,
    #[zeroize(skip)]
    pub public_key: PublicKey<E>,
}

/// Setup parameters for accumulators
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SetupParams<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub P: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub P_tilde: E::G2Affine,
}

impl<F: PrimeField> SecretKey<F> {
    pub const DST: &'static [u8] = b"VB-ACCUM-KEYGEN-SALT";

    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(F::rand(rng))
    }

    pub fn generate_using_seed<D>(seed: &[u8]) -> Self
    where
        F: PrimeField,
        D: DynDigest + Default + Clone,
    {
        Self(hash_to_field::<F, D>(Self::DST, seed))
    }
}

impl<F: PrimeField> AsRef<F> for SecretKey<F> {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl<E: Pairing> SetupParams<E> {
    /// Generate params using a random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self {
            P: E::G1Affine::rand(rng),
            P_tilde: E::G2Affine::rand(rng),
        }
    }

    /// Generate params by hashing a known string. The hash function is vulnerable to timing
    /// attack but since all this is public knowledge, it is fine.
    /// This is useful if people need to be convinced that the discrete log of group elements wrt each other is not known.
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let (P, P_tilde) = join!(
            affine_group_element_from_byte_slices!(label, b" : P"),
            affine_group_element_from_byte_slices!(label, b" : P_tilde")
        );

        Self { P, P_tilde }
    }

    /// Params shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.P.is_zero() && !self.P_tilde.is_zero()
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for SetupParams<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.P
    }
}

impl<E: Pairing> Keypair<E> {
    /// Create a secret key and corresponding public key using seed
    pub fn generate_using_seed<D>(seed: &[u8], setup_params: &SetupParams<E>) -> Self
    where
        D: DynDigest + Default + Clone,
    {
        let secret_key = SecretKey::<E::ScalarField>::generate_using_seed::<D>(seed);
        let public_key = Self::public_key_from_secret_key(&secret_key, setup_params);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a secret key and corresponding public key using given pseudo random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R, setup_params: &SetupParams<E>) -> Self {
        let secret_key = SecretKey(E::ScalarField::rand(rng));
        let public_key = Self::public_key_from_secret_key(&secret_key, setup_params);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Generate public key from given secret key and signature parameters
    pub fn public_key_from_secret_key(
        secret_key: &SecretKey<E::ScalarField>,
        setup_params: &SetupParams<E>,
    ) -> PublicKey<E> {
        PublicKey(
            setup_params
                .P_tilde
                .mul_bigint(secret_key.0.into_bigint())
                .into(),
        )
    }
}

impl<E: Pairing> PublicKey<E> {
    /// Generate public key from given secret key and signature parameters
    pub fn new_from_secret_key(
        secret_key: &SecretKey<E::ScalarField>,
        setup_params: &SetupParams<E>,
    ) -> Self {
        Self(
            setup_params
                .P_tilde
                .mul_bigint(secret_key.0.into_bigint())
                .into_affine(),
        )
    }

    /// Public key shouldn't be 0
    pub fn is_valid(&self) -> bool {
        !self.0.is_zero()
    }
}

#[serde_as]
#[derive(
    Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedSetupParams<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub P: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub P_tilde: E::G2Prepared,
}

#[serde_as]
#[derive(
    Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedPublicKey<E: Pairing>(#[serde_as(as = "ArkObjectBytes")] pub E::G2Prepared);

impl<E: Pairing> From<SetupParams<E>> for PreparedSetupParams<E> {
    fn from(params: SetupParams<E>) -> Self {
        Self {
            P: params.P,
            P_tilde: E::G2Prepared::from(params.P_tilde),
        }
    }
}

impl<E: Pairing> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(pk: PublicKey<E>) -> Self {
        Self(E::G2Prepared::from(pk.0))
    }
}

/// Used between prover and verifier only to prove knowledge of member and corresponding witness.
/// `X`, `Y` and `Z` from the paper
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MembershipProvingKey<G: AffineRepr>(
    #[serde(bound = "ProvingKey<G>: Serialize, for<'a> ProvingKey<G>: Deserialize<'a>")]
    pub  ProvingKey<G>,
);

/// Used between prover and verifier only to prove knowledge of non-member and corresponding witness
/// `X`, `Y`, `Z` and `K` from the paper
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipProvingKey<G: AffineRepr> {
    #[serde(bound = "ProvingKey<G>: Serialize, for<'a> ProvingKey<G>: Deserialize<'a>")]
    pub XYZ: ProvingKey<G>,
    #[serde_as(as = "ArkObjectBytes")]
    pub K: G,
}

impl<G> MembershipProvingKey<G>
where
    G: AffineRepr,
{
    /// Generate using a random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self(ProvingKey::generate_using_rng(rng))
    }

    /// Generate by hashing known strings
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        Self(ProvingKey::generate_using_hash::<D>(label))
    }
}

impl<G> NonMembershipProvingKey<G>
where
    G: AffineRepr,
{
    /// Generate using a random number generator
    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let XYZ = ProvingKey::generate_using_rng(rng);
        Self {
            XYZ,
            K: G::Group::rand(rng).into(),
        }
    }

    /// Generate by hashing known strings
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let XYZ = ProvingKey::generate_using_hash::<D>(label);
        Self {
            XYZ,
            K: projective_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : K"])
                .into(),
        }
    }

    /// Derive the membership proving key when doing a membership proof with a universal accumulator.
    pub fn derive_membership_proving_key(&self) -> MembershipProvingKey<G> {
        MembershipProvingKey(self.XYZ.clone())
    }
}

impl<G: AffineRepr> AsRef<ProvingKey<G>> for MembershipProvingKey<G> {
    fn as_ref(&self) -> &ProvingKey<G> {
        &self.0
    }
}

impl<G: AffineRepr> SchnorrChallengeContributor for MembershipProvingKey<G> {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SchnorrError> {
        self.0.challenge_contribution(writer)
    }
}

impl<G: AffineRepr> SchnorrChallengeContributor for NonMembershipProvingKey<G> {
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.XYZ.challenge_contribution(&mut writer)?;
        self.K
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::{
        compute_random_oracle_challenge,
        discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    };

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn keypair() {
        // Same seed generates same keypair
        let params = SetupParams::<Bls12_381>::new::<Blake2b512>("test".as_bytes());
        assert!(params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P = <Bls12_381 as Pairing>::G1Affine::zero();
        assert!(!invalid_params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P_tilde = <Bls12_381 as Pairing>::G2Affine::zero();
        assert!(!invalid_params.is_valid());
        let mut invalid_params = params.clone();
        invalid_params.P = <Bls12_381 as Pairing>::G1Affine::zero();
        invalid_params.P_tilde = <Bls12_381 as Pairing>::G2Affine::zero();
        assert!(!invalid_params.is_valid());

        let seed = vec![0, 1, 4, 6, 2, 10];

        let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
        assert_eq!(sk, SecretKey::generate_using_seed::<Blake2b512>(&seed));

        let pk = Keypair::public_key_from_secret_key(&sk, &params);
        assert!(pk.is_valid());
        let mut invalid_pk = pk.clone();
        invalid_pk.0 = <Bls12_381 as Pairing>::G2Affine::zero();
        assert!(!invalid_pk.is_valid());

        let keypair = Keypair::generate_using_seed::<Blake2b512>(&seed, &params);
        assert_eq!(
            keypair,
            Keypair {
                secret_key: sk.clone(),
                public_key: pk
            }
        );
        drop(sk);
        drop(keypair);
    }

    #[test]
    fn setup_serialization() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
        test_serialization!(SetupParams<Bls12_381>, params);

        let params_1 = SetupParams::<Bls12_381>::new::<Blake2b512>("test".as_bytes());
        test_serialization!(SetupParams<Bls12_381>, params_1);

        let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
        test_serialization!(
            SecretKey<<Bls12_381 as Pairing>::ScalarField>,
            keypair.secret_key
        );
        test_serialization!(PublicKey<Bls12_381>, keypair.public_key);

        test_serialization!(
            PreparedSetupParams<Bls12_381>,
            PreparedSetupParams::from(params.clone())
        );
        test_serialization!(
            PreparedPublicKey<Bls12_381>,
            PreparedPublicKey::from(keypair.public_key.clone())
        );
    }

    #[test]
    fn proof_of_knowledge_of_public_key() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);

        let seed = [0, 1, 2, 10, 11];
        let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
        let pk = Keypair::public_key_from_secret_key(&sk, &params);

        let base = &params.P_tilde;
        let witness = sk.0;
        let blinding = Fr::rand(&mut rng);

        let protocol = PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::G2Affine>::init(
            witness, blinding, base,
        );

        let mut chal_contrib_prover = vec![];
        protocol
            .challenge_contribution(base, &pk.0, &mut chal_contrib_prover)
            .unwrap();

        test_serialization!(
            PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::G2Affine>,
            protocol
        );

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

        test_serialization!(PokDiscreteLog<<Bls12_381 as Pairing>::G2Affine>, proof);
    }
}
