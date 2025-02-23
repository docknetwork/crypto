//! Schnorr protocol for proving knowledge of discrete logs
//!
//! The following are specializations of the Schnorr protocol implemented using `SchnorrCommitment` and `SchnorrResponse`.
//! Proving knowledge of 1 or 2 discrete logs is quite common and the following avoid creating vectors.
//!
//! To prove knowledge of a single discrete log, i.e. given public `Y` and `G`, prove knowledge of `x` in `G * x = Y`:
//! 1. Prover chooses a random `r` and computes `T = G * r`
//! 2. Hashes `T` towards getting a challenge `c`.
//! 3. Computes response `s = r + c*x` and sends it to the verifier.
//! 4. Verifier checks if `G * s = T + Y*c`
//!
//! To prove knowledge of 2 discrete logs, i.e. given public `Y`, `G1` and `G2`, prove knowledge of `x1` and `x2` in `G1 * x1 + G2 * x2 = Y`.
//! 1. Prover chooses 2 random `r1` and `r2` and computes `T = G1 * r1 + G2 * r2`
//! 2. Hashes `T` towards getting a challenge `c`.
//! 3. Computes 2 responses `s1 = r1 + c*x1` and `s2 = r2 + c*x2` and sends them to the verifier.
//! 4. Verifier checks if `G1 * s1 + G2 * s2 = T + Y*c`

use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, vec::Vec};
use dock_crypto_utils::{
    randomized_mult_checker::RandomizedMultChecker, serde_utils::ArkObjectBytes,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol for proving knowledge of discrete log, i.e given public `Y` and `G`, prove knowledge of `x` in `G * x = y`
#[serde_as]
#[derive(
    Default,
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
pub struct PokDiscreteLogProtocol<G: AffineRepr> {
    /// Commitment to randomness
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    /// Randomness chosen by the prover
    #[serde_as(as = "ArkObjectBytes")]
    blinding: G::ScalarField,
    /// Prover's secret `x`
    #[serde_as(as = "ArkObjectBytes")]
    witness: G::ScalarField,
}

/// Proof of knowledge of discrete log
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PokDiscreteLog<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response: G::ScalarField,
}

/// Protocol for proving knowledge of 2 discrete logs, i.e given public `Y`, `G1` and `G2`, prove knowledge of `x1` and `x2` in `G1 * x1 + G2 * x2 = Y`
#[serde_as]
#[derive(
    Default,
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
pub struct PokPedersenCommitmentProtocol<G: AffineRepr> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) blinding1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) witness1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) blinding2: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub(crate) witness2: G::ScalarField,
}

/// Proof of knowledge of 2 discrete logs
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PokPedersenCommitment<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub response2: G::ScalarField,
}

impl<G: AffineRepr> PokDiscreteLogProtocol<G> {
    pub fn init(witness: G::ScalarField, blinding: G::ScalarField, base: &G) -> Self {
        let t = base.mul_bigint(blinding.into_bigint()).into_affine();
        Self {
            t,
            blinding,
            witness,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(base, y, &self.t, writer)
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> PokDiscreteLog<G> {
        let response = self.blinding + (self.witness * *challenge);
        PokDiscreteLog {
            t: self.t,
            response,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        base: &G,
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        base.serialize_compressed(&mut writer)?;
        y.serialize_compressed(&mut writer)?;
        t.serialize_compressed(writer).map_err(|e| e.into())
    }
}

impl<G: AffineRepr> PokDiscreteLog<G> {
    pub fn challenge_contribution<W: Write>(
        &self,
        base: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokDiscreteLogProtocol::compute_challenge_contribution(base, y, &self.t, writer)
    }

    /// `base*response - y*challenge == t`
    pub fn verify(&self, y: &G, base: &G, challenge: &G::ScalarField) -> bool {
        let mut expected = base.mul_bigint(self.response.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base: G,
        challenge: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_2(base, &self.response, y, &challenge.neg(), self.t)
    }
}

impl<G: AffineRepr> PokPedersenCommitmentProtocol<G> {
    pub fn init(
        witness1: G::ScalarField,
        blinding1: G::ScalarField,
        base1: &G,
        witness2: G::ScalarField,
        blinding2: G::ScalarField,
        base2: &G,
    ) -> Self {
        let t = (base1.mul_bigint(blinding1.into_bigint())
            + base2.mul_bigint(blinding2.into_bigint()))
        .into_affine();
        Self {
            t,
            blinding1,
            witness1,
            blinding2,
            witness2,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        Self::compute_challenge_contribution(base1, base2, y, &self.t, writer)
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> PokPedersenCommitment<G> {
        let response1 = self.blinding1 + (self.witness1 * *challenge);
        let response2 = self.blinding2 + (self.witness2 * *challenge);
        PokPedersenCommitment {
            t: self.t,
            response1,
            response2,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        base1: &G,
        base2: &G,
        y: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), SchnorrError> {
        base1.serialize_compressed(&mut writer)?;
        base2.serialize_compressed(&mut writer)?;
        y.serialize_compressed(&mut writer)?;
        t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> PokPedersenCommitment<G> {
    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokPedersenCommitmentProtocol::compute_challenge_contribution(
            base1, base2, y, &self.t, writer,
        )
    }

    /// `base1*response1 + base2*response2 - y*challenge == t`
    pub fn verify(&self, y: &G, base1: &G, base2: &G, challenge: &G::ScalarField) -> bool {
        let mut expected = base1.mul_bigint(self.response1.into_bigint());
        expected += base2.mul_bigint(self.response2.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base1: G,
        base2: G,
        challenge: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_3(
            base1,
            &self.response1,
            base2,
            &self.response2,
            y,
            &challenge.neg(),
            self.t,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pok_generalized_pedersen::compute_random_oracle_challenge, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn discrete_log() {
        let mut rng = StdRng::seed_from_u64(0u64);

        macro_rules! check {
            ($group_affine:ident, $group_projective:ident) => {
                let base = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let witness = Fr::rand(&mut rng);
                let y = base.mul_bigint(witness.into_bigint()).into_affine();
                let blinding = Fr::rand(&mut rng);
                let protocol =
                    PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        witness, blinding, &base,
                    );
                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(&base, &y, &mut chal_contrib_prover)
                    .unwrap();

                test_serialization!(
                    PokDiscreteLogProtocol<<Bls12_381 as Pairing>::$group_affine>,
                    protocol
                );

                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
                let proof = protocol.gen_proof(&challenge_prover);

                let mut chal_contrib_verifier = vec![];
                proof
                    .challenge_contribution(&base, &y, &mut chal_contrib_verifier)
                    .unwrap();

                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);
                assert!(proof.verify(&y, &base, &challenge_verifier));
                assert_eq!(chal_contrib_prover, chal_contrib_verifier);
                assert_eq!(challenge_prover, challenge_verifier);

                test_serialization!(PokDiscreteLog<<Bls12_381 as Pairing>::$group_affine>, proof);

                let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
                proof.verify_using_randomized_mult_checker(
                    y,
                    base,
                    &challenge_verifier,
                    &mut checker,
                );
                assert!(checker.verify());

                // Incorrect should fail
                let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
                proof.verify_using_randomized_mult_checker(
                    base,
                    y,
                    &challenge_verifier,
                    &mut checker,
                );
                assert!(!checker.verify());
            };
        }

        check!(G1Affine, G1);
        check!(G2Affine, G2);
    }

    #[test]
    fn pedersen_comm() {
        let mut rng = StdRng::seed_from_u64(0u64);

        macro_rules! check {
            ($group_affine:ident, $group_projective:ident) => {
                let base1 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let witness1 = Fr::rand(&mut rng);
                let base2 = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
                let witness2 = Fr::rand(&mut rng);
                let y = (base1 * witness1 + base2 * witness2).into_affine();
                let blinding1 = Fr::rand(&mut rng);
                let blinding2 = Fr::rand(&mut rng);
                let protocol =
                    PokPedersenCommitmentProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        witness1, blinding1, &base1, witness2, blinding2, &base2,
                    );
                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(&base1, &base2, &y, &mut chal_contrib_prover)
                    .unwrap();

                test_serialization!(
                    PokPedersenCommitmentProtocol<<Bls12_381 as Pairing>::$group_affine>,
                    protocol
                );

                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
                let proof = protocol.gen_proof(&challenge_prover);

                let mut chal_contrib_verifier = vec![];
                proof
                    .challenge_contribution(&base1, &base2, &y, &mut chal_contrib_verifier)
                    .unwrap();

                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);
                assert!(proof.verify(&y, &base1, &base2, &challenge_verifier));
                assert_eq!(chal_contrib_prover, chal_contrib_verifier);
                assert_eq!(challenge_prover, challenge_verifier);

                test_serialization!(
                    PokPedersenCommitment<<Bls12_381 as Pairing>::$group_affine>,
                    proof
                );

                let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
                proof.verify_using_randomized_mult_checker(
                    y,
                    base1,
                    base2,
                    &challenge_verifier,
                    &mut checker,
                );
                assert!(checker.verify());

                let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
                proof.verify_using_randomized_mult_checker(
                    y,
                    base2,
                    base1,
                    &challenge_verifier,
                    &mut checker,
                );
                assert!(!checker.verify());
            };
        }

        check!(G1Affine, G1);
        check!(G2Affine, G2);
    }
}
