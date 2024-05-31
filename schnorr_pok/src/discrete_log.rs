//! Schnorr protocol for proving knowledge of discrete logs
//!
//! The following are specializations of the Schnorr protocol implemented using `SchnorrCommitment` and `SchnorrResponse`.
//! Proving knowledge of 1 or 2 discrete logs is quite common and the following avoid creating vectors.
//!
//! To prove knowledge of a single discrete log, i.e. given public `y` and `g`, prove knowledge of `x` in `g * x = y`:
//! 1. Prover chooses a random `r` and computes `t = g * r`
//! 2. Hashes `t` towards getting a challenge `c`.
//! 3. Computes response `s = r + c*x` and sends it to the verifier.
//! 4. Verifier checks if `g * s = t + y*c`
//!
//! To prove knowledge of 2 discrete logs, i.e. given public `y`, `g1` and `g2`, prove knowledge of `x1` and `x2` in `g1 * x1 + g2 * x2 = y`.
//! 1. Prover chooses 2 random `r1` and `r2` and computes `t = g1 * r1 + g2 * r2`
//! 2. Hashes `t` towards getting a challenge `c`.
//! 3. Computes 2 responses `s1 = r1 + c*x1` and `s2 = r2 + c*x2` and sends them to the verifier.
//! 4. Verifier checks if `g1 * s1 + g2 * s2 = t + y*c`

use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, vec::Vec};
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol for proving knowledge of discrete log, i.e given public `y` and `g`, prove knowledge of `x` in `g * x = y`
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

/// Protocol for proving knowledge of 2 discrete logs, i.e given public `y`, `g1` and `g2`, prove knowledge of `x1` and `x2` in `g1 * x1 + g2 * x2 = y`
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
pub struct PokTwoDiscreteLogsProtocol<G: AffineRepr> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    blinding1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    witness1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    blinding2: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    witness2: G::ScalarField,
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
pub struct PokTwoDiscreteLogs<G: AffineRepr> {
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
}

impl<G: AffineRepr> PokTwoDiscreteLogsProtocol<G> {
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

    pub fn gen_proof(self, challenge: &G::ScalarField) -> PokTwoDiscreteLogs<G> {
        let response1 = self.blinding1 + (self.witness1 * *challenge);
        let response2 = self.blinding2 + (self.witness2 * *challenge);
        PokTwoDiscreteLogs {
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

impl<G: AffineRepr> PokTwoDiscreteLogs<G> {
    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokTwoDiscreteLogsProtocol::compute_challenge_contribution(base1, base2, y, &self.t, writer)
    }

    /// `base1*response1 + base2*response2 - y*challenge == t`
    pub fn verify(&self, y: &G, base1: &G, base2: &G, challenge: &G::ScalarField) -> bool {
        let mut expected = base1.mul_bigint(self.response1.into_bigint());
        expected += base2.mul_bigint(self.response2.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_random_oracle_challenge, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn schnorr_single() {
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
            };
        }

        check!(G1Affine, G1);
        check!(G2Affine, G2);
    }

    #[test]
    fn schnorr_double() {
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
                    PokTwoDiscreteLogsProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        witness1, blinding1, &base1, witness2, blinding2, &base2,
                    );
                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(&base1, &base2, &y, &mut chal_contrib_prover)
                    .unwrap();

                test_serialization!(
                    PokTwoDiscreteLogsProtocol<<Bls12_381 as Pairing>::$group_affine>,
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
                    PokTwoDiscreteLogs<<Bls12_381 as Pairing>::$group_affine>,
                    proof
                );
            };
        }

        check!(G1Affine, G1);
        check!(G2Affine, G2);
    }
}
