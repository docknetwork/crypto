//! Proofs of knowledge of weak-BB signature with keyed-verification, i.e. the verifier needs to know the secret key to verify the proof.
//! `g1` is generator of group G1, secret key = `x`, message = `m`, signature = `A = g1 * 1/(x + m)`
//! 1. Prover chooses random `r` from Z_p.
//! 2. Prover creates `A' = A * r` and `A_bar = g1 * r - A' * m`. Note that `A_bar = A' * x`
//! 3. Prover creates proof of knowledge `pi`, of `r` and `m` in `A_bar` and sends `pi, A', A_bar` to the verifier.
//! 4. Verifier checks if `A_bar = A' * x` and then verifies proof `pi`

use crate::error::ShortGroupSigError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use core::mem;

use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of weak-BB signature in the keyed-verification model
#[derive(Default, Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoKOfSignatureG1KVProtocol<G: AffineRepr> {
    /// The randomized signature
    #[zeroize(skip)]
    pub A_prime: G,
    #[zeroize(skip)]
    pub A_bar: G,
    /// For proving relation `A_bar = g1 * r - A' * m`
    pub sc: PokTwoDiscreteLogsProtocol<G>,
}

/// Proof of knowledge of weak-BB signature in the keyed-verification model
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKOfSignatureG1KV<G: AffineRepr> {
    /// The randomized signature
    #[serde_as(as = "ArkObjectBytes")]
    pub A_prime: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: G,
    /// For proving relation `A_bar = g1 * r - A' * m`
    pub sc: PokTwoDiscreteLogs<G>,
}

impl<G: AffineRepr> PoKOfSignatureG1KVProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: impl AsRef<G>,
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
        g1: &G,
    ) -> Self {
        let sig_randomizer = G::ScalarField::rand(rng);
        let sc_blinding = G::ScalarField::rand(rng);
        let msg_blinding = blinding.unwrap_or_else(|| G::ScalarField::rand(rng));
        Self::init_with_given_randomness(
            sig_randomizer,
            msg_blinding,
            sc_blinding,
            signature,
            message,
            g1,
        )
    }

    /// Same as `Self::init` but uses the given randomness
    pub fn init_with_given_randomness(
        sig_randomizer: G::ScalarField,
        msg_blinding: G::ScalarField,
        sc_blinding: G::ScalarField,
        signature: impl AsRef<G>,
        message: G::ScalarField,
        g1: &G,
    ) -> Self {
        let sig_r = sig_randomizer.into_bigint();
        // A * r
        let A_prime = signature.as_ref().mul_bigint(sig_r);
        let A_prime_neg = A_prime.neg();
        // A_bar = g1 * r - A' * m
        let A_bar = g1.mul_bigint(sig_r) + A_prime_neg * message;
        let sc = PokTwoDiscreteLogsProtocol::init(
            sig_randomizer,
            sc_blinding,
            g1,
            message,
            msg_blinding,
            &A_prime_neg.into(),
        );
        Self {
            A_prime: A_prime.into_affine(),
            A_bar: A_bar.into_affine(),
            sc,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g1: &G,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(&self.A_prime, &self.A_bar, g1, &self.sc.t, writer)
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> PoKOfSignatureG1KV<G> {
        let sc = mem::take(&mut self.sc).gen_proof(challenge);
        PoKOfSignatureG1KV {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            sc,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        A_prime: &G,
        A_bar: &G,
        g1: &G,
        t: &G,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        A_bar.serialize_compressed(&mut writer)?;
        A_prime.serialize_compressed(&mut writer)?;
        g1.serialize_compressed(&mut writer)?;
        t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> PoKOfSignatureG1KV<G> {
    pub fn verify(
        &self,
        challenge: &G::ScalarField,
        secret_key: impl AsRef<G::ScalarField>,
        g1: &G,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_bar != (self.A_prime * secret_key.as_ref()).into() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        self.verify_schnorr_proof(g1, challenge)
    }

    pub fn verify_schnorr_proof(
        &self,
        g1: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), ShortGroupSigError> {
        if !self.sc.verify(
            &self.A_bar,
            g1,
            &self.A_prime.into_group().neg().into(),
            challenge,
        ) {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g1: &G,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1KVProtocol::compute_challenge_contribution(
            &self.A_prime,
            &self.A_bar,
            g1,
            &self.sc.t,
            &mut writer,
        )
    }

    pub fn get_resp_for_message(&self) -> &G::ScalarField {
        &self.sc.response2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::SignatureParams,
        weak_bb_sig::{SecretKey, SignatureG1},
    };
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn proof_of_knowledge_of_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = SignatureParams::<Bls12_381>::new::<Blake2b512>(b"test-params");

        let sk = SecretKey::new(&mut rng);
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&message, &sk, &params);

        let protocol =
            PoKOfSignatureG1KVProtocol::<G1Affine>::init(&mut rng, sig, message, None, &params.g1);

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&params.g1, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&params.g1, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        proof.verify(&challenge_verifier, &sk, &params.g1).unwrap();
    }
}
