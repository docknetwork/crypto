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
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::{
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
    partial::Partial1PokPedersenCommitment,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
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
    pub sc: PokPedersenCommitmentProtocol<G>,
}

/// Proof of knowledge of weak-BB signature in the keyed-verification model
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKOfSignatureG1KV<G: AffineRepr> {
    /// The randomized signature
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_prime: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_bar: G,
    /// For proving relation `A_bar = g1 * r - A' * m`
    /// The following could be achieved by using Either<PokPedersenCommitment, Partial1PokPedersenCommitment> but serialization
    /// for Either is not supported out of the box and had to be implemented
    pub sc: Option<PokPedersenCommitment<G>>,
    pub sc_partial: Option<Partial1PokPedersenCommitment<G>>,
}

impl<G: AffineRepr> PoKOfSignatureG1KVProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: &G,
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
        signature: &G,
        message: G::ScalarField,
        g1: &G,
    ) -> Self {
        let sig_r = sig_randomizer.into_bigint();
        // A * r
        let A_prime = signature.mul_bigint(sig_r);
        let A_prime_neg = A_prime.neg();
        // A_bar = g1 * r - A' * m
        let A_bar = g1.mul_bigint(sig_r) + A_prime_neg * message;
        let sc = PokPedersenCommitmentProtocol::init(
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
            sc: Some(sc),
            sc_partial: None,
        }
    }

    pub fn gen_partial_proof(mut self, challenge: &G::ScalarField) -> PoKOfSignatureG1KV<G> {
        let sc = mem::take(&mut self.sc).gen_partial1_proof(challenge);
        PoKOfSignatureG1KV {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            sc: None,
            sc_partial: Some(sc),
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

    pub fn verify_partial(
        &self,
        resp_for_message: &G::ScalarField,
        challenge: &G::ScalarField,
        secret_key: impl AsRef<G::ScalarField>,
        g1: &G,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_bar != (self.A_prime * secret_key.as_ref()).into() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        self.verify_partial_schnorr_proof(resp_for_message, g1, challenge)
    }

    pub fn verify_schnorr_proof(
        &self,
        g1: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), ShortGroupSigError> {
        if !self
            .sc
            .as_ref()
            .ok_or_else(|| ShortGroupSigError::NeedEitherPartialOrCompleteSchnorrResponse)?
            .verify(
                &self.A_bar,
                g1,
                &self.A_prime.into_group().neg().into(),
                challenge,
            )
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn verify_partial_schnorr_proof(
        &self,
        resp_for_message: &G::ScalarField,
        g1: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), ShortGroupSigError> {
        if !self
            .sc_partial
            .as_ref()
            .ok_or_else(|| ShortGroupSigError::NeedEitherPartialOrCompleteSchnorrResponse)?
            .verify(
                &self.A_bar,
                g1,
                &self.A_prime.into_group().neg().into(),
                challenge,
                resp_for_message,
            )
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        g1: &G,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        let t = if let Some(sc) = &self.sc {
            &sc.t
        } else if let Some(sc) = &self.sc_partial {
            &sc.t
        } else {
            return Err(ShortGroupSigError::NeedEitherPartialOrCompleteSchnorrResponse);
        };
        PoKOfSignatureG1KVProtocol::compute_challenge_contribution(
            &self.A_prime,
            &self.A_bar,
            g1,
            t,
            &mut writer,
        )
    }

    pub fn get_resp_for_message(&self) -> Option<&G::ScalarField> {
        self.sc.as_ref().map(|s| &s.response2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weak_bb_sig::{gen_sig, SecretKey};
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn proof_of_knowledge_of_signature() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Affine::rand(&mut rng);

        let sk = SecretKey::new(&mut rng);
        let message = Fr::rand(&mut rng);
        let sig = gen_sig::<G1Affine>(&message, &sk, &g1);

        let protocol =
            PoKOfSignatureG1KVProtocol::<G1Affine>::init(&mut rng, &sig, message, None, &g1);

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&g1, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&g1, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        proof.verify(&challenge_verifier, &sk, &g1).unwrap();
    }
}
