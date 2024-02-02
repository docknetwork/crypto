//! Proof of knowledge of weak-BB signature as described in the paper [Scalable Revocation Scheme for Anonymous Credentials Based on n-times Unlinkable Proofs](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf)
//! The advantage of this variation is that the prover does not need to compute any pairings
// TODO: Add proof of correctness (should i really call proof of correctness as this makes the proof/simulation happen), i.e. a tuple (G, G*x) and proof that x is the secret key

use crate::error::ShortGroupSigError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use core::mem;
use dock_crypto_utils::{
    randomized_pairing_check::RandomizedPairingChecker, serde_utils::ArkObjectBytes,
};
use schnorr_pok::discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default, Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoKOfSignatureG1Protocol<E: Pairing> {
    /// Randomized signature. Called `sigma'` in the paper
    #[zeroize(skip)]
    pub A_prime: E::G1Affine,
    /// Called `sigma_bar` in the paper
    #[zeroize(skip)]
    pub A_bar: E::G1Affine,
    /// For proving relation `sigma_bar = g1 * r - sigma' * m`
    pub sc: PokTwoDiscreteLogsProtocol<E::G1Affine>,
}

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
pub struct PoKOfSignatureG1<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A_prime: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    pub sc: PokTwoDiscreteLogs<E::G1Affine>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: impl AsRef<E::G1Affine>,
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
        g1: &E::G1Affine,
    ) -> Self {
        let sig_randomizer = E::ScalarField::rand(rng);
        let sc_blinding = E::ScalarField::rand(rng);
        let msg_blinding = blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
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
        sig_randomizer: E::ScalarField,
        msg_blinding: E::ScalarField,
        sc_blinding: E::ScalarField,
        signature: impl AsRef<E::G1Affine>,
        message: E::ScalarField,
        g1: &E::G1Affine,
    ) -> Self {
        let sig_r = sig_randomizer.into_bigint();
        // A * r
        let A_prime = signature.as_ref().mul_bigint(sig_r);
        let A_prime_neg = A_prime.neg();
        // A_bar = g1 * r - A_prime * m
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
        g1: &E::G1Affine,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(&self.A_bar, &self.A_prime, g1, &self.sc.t, writer)
    }

    pub fn gen_proof(mut self, challenge: &E::ScalarField) -> PoKOfSignatureG1<E> {
        let sc = mem::take(&mut self.sc).gen_proof(challenge);
        PoKOfSignatureG1 {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            sc,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        A_prime: &E::G1Affine,
        A_bar: &E::G1Affine,
        g1: &E::G1Affine,
        t: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        A_bar.serialize_compressed(&mut writer)?;
        A_prime.serialize_compressed(&mut writer)?;
        g1.serialize_compressed(&mut writer)?;
        t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> PoKOfSignatureG1<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<E::G2Prepared>,
        g1: &E::G1Affine,
        g2: impl Into<E::G2Prepared>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_except_pairings(challenge, g1)?;
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.A_bar),
                E::G1Prepared::from(-(self.A_prime.into_group())),
            ],
            [g2.into(), pk.into()],
        )
        .is_zero()
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<E::G2Prepared>,
        g1: &E::G1Affine,
        g2: impl Into<E::G2Prepared>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_except_pairings(challenge, g1)?;
        pairing_checker.add_sources(&self.A_prime, pk.into(), &self.A_bar, g2);
        Ok(())
    }

    pub fn verify_except_pairings(
        &self,
        challenge: &E::ScalarField,
        g1: &E::G1Affine,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_prime.is_zero() {
            return Err(ShortGroupSigError::InvalidProof);
        }
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
        g1: &E::G1Affine,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1Protocol::<E>::compute_challenge_contribution(
            &self.A_bar,
            &self.A_prime,
            g1,
            &self.sc.t,
            writer,
        )
    }

    pub fn get_resp_for_message(&self) -> &E::ScalarField {
        &self.sc.response2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::SignatureParams,
        weak_bb_sig::{PreparedPublicKeyG2, PublicKeyG2, SecretKey, SignatureG1},
    };
    use ark_bls12_381::{Bls12_381, Fr};
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
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);
        let prepared_pk = PreparedPublicKeyG2::from(pk.clone());
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&message, &sk, &params);

        let protocol =
            PoKOfSignatureG1Protocol::<Bls12_381>::init(&mut rng, sig, message, None, &params.g1);

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
        proof
            .verify(
                &challenge_verifier,
                prepared_pk.0.clone(),
                &params.g1,
                params.g2,
            )
            .unwrap();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        proof
            .verify_with_randomized_pairing_checker(
                &challenge_verifier,
                prepared_pk.0,
                &params.g1,
                params.g2,
                &mut pairing_checker,
            )
            .unwrap();
        assert!(pairing_checker.verify());
    }
}
