//! Proof of knowledge of BB signature. This is not published in any paper but is an adaptation of similar protocol for proving
//! knowledge of weak-BB signature. The advantage of this variation is that the prover does not need to compute any pairings.
//! Following is a description
//! For BB signature, secret key = `(x, y)`, public key = `(w1=g2*x, w2=g2*y)`, message = `m` and signature = `(A = g*{1/{m + x + e*y}}, e)`
//! As part of setup params, generators `u`, `v` and `h` og group G1 exist.
//! 1. Pick random `r1` and `r2` from `Z_p`.
//! 2. Create `A' = A * r1, A_hat = A * r2, A_bar = g1 * r - A' * m, w2' = w2 * e * r1/r2`. Note that `A_bar = A*{{x + e*y}*r1} = A'*{x + e*y}`.
//! 3. Prover creates proof `pi_1` to prove knowledge of `m` and `r1` in `A_bar`, i.e. `pi_1 = SPK{(m, r1): A_bar = g1 * r - A' * m}`.
//! 4. Prover creates proof `pi_2` to prove knowledge of `e*r1/r2` in `w2'`, i.e. `pi_2 = SPK{(e*r1/r2): w2' = w2 * {e*r1/r2}}`.
//! 5. Prover sends `A', A_hat, A_bar, w2'`, proofs `pi_1, pi_2` to verifier.
//! 6. Verifier checks `pi_1, pi_2`, and `A'` and `w2'` are not zero, and the relation `e(A_bar, g2) = e(A', w1) * e(A_hat, w2')`

use crate::{
    bb_sig::{PreparedPublicKeyG2, PublicKeyG2, SignatureG1},
    error::ShortGroupSigError,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use core::mem;

use schnorr_pok::discrete_log::{
    PokDiscreteLog, PokDiscreteLogProtocol, PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoKOfSignatureG1Protocol<E: Pairing> {
    /// `A * r1`
    #[zeroize(skip)]
    pub A_prime: E::G1Affine,
    /// `A * r2`
    #[zeroize(skip)]
    pub A_hat: E::G1Affine,
    /// `g1 * r - A' * m`
    #[zeroize(skip)]
    pub A_bar: E::G1Affine,
    /// `w2 * e * r1/r2`
    #[zeroize(skip)]
    pub w2_prime: E::G2Affine,
    pub sc_1: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// Protocol for proving knowledge of `e * r1 / r2` in `w2' = w2 * {e * r1 / r2}`
    pub sc_2: PokDiscreteLogProtocol<E::G2Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKOfSignatureG1<E: Pairing> {
    /// `A * r1`
    pub A_prime: E::G1Affine,
    /// `A * r2`
    pub A_hat: E::G1Affine,
    /// `g1 * r - A' * m`
    pub A_bar: E::G1Affine,
    /// `w2 * e * r1/r2`
    pub w2_prime: E::G2Affine,
    pub sc_1: PokTwoDiscreteLogs<E::G1Affine>,
    pub sc_2: PokDiscreteLog<E::G2Affine>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: &SignatureG1<E>,
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
        pk: &PublicKeyG2<E>,
        g1: impl Into<E::G1Affine>,
    ) -> Self {
        let A = signature.0;
        let e = signature.1;
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let blinding = blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        let A_prime = A * r1;
        let A_hat = A * r2;
        let A_prime_neg = A_prime.neg();
        // wit = e * r1 / r2
        let wit = e * r1 * r2.inverse().unwrap();
        let w2_prime = (pk.1 * wit).into();
        let g1 = g1.into();
        // A_bar = g1 * r - A' * message
        let A_bar = g1 * r1 + A_prime_neg * message;
        let sc_comm_1 = PokTwoDiscreteLogsProtocol::init(
            r1,
            E::ScalarField::rand(rng),
            &g1,
            message,
            blinding,
            &A_prime_neg.into(),
        );
        let sc_comm_2 = PokDiscreteLogProtocol::init(wit, E::ScalarField::rand(rng), &pk.1);
        Self {
            A_prime: A_prime.into_affine(),
            A_hat: A_hat.into_affine(),
            A_bar: A_bar.into_affine(),
            w2_prime,
            sc_1: sc_comm_1,
            sc_2: sc_comm_2,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        pk: &PublicKeyG2<E>,
        g1: impl Into<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(
            &self.A_bar,
            &self.A_prime,
            &self.A_hat,
            &self.w2_prime,
            g1,
            pk.1,
            &self.sc_1.t,
            &self.sc_2.t,
            writer,
        )
    }

    pub fn gen_proof(
        mut self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignatureG1<E>, ShortGroupSigError> {
        let sc_resp_1 = mem::take(&mut self.sc_1).gen_proof(challenge);
        let sc_2 = mem::take(&mut self.sc_2).gen_proof(challenge);
        Ok(PoKOfSignatureG1 {
            A_prime: self.A_prime,
            A_hat: self.A_hat,
            A_bar: self.A_bar,
            w2_prime: self.w2_prime,
            sc_1: sc_resp_1,
            sc_2,
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        A_bar: &E::G1Affine,
        A_prime: &E::G1Affine,
        A_hat: &E::G1Affine,
        pk_prime: &E::G2Affine,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Affine>,
        t_1: &E::G1Affine,
        t_2: &E::G2Affine,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        A_bar.serialize_compressed(&mut writer)?;
        A_prime.serialize_compressed(&mut writer)?;
        A_hat.serialize_compressed(&mut writer)?;
        pk_prime.serialize_compressed(&mut writer)?;
        g1.into().serialize_compressed(&mut writer)?;
        g2.into().serialize_compressed(&mut writer)?;
        t_1.serialize_compressed(&mut writer)?;
        t_2.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> PoKOfSignatureG1<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
    ) -> Result<(), ShortGroupSigError> {
        if self.A_prime.is_zero() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if self.w2_prime.is_zero() {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !self.sc_1.verify(
            &self.A_bar,
            &g1.into(),
            &self.A_prime.into_group().neg().into(),
            challenge,
        ) {
            return Err(ShortGroupSigError::InvalidProof);
        }
        let pk = pk.into();
        if !self.sc_2.verify(&self.w2_prime, &pk.2, challenge) {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !E::multi_pairing(
            [
                E::G1Prepared::from(-(self.A_bar.into_group())),
                E::G1Prepared::from(self.A_prime),
                E::G1Prepared::from(self.A_hat),
            ],
            [g2.into(), pk.0, E::G2Prepared::from(self.w2_prime)],
        )
        .is_zero()
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        pk: &PublicKeyG2<E>,
        g1: impl Into<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1Protocol::<E>::compute_challenge_contribution(
            &self.A_bar,
            &self.A_prime,
            &self.A_hat,
            &self.w2_prime,
            g1,
            pk.1,
            &self.sc_1.t,
            &self.sc_2.t,
            writer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bb_sig::{PublicKeyG2, SecretKey, SignatureG1},
        common::SignatureParams,
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
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&mut rng, &message, &sk, &params);

        let protocol = PoKOfSignatureG1Protocol::<Bls12_381>::init(
            &mut rng, &sig, message, None, &pk, params.g1,
        );
        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&pk, params.g1, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover).unwrap();
        let mut bytes = vec![];
        proof.serialize_compressed(&mut bytes).unwrap();
        println!("{:?}", bytes);
        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&pk, params.g1, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        proof
            .verify(&challenge_verifier, pk, params.g1, params.g2)
            .unwrap();
    }
}
