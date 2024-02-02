//! Proof of knowledge of BB signature. Adapted from the construction in section 4.2 of the paper [Proof-of-Knowledge of Representation of Committed Value and Its Applications](https://link.springer.com/chapter/10.1007/978-3-642-14081-5_22)
//! Specifically the adaptation is of `SPK_1` of construction `pi_m` in section 4.2 as following:
//! For BB signature, secret key = `(x, y)`, public key = `(w1=g2*x, w2=g2*y)`, message = `m` and signature = `(A = g*{1/{m + x + e*y}}, e)`
//! As part of setup params, generators `u`, `v` and `h` og group G1 exist.
//! 1. Pick random `alpha` and `beta` from `Z_p`.
//! 2. Create `delta_1 = -m * alpha, delta_2 = -m * beta, delta_3 = -e * alpha, delta_4 = -e * beta, T1 = u * alpha, T2 = v * alpha, T3 = A * alpha + h * (alpha + beta)`.
//! 3. Now the prover proves the following 5 relations
//!    a. `T1*m + u*delta_1 = 0`
//!    b. `T2*m + v*delta_2 = 0`
//!    c. `T1*e + u*delta_3 = 0`
//!    d. `T2*e + v*delta_4 = 0`
//!    e. `e(T3, g2)*m + e(T3, w2)*e + e(h, w1)*{alpha + beta} + e(h, g2)*{delta_1 + delta_2} + e(h, w2)*{delta_3 + delta_4} = e(g1, g2) - e(T3, w1)`

use crate::{
    bb_sig::{PreparedPublicKeyG2, PublicKeyG2, SignatureG1},
    common::{ProvingKey, SignatureParams},
    error::ShortGroupSigError,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use core::mem;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{msm::WindowTable, randomized_pairing_check::RandomizedPairingChecker};

use schnorr_pok::discrete_log::{
    PokDiscreteLog, PokDiscreteLogProtocol, PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of a BB signature in group G1
#[derive(Default, Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PoKOfSignatureG1Protocol<E: Pairing> {
    /// `u * alpha`
    #[zeroize(skip)]
    pub T1: E::G1Affine,
    /// `v * beta`
    #[zeroize(skip)]
    pub T2: E::G1Affine,
    /// `A + h * (alpha + beta)`
    #[zeroize(skip)]
    pub T3: E::G1Affine,
    /// Protocol for proving knowledge of `alpha` in `T1 = u * alpha`
    pub sc_T1: PokDiscreteLogProtocol<E::G1Affine>,
    /// Protocol for proving knowledge of `beta` in `T2 = v * beta`
    pub sc_T2: PokDiscreteLogProtocol<E::G1Affine>,
    /// For proving knowledge of `message` and `delta_1` in `T1 * message + u * delta_1 = 0`
    pub sc_T1_x: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// For proving knowledge of `message` and `delta_2` in `T2 * message + v * delta_2 = 0`
    pub sc_T2_x: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// For proving knowledge of `e` and `delta_3` in `T1 * e + u * delta_3 = 0`
    pub sc_T1_e: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// For proving knowledge of `e` and `delta_4` in `T2 * e + v * delta_4 = 0`
    pub sc_T2_e: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// Commitment to randomness from the 1st step of the Schnorr protocol over the pairing equation.
    #[zeroize(skip)]
    pub R_3: PairingOutput<E>,
    /// - message * alpha
    pub delta_1: E::ScalarField,
    /// - message * beta
    pub delta_2: E::ScalarField,
    /// - e * alpha
    pub delta_3: E::ScalarField,
    /// - e * beta
    pub delta_4: E::ScalarField,
}

/// Proof of knowledge of a BB signature in group G1
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKOfSignatureG1<E: Pairing> {
    /// `u * alpha`
    pub T1: E::G1Affine,
    /// `v * beta`
    pub T2: E::G1Affine,
    /// `A + h * (alpha + beta)`
    pub T3: E::G1Affine,
    /// Proof of knowledge of `alpha` in `T1 = u * alpha`
    pub sc_T1: PokDiscreteLog<E::G1Affine>,
    /// Proof of knowledge of `beta` in `T2 = v * beta`
    pub sc_T2: PokDiscreteLog<E::G1Affine>,
    /// For relation `T1 * message + u * delta_1 = 0`
    pub sc_T1_x: PokTwoDiscreteLogs<E::G1Affine>,
    /// For relation `T2 * message + v * delta_2 = 0`
    pub sc_T2_x: PokTwoDiscreteLogs<E::G1Affine>,
    /// For relation `T1 * e + u * delta_3 = 0`
    pub sc_T1_e: PokTwoDiscreteLogs<E::G1Affine>,
    /// For relation `T2 * e + v * delta_4 = 0`
    pub sc_T2_e: PokTwoDiscreteLogs<E::G1Affine>,
    /// Commitment to randomness from the 1st step of the Schnorr protocol over the pairing equation.
    pub R_3: PairingOutput<E>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: &SignatureG1<E>,
        message: E::ScalarField,
        message_blinding: Option<E::ScalarField>,
        randomness_blinding: Option<E::ScalarField>,
        pk: &PublicKeyG2<E>,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Self {
        let A = signature.0;
        let e = signature.1;
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        // - message * alpha
        let delta_1 = (message * alpha).neg();
        // - message * beta
        let delta_2 = (message * beta).neg();
        // - e * alpha
        let delta_3 = (e * alpha).neg();
        // - e * beta
        let delta_4 = (e * beta).neg();

        let T1 = (proving_key.X * alpha).into_affine();
        let T2 = (proving_key.Y * beta).into_affine();
        let Z_table = WindowTable::new(4, proving_key.Z.into_group());

        let T3 = A + Z_table.multiply(&(alpha + beta));
        // blinding for message
        let r_x = message_blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        // blinding for e
        let r_e = randomness_blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        let r_alpha = E::ScalarField::rand(rng);
        let r_beta = E::ScalarField::rand(rng);
        let r_delta_1 = E::ScalarField::rand(rng);
        let r_delta_2 = E::ScalarField::rand(rng);
        let r_delta_3 = E::ScalarField::rand(rng);
        let r_delta_4 = E::ScalarField::rand(rng);
        let sc_T1 = PokDiscreteLogProtocol::init(alpha, r_alpha, &proving_key.X);
        let sc_T2 = PokDiscreteLogProtocol::init(beta, r_beta, &proving_key.Y);
        let sc_T1_x =
            PokTwoDiscreteLogsProtocol::init(message, r_x, &T1, delta_1, r_delta_1, &proving_key.X);
        let sc_T2_x =
            PokTwoDiscreteLogsProtocol::init(message, r_x, &T2, delta_2, r_delta_2, &proving_key.Y);
        let sc_T1_e =
            PokTwoDiscreteLogsProtocol::init(e, r_e, &T1, delta_3, r_delta_3, &proving_key.X);
        let sc_T2_e =
            PokTwoDiscreteLogsProtocol::init(e, r_e, &T2, delta_4, r_delta_4, &proving_key.Y);
        let g2_prepared = E::G2Prepared::from(params.g2);
        let pk_0_prepared = E::G2Prepared::from(pk.0);
        let pk_1_prepared = E::G2Prepared::from(pk.1);
        // R_3 = e(T_3, g2) * r_x + e(T_3, w2) * r_e + e(Z, w1) * -(r_alpha + r_beta) + e(Z, g2) * (r_delta_1 + r_delta_2) + e(Z, w2) * (r_delta_3 + r_delta_4)
        let R_3 = E::multi_pairing(
            [
                E::G1Prepared::from(T3 * r_x),
                E::G1Prepared::from(T3 * r_e),
                E::G1Prepared::from(Z_table.multiply(&(r_alpha.neg() + r_beta.neg()))),
                E::G1Prepared::from(Z_table.multiply(&(r_delta_1 + r_delta_2))),
                E::G1Prepared::from(Z_table.multiply(&(r_delta_3 + r_delta_4))),
            ],
            [
                g2_prepared.clone(),
                pk_1_prepared.clone(),
                pk_0_prepared,
                g2_prepared,
                pk_1_prepared,
            ],
        );
        Self {
            T1,
            T2,
            T3: T3.into(),
            sc_T1,
            sc_T2,
            sc_T1_x,
            sc_T2_x,
            sc_T1_e,
            sc_T2_e,
            R_3,
            delta_1,
            delta_2,
            delta_3,
            delta_4,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        pk: &PublicKeyG2<E>,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(
            &self.T1,
            &self.T2,
            &self.T3,
            &proving_key,
            pk,
            &params.g2,
            &self.sc_T1.t,
            &self.sc_T2.t,
            &self.sc_T1_x.t,
            &self.sc_T2_x.t,
            &self.sc_T1_e.t,
            &self.sc_T2_e.t,
            &self.R_3,
            writer,
        )
    }

    pub fn gen_proof(
        mut self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignatureG1<E>, ShortGroupSigError> {
        let sc_T1 = mem::take(&mut self.sc_T1).gen_proof(challenge);
        let sc_T2 = mem::take(&mut self.sc_T2).gen_proof(challenge);
        let sc_T1_x = mem::take(&mut self.sc_T1_x).gen_proof(challenge);
        let sc_T2_x = mem::take(&mut self.sc_T2_x).gen_proof(challenge);
        let sc_T1_e = mem::take(&mut self.sc_T1_e).gen_proof(challenge);
        let sc_T2_e = mem::take(&mut self.sc_T2_e).gen_proof(challenge);
        Ok(PoKOfSignatureG1 {
            T1: self.T1,
            T2: self.T2,
            T3: self.T3,
            sc_T1,
            sc_T2,
            sc_T1_x,
            sc_T2_x,
            sc_T1_e,
            sc_T2_e,
            R_3: self.R_3,
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        T1: &E::G1Affine,
        T2: &E::G1Affine,
        T3: &E::G1Affine,
        proving_key: &ProvingKey<E::G1Affine>,
        pk: &PublicKeyG2<E>,
        g2: &E::G2Affine,
        t_T1: &E::G1Affine,
        t_T2: &E::G1Affine,
        t_T1_x: &E::G1Affine,
        t_T2_x: &E::G1Affine,
        t_T1_e: &E::G1Affine,
        t_T2_e: &E::G1Affine,
        R3: &PairingOutput<E>,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        T1.serialize_compressed(&mut writer)?;
        T2.serialize_compressed(&mut writer)?;
        T3.serialize_compressed(&mut writer)?;
        proving_key.X.serialize_compressed(&mut writer)?;
        proving_key.Y.serialize_compressed(&mut writer)?;
        proving_key.Z.serialize_compressed(&mut writer)?;
        pk.0.serialize_compressed(&mut writer)?;
        pk.1.serialize_compressed(&mut writer)?;
        g2.serialize_compressed(&mut writer)?;
        t_T1.serialize_compressed(&mut writer)?;
        t_T2.serialize_compressed(&mut writer)?;
        t_T1_x.serialize_compressed(&mut writer)?;
        t_T2_x.serialize_compressed(&mut writer)?;
        t_T1_e.serialize_compressed(&mut writer)?;
        t_T2_e.serialize_compressed(&mut writer)?;
        R3.serialize_compressed(&mut writer)?;
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
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_except_pairings(challenge, proving_key)?;
        let s_message = self.sc_T1_x.response1;
        let e_message = self.sc_T1_e.response1;
        let g2_prepared = g2.into();
        let PreparedPublicKeyG2(pk_0_prepared, pk_1_prepared, _) = pk.into();
        let Z_table = WindowTable::new(3, proving_key.Z.into_group());
        if self.R_3
            != E::multi_pairing(
                [
                    E::G1Prepared::from(self.T3 * s_message),
                    E::G1Prepared::from(self.T3 * e_message),
                    E::G1Prepared::from(
                        Z_table.multiply(&(self.sc_T1.response.neg() + self.sc_T2.response.neg())),
                    ),
                    E::G1Prepared::from(
                        Z_table.multiply(&(self.sc_T1_x.response2 + self.sc_T2_x.response2)),
                    ),
                    E::G1Prepared::from(
                        Z_table.multiply(&(self.sc_T1_e.response2 + self.sc_T2_e.response2)),
                    ),
                    E::G1Prepared::from(self.T3 * challenge),
                    E::G1Prepared::from(g1.into() * challenge.neg()),
                ],
                [
                    g2_prepared.clone(),
                    pk_1_prepared.clone(),
                    pk_0_prepared.clone(),
                    g2_prepared.clone(),
                    pk_1_prepared,
                    pk_0_prepared,
                    g2_prepared,
                ],
            )
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
        proving_key: &ProvingKey<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), ShortGroupSigError> {
        let s_message = self.sc_T1_x.response1;
        let e_message = self.sc_T1_e.response1;
        let g2_prepared = g2.into();
        let PreparedPublicKeyG2(pk_0_prepared, pk_1_prepared, _) = pk.into();
        let Z_table = WindowTable::new(3, proving_key.Z.into_group());
        pairing_checker.add_multiple_sources_and_target(
            &[
                (self.T3 * s_message).into(),
                (self.T3 * e_message).into(),
                Z_table
                    .multiply(&(self.sc_T1.response.neg() + self.sc_T2.response.neg()))
                    .into(),
                Z_table
                    .multiply(&(self.sc_T1_x.response2 + self.sc_T2_x.response2))
                    .into(),
                (Z_table.multiply(&(self.sc_T1_e.response2 + self.sc_T2_e.response2))).into(),
                (self.T3 * challenge).into(),
                (g1.into() * challenge.neg()).into(),
            ],
            [
                g2_prepared.clone(),
                pk_1_prepared.clone(),
                pk_0_prepared.clone(),
                g2_prepared.clone(),
                pk_1_prepared,
                pk_0_prepared,
                g2_prepared,
            ],
            &self.R_3,
        );
        Ok(())
    }

    pub fn verify_except_pairings(
        &self,
        challenge: &E::ScalarField,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Result<(), ShortGroupSigError> {
        if !self.sc_T1.verify(&self.T1, &proving_key.X, challenge) {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !self.sc_T2.verify(&self.T2, &proving_key.Y, challenge) {
            return Err(ShortGroupSigError::InvalidProof);
        }

        // Check that `message` is same in `T1 * message + u * delta_1 = 0` and `T2 * message + v * delta_2 = 0`
        let s_message = self.sc_T1_x.response1;
        if s_message != self.sc_T2_x.response1 {
            return Err(ShortGroupSigError::InvalidProof);
        }

        // Check that `e` is same in `T1 * e + u * delta_3 = 0` and `T2 * e + v * delta_4 = 0`
        let e_message = self.sc_T1_e.response1;
        if e_message != self.sc_T2_e.response1 {
            return Err(ShortGroupSigError::InvalidProof);
        }

        let zero = E::G1Affine::zero();
        if !self
            .sc_T1_x
            .verify(&zero, &self.T1, &proving_key.X, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !self
            .sc_T2_x
            .verify(&zero, &self.T2, &proving_key.Y, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !self
            .sc_T1_e
            .verify(&zero, &self.T1, &proving_key.X, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        if !self
            .sc_T2_e
            .verify(&zero, &self.T2, &proving_key.Y, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        pk: &PublicKeyG2<E>,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1Protocol::<E>::compute_challenge_contribution(
            &self.T1,
            &self.T2,
            &self.T3,
            &proving_key,
            pk,
            &params.g2,
            &self.sc_T1.t,
            &self.sc_T2.t,
            &self.sc_T1_x.t,
            &self.sc_T2_x.t,
            &self.sc_T1_e.t,
            &self.sc_T2_e.t,
            &self.R_3,
            writer,
        )
    }

    pub fn get_resp_for_message(&self) -> &E::ScalarField {
        &self.sc_T1_x.response1
    }

    pub fn get_resp_for_randomness(&self) -> &E::ScalarField {
        &self.sc_T1_e.response1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bb_sig::SecretKey, common::SignatureParamsWithPairing};
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
        let params_with_pairing = SignatureParamsWithPairing::<Bls12_381>::from(params.clone());
        let prk = ProvingKey::<G1Affine>::generate_using_hash::<Blake2b512>(b"test-proving-key");

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);
        let prepared_pk = PreparedPublicKeyG2::from(pk.clone());
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&mut rng, &message, &sk, &params);
        sig.verify(&message, &pk, &params).unwrap();

        let protocol =
            PoKOfSignatureG1Protocol::init(&mut rng, &sig, message, None, None, &pk, &params, &prk);
        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&pk, &params, &prk, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
        let proof = protocol.gen_proof(&challenge_prover).unwrap();

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&pk, &params, &prk, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        proof
            .verify(
                &challenge_verifier,
                prepared_pk.clone(),
                params.g1,
                params_with_pairing.g2_prepared.clone(),
                &prk,
            )
            .unwrap();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        proof
            .verify_with_randomized_pairing_checker(
                &challenge_verifier,
                prepared_pk.clone(),
                params.g1,
                params_with_pairing.g2_prepared.clone(),
                &prk,
                &mut pairing_checker,
            )
            .unwrap();

        let msg_blinding = Fr::rand(&mut rng);
        let rand_blinding = Fr::rand(&mut rng);
        let same_challenge = Fr::rand(&mut rng);

        let protocol1 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            message,
            Some(msg_blinding),
            Some(rand_blinding),
            &pk,
            &params,
            &prk,
        );
        let proof1 = protocol1.gen_proof(&same_challenge).unwrap();
        proof1
            .verify(
                &same_challenge,
                prepared_pk.clone(),
                params.g1,
                params_with_pairing.g2_prepared.clone(),
                &prk,
            )
            .unwrap();

        let protocol2 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            message,
            Some(msg_blinding),
            Some(rand_blinding),
            &pk,
            &params,
            &prk,
        );
        let proof2 = protocol2.gen_proof(&same_challenge).unwrap();
        proof2
            .verify(
                &same_challenge,
                prepared_pk.clone(),
                params.g1,
                params_with_pairing.g2_prepared.clone(),
                &prk,
            )
            .unwrap();

        assert_eq!(proof1.get_resp_for_message(), proof2.get_resp_for_message());
        assert_eq!(
            proof1.get_resp_for_randomness(),
            proof2.get_resp_for_randomness()
        );
    }
}
