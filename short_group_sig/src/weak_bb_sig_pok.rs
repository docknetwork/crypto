//! Proof of knowledge of weak-BB signature. Implements the protocol described in section 4 of the paper [Short Group Signatures](https://eprint.iacr.org/2004/174)

use crate::{
    common::{ProvingKey, SignatureParams},
    error::ShortGroupSigError,
    weak_bb_sig::{PublicKeyG2, SignatureG1},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use core::mem;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

use schnorr_pok::discrete_log::{
    PokDiscreteLog, PokDiscreteLogProtocol, PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of a weak-BB signature in group G1
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
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
    /// Commitment to randomness from the 1st step of the Schnorr protocol over the pairing equation. Called `R_3` in the paper
    #[zeroize(skip)]
    pub R_3: PairingOutput<E>,
}

/// Proof of knowledge of a weak-BB signature in group G1
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
    /// `R_3` from the paper
    pub R_3: PairingOutput<E>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: &SignatureG1<E>,
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
        pk: &PublicKeyG2<E>,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Self {
        let A = signature.0;
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);
        // - message * alpha
        let delta_1 = (message * alpha).neg();
        // - message * beta
        let delta_2 = (message * beta).neg();
        let T1 = (proving_key.X * alpha).into_affine();
        let T2 = (proving_key.Y * beta).into_affine();
        let T3 = A + proving_key.Z * (alpha + beta);
        // blinding for message
        let r_x = blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        let r_alpha = E::ScalarField::rand(rng);
        let r_beta = E::ScalarField::rand(rng);
        let r_delta_1 = E::ScalarField::rand(rng);
        let r_delta_2 = E::ScalarField::rand(rng);
        let sc_T1 = PokDiscreteLogProtocol::init(alpha, r_alpha, &proving_key.X);
        let sc_T2 = PokDiscreteLogProtocol::init(beta, r_beta, &proving_key.Y);
        let sc_T1_x =
            PokTwoDiscreteLogsProtocol::init(message, r_x, &T1, delta_1, r_delta_1, &proving_key.X);
        let sc_T2_x =
            PokTwoDiscreteLogsProtocol::init(message, r_x, &T2, delta_2, r_delta_2, &proving_key.Y);
        let g2_prepared = E::G2Prepared::from(params.g2);
        // R_3 = e(T_3, g2) * r_x + e(Z, pk) * -(r_alpha + r_beta) + e(Z, g2) * (r_delta_1 + r_delta_2)
        let R_3 = E::multi_pairing(
            [
                E::G1Prepared::from(T3 * r_x),
                E::G1Prepared::from(proving_key.Z * (r_alpha.neg() + r_beta.neg())),
                E::G1Prepared::from(proving_key.Z * (r_delta_1 + r_delta_2)),
            ],
            [g2_prepared.clone(), E::G2Prepared::from(pk.0), g2_prepared],
        );
        Self {
            T1,
            T2,
            T3: T3.into(),
            sc_T1,
            sc_T2,
            sc_T1_x,
            sc_T2_x,
            R_3,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        Self::compute_challenge_contribution(
            &self.T1,
            &self.T2,
            &self.T3,
            &proving_key,
            &params.g2,
            &self.sc_T1.t,
            &self.sc_T2.t,
            &self.sc_T1_x.t,
            &self.sc_T2_x.t,
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
        Ok(PoKOfSignatureG1 {
            T1: self.T1,
            T2: self.T2,
            T3: self.T3,
            sc_T1,
            sc_T2,
            sc_T1_x,
            sc_T2_x,
            R_3: self.R_3,
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        T1: &E::G1Affine,
        T2: &E::G1Affine,
        T3: &E::G1Affine,
        proving_key: &ProvingKey<E::G1Affine>,
        g2: &E::G2Affine,
        t_T1: &E::G1Affine,
        t_T2: &E::G1Affine,
        t_T1_x: &E::G1Affine,
        t_T2_x: &E::G1Affine,
        R3: &PairingOutput<E>,
        mut writer: W,
    ) -> Result<(), ShortGroupSigError> {
        T1.serialize_compressed(&mut writer)?;
        T2.serialize_compressed(&mut writer)?;
        T3.serialize_compressed(&mut writer)?;
        proving_key.X.serialize_compressed(&mut writer)?;
        proving_key.Y.serialize_compressed(&mut writer)?;
        proving_key.Z.serialize_compressed(&mut writer)?;
        g2.serialize_compressed(&mut writer)?;
        t_T1.serialize_compressed(&mut writer)?;
        t_T2.serialize_compressed(&mut writer)?;
        t_T1_x.serialize_compressed(&mut writer)?;
        t_T2_x.serialize_compressed(&mut writer)?;
        R3.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> PoKOfSignatureG1<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        pk: impl Into<E::G2Prepared>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
        proving_key: &ProvingKey<E::G1Affine>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_except_pairings(challenge, proving_key)?;
        let s_message = self.sc_T1_x.response1;
        let g2_prepared = g2.into();
        let pk_prepared = pk.into();
        // Following is the pairing check equation from the paper converted to a single multi-pairing
        if self.R_3
            != E::multi_pairing(
                [
                    E::G1Prepared::from(self.T3 * s_message),
                    E::G1Prepared::from(
                        proving_key.Z * (self.sc_T1.response.neg() + self.sc_T2.response.neg()),
                    ),
                    E::G1Prepared::from(
                        proving_key.Z * (self.sc_T1_x.response2 + self.sc_T2_x.response2),
                    ),
                    E::G1Prepared::from(self.T3 * challenge),
                    E::G1Prepared::from(g1.into() * challenge.neg()),
                ],
                [
                    g2_prepared.clone(),
                    pk_prepared.clone(),
                    g2_prepared.clone(),
                    pk_prepared,
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
        pk: impl Into<E::G2Prepared>,
        g1: impl Into<E::G1Affine>,
        g2: impl Into<E::G2Prepared>,
        proving_key: &ProvingKey<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), ShortGroupSigError> {
        self.verify_except_pairings(challenge, proving_key)?;
        let s_message = self.sc_T1_x.response1;
        let g2_prepared = g2.into();
        let pk_prepared = pk.into();
        pairing_checker.add_multiple_sources_and_target(
            &[
                (self.T3 * s_message).into(),
                (proving_key.Z * (self.sc_T1.response.neg() + self.sc_T2.response.neg())).into(),
                (proving_key.Z * (self.sc_T1_x.response2 + self.sc_T2_x.response2)).into(),
                (self.T3 * challenge).into(),
                (g1.into() * challenge.neg()).into(),
            ],
            [
                g2_prepared.clone(),
                pk_prepared.clone(),
                g2_prepared.clone(),
                pk_prepared,
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
        let zero = E::G1Affine::zero();
        if !self
            .sc_T1_x
            .verify(&zero, &self.T1, &proving_key.X, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        };
        if !self
            .sc_T2_x
            .verify(&zero, &self.T2, &proving_key.Y, challenge)
        {
            return Err(ShortGroupSigError::InvalidProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        params: &SignatureParams<E>,
        proving_key: &ProvingKey<E::G1Affine>,
        writer: W,
    ) -> Result<(), ShortGroupSigError> {
        PoKOfSignatureG1Protocol::<E>::compute_challenge_contribution(
            &self.T1,
            &self.T2,
            &self.T3,
            &proving_key,
            &params.g2,
            &self.sc_T1.t,
            &self.sc_T2.t,
            &self.sc_T1_x.t,
            &self.sc_T2_x.t,
            &self.R_3,
            writer,
        )
    }

    pub fn get_resp_for_message(&self) -> &E::ScalarField {
        &self.sc_T1_x.response1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::SignatureParamsWithPairing,
        weak_bb_sig::{PreparedPublicKeyG2, SecretKey},
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
        let params_with_pairing = SignatureParamsWithPairing::<Bls12_381>::from(params.clone());
        let prk = ProvingKey::<G1Affine>::generate_using_hash::<Blake2b512>(b"test-proving-key");

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &params);
        let prepared_pk = PreparedPublicKeyG2::from(pk.clone());
        let message = Fr::rand(&mut rng);
        let sig = SignatureG1::new(&message, &sk, &params);

        let protocol =
            PoKOfSignatureG1Protocol::init(&mut rng, &sig, message, None, &pk, &params, &prk);
        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&params, &prk, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
        let proof = protocol.gen_proof(&challenge_prover).unwrap();

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&params, &prk, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        proof
            .verify(&challenge_verifier, pk.0, params.g1, params.g2, &prk)
            .unwrap();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        proof
            .verify_with_randomized_pairing_checker(
                &challenge_verifier,
                prepared_pk.0,
                params.g1,
                params_with_pairing.g2_prepared,
                &prk,
                &mut pairing_checker,
            )
            .unwrap();
        assert!(pairing_checker.verify());
    }
}
