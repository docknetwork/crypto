use crate::{
    bbs_sharp::setup::{MACParams, PublicKey, SecretKey},
    error::KVACError,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    expect_equality, serde_utils::ArkObjectBytes, signature::MultiMessageSignatureParams,
};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
pub struct MAC<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub e: G::ScalarField,
}

/// A proof corresponding to a MAC that it is correctly created, i.e. can be verified successfully by someone possessing
/// the secret key. Verifying the proof does not require the secret key.
/// Consists of 2 protocols for discrete log relations, and both have the same discrete log
///
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfMAC<G: AffineRepr> {
    /// For proving `B = A * sk` where `sk` is the secret key and `B = g_0 + signer_pk + g_1 * m_1 + g_2 * m_2 + ... g_n * m_n`
    pub sc_B: PokDiscreteLog<G>,
    /// For proving knowledge of secret key, i.e. `pk = g * sk`
    pub sc_pk: PokDiscreteLog<G>,
}

impl<G: AffineRepr> MAC<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: &[G::ScalarField],
        user_public_key: &PublicKey<G>,
        signer_secret_key: &SecretKey<G::ScalarField>,
        params: impl AsRef<MACParams<G>>,
    ) -> Result<Self, KVACError> {
        if messages.is_empty() {
            return Err(KVACError::NoMessageGiven);
        }
        let params = params.as_ref();
        expect_equality!(
            messages.len(),
            params.supported_message_count(),
            KVACError::MessageCountIncompatibleWithMACParams
        );
        let mut e = G::ScalarField::rand(rng);
        while (e + signer_secret_key.0).is_zero() {
            e = G::ScalarField::rand(rng)
        }
        // 1/(e+x)
        let e_plus_x_inv = (e + signer_secret_key.0).inverse().unwrap();
        let A = params.b(messages.iter().enumerate(), user_public_key)? * e_plus_x_inv;
        Ok(Self {
            A: A.into_affine(),
            e,
        })
    }

    pub fn verify(
        &self,
        messages: &[G::ScalarField],
        user_public_key: &PublicKey<G>,
        sk: impl AsRef<G::ScalarField>,
        params: impl AsRef<MACParams<G>>,
    ) -> Result<(), KVACError> {
        if messages.is_empty() {
            return Err(KVACError::NoMessageGiven);
        }
        let params = params.as_ref();
        expect_equality!(
            messages.len(),
            params.supported_message_count(),
            KVACError::MessageCountIncompatibleWithMACParams
        );
        let b = params.b(messages.iter().enumerate(), user_public_key)?;
        let e_plus_x_inv = (self.e + sk.as_ref())
            .inverse()
            .ok_or(KVACError::CannotInvert0)?;
        if (b * e_plus_x_inv).into_affine() != self.A {
            return Err(KVACError::InvalidMAC);
        }
        Ok(())
    }
}

impl<G: AffineRepr> ProofOfValidityOfMAC<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        mac: &MAC<G>,
        secret_key: &SecretKey<G::ScalarField>,
        public_key: &PublicKey<G>,
        params: impl AsRef<MACParams<G>>,
    ) -> Self {
        let witness = secret_key.0;
        let blinding = G::ScalarField::rand(rng);
        let B = (mac.A * witness).into_affine();
        let params = params.as_ref();
        let mut challenge_bytes = vec![];
        // As witness has to be proven same in both protocols.
        let p1 = PokDiscreteLogProtocol::init(witness, blinding, &mac.A);
        let p2 = PokDiscreteLogProtocol::init(witness, blinding, &params.g);
        p1.challenge_contribution(&mac.A, &B, &mut challenge_bytes)
            .unwrap();
        p2.challenge_contribution(&params.g, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        Self {
            sc_B: p1.gen_proof(&challenge),
            sc_pk: p2.gen_proof(&challenge),
        }
    }

    pub fn verify<D: Digest>(
        &self,
        mac: &MAC<G>,
        messages: &[G::ScalarField],
        user_public_key: &PublicKey<G>,
        signer_public_key: &PublicKey<G>,
        params: impl AsRef<MACParams<G>>,
    ) -> Result<(), KVACError> {
        if self.sc_B.response != self.sc_pk.response {
            return Err(KVACError::InvalidMACProof);
        }
        let params = params.as_ref();
        // B = g_0 + user_pk + g_1 * m_1 + g_2 * m_2 + ... g_n * m_n - A * e
        let B = (params.b(messages.iter().enumerate(), user_public_key)? + mac.A * mac.e.neg())
            .into_affine();

        let mut challenge_bytes = vec![];
        self.sc_B
            .challenge_contribution(&mac.A, &B, &mut challenge_bytes)
            .unwrap();
        self.sc_pk
            .challenge_contribution(&params.g, &signer_public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self.sc_B.verify(&B, &mac.A, &challenge) {
            return Err(KVACError::InvalidMACProof);
        }
        if !self
            .sc_pk
            .verify(&signer_public_key.0, &params.g, &challenge)
        {
            return Err(KVACError::InvalidMACProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256r1::{Affine, Fr};
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use sha2::Sha256;

    #[test]
    fn mac_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
        let signer_sk = SecretKey::new(&mut rng);
        let signer_pk = PublicKey::new(&signer_sk, &params.g);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = PublicKey::new(&user_sk, &params.g);

        // Signer sends the following 2 items to the user
        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof =
            ProofOfValidityOfMAC::new::<_, Sha256>(&mut rng, &mac, &signer_sk, &signer_pk, &params);

        // User verifies both
        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params)
            .unwrap();
    }
}
