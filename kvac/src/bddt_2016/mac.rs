//! MAC_BB - A MAC based on Boneh-Boyen Signatures. Follows section 3.2 of the paper

use crate::{
    bddt_2016::setup::{MACParams, PublicKey, SecretKey},
    error::KVACError,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
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

/// MAC of list of messages
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
    /// Called `r` in the paper
    #[serde_as(as = "ArkObjectBytes")]
    pub e: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub s: G::ScalarField,
}

/// A proof corresponding to a MAC that it is correctly created, i.e. can be verified successfully by someone possessing
/// the secret key. Verifying the proof does not require the secret key.
/// Consists of 2 protocols for discrete log relations, and both have the same discrete log
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfMAC<G: AffineRepr> {
    /// For proving `B = A * sk` where `sk` is the secret key and `B = h + g * s + g_1 * m_1 + g_2 * m_2 + ... g_n * m_n`
    pub sc_B: PokDiscreteLog<G>,
    /// For proving knowledge of secret key, i.e. `pk = g_0 * sk`
    pub sc_pk: PokDiscreteLog<G>,
}

impl<G: AffineRepr> MAC<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: &[G::ScalarField],
        secret_key: &SecretKey<G::ScalarField>,
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
        let s = G::ScalarField::rand(rng);
        let mut e = G::ScalarField::rand(rng);
        while (e + secret_key.0).is_zero() {
            e = G::ScalarField::rand(rng)
        }
        // 1/(e+x)
        let e_plus_x_inv = (e + secret_key.0).inverse().unwrap();
        let A = params.b(messages.iter().enumerate(), &s)? * e_plus_x_inv;
        Ok(Self {
            A: A.into_affine(),
            e,
            s,
        })
    }

    /// Issuer creates a MAC on some blinded attributes.
    /// This is for "Blind Issuance" mentioned in section 4.2 of the paper with a modification, the issuer does not
    /// contribute any randomness that goes towards `s`
    pub fn new_with_committed_messages<R: RngCore>(
        rng: &mut R,
        commitment: &G,
        uncommitted_messages: BTreeMap<usize, &G::ScalarField>,
        sk: &SecretKey<G::ScalarField>,
        params: impl AsRef<MACParams<G>>,
    ) -> Result<Self, KVACError> {
        if uncommitted_messages.is_empty() {
            return Err(KVACError::NoMessageGiven);
        }
        let params = params.as_ref();
        // `>` as commitment will have 0 or more messages. In practice, commitment should have
        // at least 1 message
        if uncommitted_messages.len() > params.supported_message_count() {
            return Err(KVACError::MessageCountIncompatibleWithMACParams(
                uncommitted_messages.len(),
                params.supported_message_count(),
            ));
        }

        let s = G::ScalarField::rand(rng);
        // `b` is the part of signature on uncommitted messages,
        // i.e. partial_sig = h + sum(g_vec_i * m_i) for all i in uncommitted_messages
        let b = params.b(uncommitted_messages, &s)?;

        let mut e = G::ScalarField::rand(rng);
        while (e + sk.0).is_zero() {
            e = G::ScalarField::rand(rng)
        }
        // 1/(e+x)
        let e_plus_x_inv = (e + sk.0).inverse().unwrap();

        // {commitment + b} * {1/(e+x)}
        let commitment_plus_b = b + commitment;
        let A = commitment_plus_b * e_plus_x_inv;
        Ok(MAC {
            A: A.into_affine(),
            e,
            s,
        })
    }

    pub fn verify(
        &self,
        messages: &[G::ScalarField],
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
        let b = params.b(messages.iter().enumerate(), &self.s)?;
        let e_plus_x_inv = (self.e + sk.as_ref())
            .inverse()
            .ok_or(KVACError::CannotInvert0)?;
        if (b * e_plus_x_inv).into_affine() != self.A {
            return Err(KVACError::InvalidMAC);
        }
        Ok(())
    }

    /// Used to unblind a blinded MAC from signer
    pub fn unblind(self, blinding: &G::ScalarField) -> Self {
        MAC {
            A: self.A,
            s: self.s + blinding,
            e: self.e,
        }
        .into()
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
        let p2 = PokDiscreteLogProtocol::init(witness, blinding, &params.g_0);
        p1.challenge_contribution(&mac.A, &B, &mut challenge_bytes)
            .unwrap();
        p2.challenge_contribution(&params.g_0, &public_key.0, &mut challenge_bytes)
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
        public_key: &PublicKey<G>,
        params: impl AsRef<MACParams<G>>,
    ) -> Result<(), KVACError> {
        if self.sc_B.response != self.sc_pk.response {
            return Err(KVACError::InvalidMACProof);
        }
        let params = params.as_ref();
        // B = h + g * s + g_1 * m_1 + g_2 * m_2 + ... g_n * m_n
        let B =
            (params.b(messages.iter().enumerate(), &mac.s)? + mac.A * mac.e.neg()).into_affine();

        let mut challenge_bytes = vec![];
        self.sc_B
            .challenge_contribution(&mac.A, &B, &mut challenge_bytes)
            .unwrap();
        self.sc_pk
            .challenge_contribution(&params.g_0, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self.sc_B.verify(&B, &mac.A, &challenge) {
            return Err(KVACError::InvalidMACProof);
        }
        if !self.sc_pk.verify(&public_key.0, &params.g_0, &challenge) {
            return Err(KVACError::InvalidMACProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use std::collections::BTreeSet;

    #[test]
    fn mac_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", message_count);
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&sk, &params.g_0);
        let mac = MAC::new(&mut rng, &messages, &sk, &params).unwrap();
        mac.verify(&messages, &sk, &params).unwrap();

        let proof = ProofOfValidityOfMAC::new::<_, Blake2b512>(&mut rng, &mac, &sk, &pk, &params);
        proof
            .verify::<Blake2b512>(&mac, &messages, &pk, params)
            .unwrap();
    }

    #[test]
    fn blind_issuance() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", message_count);
        let sk = SecretKey::new(&mut rng);

        // 4 messages are not known to signer but are given in a commitment
        let blinding = Fr::rand(&mut rng);
        // Commit messages with indices 0, 1, 4, 9
        let mut committed_indices = BTreeSet::new();
        committed_indices.insert(0);
        committed_indices.insert(1);
        committed_indices.insert(4);
        committed_indices.insert(9);

        let committed_messages = committed_indices
            .iter()
            .map(|i| (*i, &messages[*i]))
            .collect::<BTreeMap<_, _>>();
        let commitment = params
            .commit_to_messages(committed_messages, &blinding)
            .unwrap();

        let mut uncommitted_messages = BTreeMap::new();
        for (i, msg) in messages.iter().enumerate() {
            if committed_indices.contains(&i) {
                continue;
            }
            uncommitted_messages.insert(i, msg);
        }

        let blinded_mac = MAC::new_with_committed_messages(
            &mut rng,
            &commitment,
            uncommitted_messages,
            &sk,
            &params,
        )
        .unwrap();

        assert!(blinded_mac.verify(&messages, &sk, &params).is_err());

        let mac = blinded_mac.unblind(&blinding);
        mac.verify(&messages, sk, params).unwrap();
    }
}
