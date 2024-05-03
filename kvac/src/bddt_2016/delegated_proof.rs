use crate::{
    bddt_2016::setup::{PublicKey, SecretKey},
    error::KVACError,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{affine_group_element_from_byte_slices, serde_utils::ArkObjectBytes};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    inequality::{UnknownDiscreteLogInequalityProof, UnknownDiscreteLogInequalityProtocol},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// The part of the proof requiring secret key to verify.
/// The purpose is to split the signer's/verifier's task into 2 parts where `Proof::verify_schnorr_proofs`
/// can be done by an "untrusted helper" who does not know secret key `y` but `DelegatedProof::verify` requires knowing
/// secret key. This lets us build for use-cases where the signer, acting as the credential issuer, would not want the credential to be used without
/// its permission, like when he wants to be paid by the verifier who acts as the "untrusted helper" which verifies the Schnorr proofs
/// and learns the revealed messages (credential attributes) but these are not learnt by the signer thus maintaining the user's privacy.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct DelegatedProof<G: AffineRepr> {
    /// The randomized MAC
    #[serde_as(as = "ArkObjectBytes")]
    pub B_0: G,
    /// `C = B_0 * y` where `y` is the secret key
    #[serde_as(as = "ArkObjectBytes")]
    pub C: G,
}

/// A public key to verify a `DelegatedProof`. The secret key can be used to create any number of delegated public
/// keys. It's a tuple of the form `(P, Q=P*y)` where `P` and `Q` are elements in group G2 and `y`
/// is the secret key.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct DelegatedPublicKey<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub E::G2Affine,
    #[serde_as(as = "ArkObjectBytes")] pub E::G2Affine,
);

#[serde_as]
#[derive(
    Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedDelegatedPublicKey<E: Pairing>(
    #[serde_as(as = "ArkObjectBytes")] pub E::G2Prepared,
    #[serde_as(as = "ArkObjectBytes")] pub E::G2Prepared,
);

/// A proof that the `DelegatedProof` can be verified successfully. It proves that secret key `y` is same in the
/// `DelegatedProof` and the `PublicKey`, i.e. `C = B_0 * y, Pk = g_0 * y`. This can be given
/// by the signer to the verifier after verifying the delegated proof to convince the verifier that the delegated
/// proof was in fact valid.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfDelegatedProof<G: AffineRepr> {
    /// Proof of knowledge of opening of `PublicKey`
    pub sc_pk: PokDiscreteLog<G>,
    /// Proof of knowledge of secret key in `DelegatedProof`
    pub sc_proof: PokDiscreteLog<G>,
}

/// A proof that the `DelegatedProof` cannot be verified successfully. It proves that DLOG of `C` wrt `B_0`
/// is not the secret key `y` where (`B_0`, `C`) and `Pk` are the `DelegatedProof` and the `PublicKey` respectively,
/// i.e. `C = B_0 * k, Pk = g_0 * y`. This can be given by the signer to the verifier after verifying the delegated
/// proof to convince the verifier that the delegated proof was in fact invalid.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfInvalidityOfDelegatedProof<G: AffineRepr>(UnknownDiscreteLogInequalityProof<G>);

impl<E: Pairing> DelegatedPublicKey<E> {
    pub fn new<D: Digest>(label: &[u8], sk: &SecretKey<E::ScalarField>) -> Self {
        let P = affine_group_element_from_byte_slices!(label, b" : P");
        let Q = P * sk.0;
        Self(P, Q.into())
    }
}

impl<E: Pairing> From<DelegatedPublicKey<E>> for PreparedDelegatedPublicKey<E> {
    fn from(pk: DelegatedPublicKey<E>) -> Self {
        Self(E::G2Prepared::from(pk.0), E::G2Prepared::from(pk.1))
    }
}

impl<G: AffineRepr> DelegatedProof<G> {
    /// Verify the proof using secret key
    pub fn verify(&self, secret_key: &SecretKey<G::ScalarField>) -> Result<(), KVACError> {
        if self.C != (self.B_0 * secret_key.0).into() {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        Ok(())
    }

    pub fn verify_with_delegated_public_key<E: Pairing>(
        &self,
        pk: impl Into<PreparedDelegatedPublicKey<E>>,
    ) -> Result<(), KVACError>
    where
        <E as Pairing>::G1Prepared: From<G>,
    {
        let pk = pk.into();
        // check e(B_0, pk.1) = e(C, pk.0)
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.B_0),
                E::G1Prepared::from(self.C.into_group().neg().into()),
            ],
            [pk.1, pk.0],
        )
        .is_zero()
        {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        Ok(())
    }

    pub fn create_proof_of_validity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        g_0: impl Into<&'a G>,
    ) -> ProofOfValidityOfDelegatedProof<G> {
        let g_0 = g_0.into();
        let sk_blinding = G::ScalarField::rand(rng);
        let sc_pk = PokDiscreteLogProtocol::init(secret_key.0, sk_blinding, g_0);
        let sc_proof = PokDiscreteLogProtocol::init(secret_key.0, sk_blinding, &self.B_0);
        let mut challenge_bytes = vec![];
        sc_pk
            .challenge_contribution(g_0, &pk.0, &mut challenge_bytes)
            .unwrap();
        sc_proof
            .challenge_contribution(&self.B_0, &self.C, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let sc_pk = sc_pk.gen_proof(&challenge);
        let sc_proof = sc_proof.gen_proof(&challenge);
        ProofOfValidityOfDelegatedProof { sc_pk, sc_proof }
    }

    pub fn create_proof_of_invalidity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        g_0: impl Into<&'a G>,
    ) -> Result<ProofOfInvalidityOfDelegatedProof<G>, KVACError> {
        let g_0 = g_0.into();
        let protocol = UnknownDiscreteLogInequalityProtocol::new(
            rng,
            secret_key.0,
            g_0,
            &self.B_0,
            &pk.0,
            &self.C,
        )?;
        let mut challenge_bytes = vec![];
        protocol.challenge_contribution(g_0, &self.B_0, &pk.0, &self.C, &mut challenge_bytes)?;
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let proof = protocol.gen_proof(&challenge);
        Ok(ProofOfInvalidityOfDelegatedProof(proof))
    }
}

impl<G: AffineRepr> ProofOfValidityOfDelegatedProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &DelegatedProof<G>,
        pk: &PublicKey<G>,
        g_0: impl Into<&'a G>,
    ) -> Result<(), KVACError> {
        if self.sc_proof.response != self.sc_pk.response {
            return Err(KVACError::InvalidDelegatedProof);
        }
        let g_0 = g_0.into();
        let mut challenge_bytes = vec![];
        self.sc_pk
            .challenge_contribution(g_0, &pk.0, &mut challenge_bytes)
            .unwrap();
        self.sc_proof
            .challenge_contribution(&proof.B_0, &proof.C, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self.sc_pk.verify(&pk.0, g_0, &challenge) {
            return Err(KVACError::InvalidDelegatedProof);
        }
        if !self.sc_proof.verify(&proof.C, &proof.B_0, &challenge) {
            return Err(KVACError::InvalidDelegatedProof);
        }
        Ok(())
    }
}

impl<G: AffineRepr> ProofOfInvalidityOfDelegatedProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &DelegatedProof<G>,
        pk: &PublicKey<G>,
        g_0: impl Into<&'a G>,
    ) -> Result<(), KVACError> {
        let g_0 = g_0.into();
        let mut challenge_bytes = vec![];
        self.0
            .challenge_contribution(g_0, &proof.B_0, &pk.0, &proof.C, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        self.0
            .verify(g_0, &proof.B_0, &pk.0, &proof.C, &challenge)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bddt_2016::setup::MACParams;
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_ec::CurveGroup;
    use ark_ff::Field;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn delegated_proof_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", 5);
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&sk, &params.g_0);

        // Verify using delegated public key
        let dpk = DelegatedPublicKey::<Bls12_381>::new::<Blake2b512>(b"test", &sk);
        let B_0 = G1Affine::rand(&mut rng);
        let C = (B_0 * sk.0).into_affine();

        let dp = DelegatedProof { B_0, C };
        dp.verify(&sk).unwrap();

        dp.verify_with_delegated_public_key(dpk).unwrap();

        let invalid_C = (B_0 * sk.0.square()).into_affine();
        let invalid_dp = DelegatedProof { B_0, C: invalid_C };

        // Check proof of validity
        let validity_proof =
            dp.create_proof_of_validity::<_, Blake2b512>(&mut rng, sk.clone(), &pk, &params.g_0);
        validity_proof
            .verify::<Blake2b512>(&dp, &pk, &params.g_0)
            .unwrap();
        assert!(validity_proof
            .verify::<Blake2b512>(&invalid_dp, &pk, &params.g_0)
            .is_err());

        // Check proof of invalidity
        let invalidity_proof = invalid_dp
            .create_proof_of_invalidity::<_, Blake2b512>(&mut rng, sk, &pk, &params.g_0)
            .unwrap();
        invalidity_proof
            .verify::<Blake2b512>(&invalid_dp, &pk, &params.g_0)
            .unwrap();
        assert!(invalidity_proof
            .verify::<Blake2b512>(&dp, &pk, &params.g_0)
            .is_err());
    }
}
