use crate::{bddt_2016::setup::SecretKey, error::KVACError};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    affine_group_element_from_byte_slices, commitment::PedersenCommitmentKey,
    serde_utils::ArkObjectBytes,
};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{
        PokDiscreteLog, PokDiscreteLogProtocol, PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol,
    },
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
/// keys and the delegated. Its a tuple of the form `(P, Q=P*i/y)` where `P` and `Q` are elements in group G2 and `y`
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

/// A Pedersen commitment to the secret key, `Comm = G * y + H * r`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SecretKeyCommitment<G: AffineRepr>(pub G);

/// A proof that the `DelegatedProof` can be verified correctly. It proves secret key `y` is same in the
/// `DelegatedProof` and the `SecretKeyCommitment`, i.e. `C = B_0 * y, Comm = G * y + H * r`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfDelegatedProof<G: AffineRepr> {
    /// Proof of knowledge of opening of `SecretKeyCommitment`
    pub sc_comm: PokTwoDiscreteLogs<G>,
    /// Proof of knowledge of secret key in `DelegatedProof`
    pub sc_proof: PokDiscreteLog<G>,
}

impl<E: Pairing> DelegatedPublicKey<E> {
    pub fn new<D: Digest>(label: &[u8], sk: &SecretKey<E::ScalarField>) -> Self {
        let P = affine_group_element_from_byte_slices!(label, b" : P");
        let Q = P * sk.0.inverse().unwrap();
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
        // check e(B_0, pk.0) = e(C, pk.1)
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.B_0),
                E::G1Prepared::from(self.C.into_group().neg().into()),
            ],
            [pk.0, pk.1],
        )
        .is_zero()
        {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        Ok(())
    }

    pub fn create_proof_of_validity<R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: SecretKey<G::ScalarField>,
        comm_randomness: G::ScalarField,
        comm: &SecretKeyCommitment<G>,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> ProofOfValidityOfDelegatedProof<G> {
        let sk_blinding = G::ScalarField::rand(rng);
        let sc_comm = PokTwoDiscreteLogsProtocol::init(
            secret_key.0,
            sk_blinding,
            &comm_key.g,
            comm_randomness,
            G::ScalarField::rand(rng),
            &comm_key.h,
        );
        let sc_proof = PokDiscreteLogProtocol::init(secret_key.0, sk_blinding, &self.B_0);
        let mut challenge_bytes = vec![];
        sc_comm
            .challenge_contribution(&comm_key.g, &comm_key.h, &comm.0, &mut challenge_bytes)
            .unwrap();
        sc_proof
            .challenge_contribution(&self.B_0, &self.C, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let sc_comm = sc_comm.gen_proof(&challenge);
        let sc_proof = sc_proof.gen_proof(&challenge);
        ProofOfValidityOfDelegatedProof { sc_comm, sc_proof }
    }
}

impl<G: AffineRepr> SecretKeyCommitment<G> {
    pub fn new(
        secret_key: &SecretKey<G::ScalarField>,
        randomness: &G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        Self(comm_key.commit(&secret_key.0, randomness))
    }
}

impl<G: AffineRepr> ProofOfValidityOfDelegatedProof<G> {
    pub fn verify<D: Digest>(
        &self,
        proof: &DelegatedProof<G>,
        comm: &SecretKeyCommitment<G>,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Result<(), KVACError> {
        if self.sc_proof.response != self.sc_comm.response1 {
            return Err(KVACError::InvalidDelegatedProof);
        }
        let mut challenge_bytes = vec![];
        self.sc_comm
            .challenge_contribution(&comm_key.g, &comm_key.h, &comm.0, &mut challenge_bytes)
            .unwrap();
        self.sc_proof
            .challenge_contribution(&proof.B_0, &proof.C, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self
            .sc_comm
            .verify(&comm.0, &comm_key.g, &comm_key.h, &challenge)
        {
            return Err(KVACError::InvalidDelegatedProof);
        }
        if !self.sc_proof.verify(&proof.C, &proof.B_0, &challenge) {
            return Err(KVACError::InvalidDelegatedProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ec::CurveGroup;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn verification_using_delegated_public_key() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let sk = SecretKey::new(&mut rng);
        let pk = DelegatedPublicKey::<Bls12_381>::new::<Blake2b512>(b"test", &sk);
        let B_0 = G1Affine::rand(&mut rng);
        let C = (B_0 * sk.0).into_affine();

        let dp = DelegatedProof { B_0, C };
        dp.verify(&sk).unwrap();

        dp.verify_with_delegated_public_key(pk).unwrap();

        let comm_key = PedersenCommitmentKey::new::<Blake2b512>(b"test");
        let sk_comm_randomness = Fr::rand(&mut rng);
        let sk_comm = SecretKeyCommitment::new(&sk, &sk_comm_randomness, &comm_key);
        let validity_proof = dp.create_proof_of_validity::<_, Blake2b512>(
            &mut rng,
            sk,
            sk_comm_randomness,
            &sk_comm,
            &comm_key,
        );
        validity_proof
            .verify::<Blake2b512>(&dp, &sk_comm, &comm_key)
            .unwrap();
    }
}
