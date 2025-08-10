//! A more efficient protocol generating pseudonym and corresponding proof of knowledge
//!
//! This significantly reduces the number of pairings done by both the user and verifier as well as reducing the
//! storage and computation cost of user and issuer as the "user secret key" (issuer's signature) is a single group
//! element in group G1. **But this doesn't have a security proof yet.**
//!
//! - Setup parameters: `g ∈ G1, g_hat ∈ G2`
//! - Issuer keys: secret `sk ∈ Z_p`, public `ivk_hat ∈ G2, ivk_hat = g_hat*sk`
//! - User gets from issuer a weak-BB signature `usk ∈ G1, usk = g*{1/(sk+s)}` where `s ∈ Z_p` is the user's identity
//! - User and verifier hash context to `Z ∈ G2`.
//!
//! For the user's signature generation, the objective is that given usk, the user wants to prove 2 relations
//! 1. `T = e(usk, Z)` where `T, Z` are public but usk is only known to the user.
//! 2. User knows a valid `usk` and the `s` in `usk` without revealing `usk` and `usk` satisfies `e(usk, g_hat*s + ivk_hat) == e(g, g_hat)`.
//! And the user should prove that usk used in relation 1 and 2 are the same.
//!
//! Relation 1 can be proved by applying the folklore Schnorr protocol for discrete log to the pairing setting. Eg. i.e. given the prover and
//! verifier both know `(Z, T)` and the prover additionally knows `usk`, prove that `e(usk, Z) = T`.
//! 1. Prover chooses a random `R ∈ G1` and computes `K = e(R, Z)`
//! 2. Verifier gives a challenge `c ∈ Z_p`.
//! 3. Computes response `S ∈ G1, S = R + usk*c` and sends `(K, S)` to the verifier.
//! 4. Verifier checks if `e(S, Z) = K + T*c`. This works because `e(S, Z) = e(R + usk*c, Z) = e(R, Z) + e(usk*c, Z) = K + c*e(usk, Z) = K + c*T`.
//!
//! `usk` is essentially a weak-BB signature so we can create a proof for relation 2 using the proof of knowledge of weak-BB signature protocol described
//! in section 2.4 of [this paper](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf). Note that there is no pairing computation for prover and
//! only 1 for verifier (considering a pairing product).
//!
//! To prove `usk` is the same in both relations, the user chooses a random `r ∈ Z_p` and creates `V ∈ G1, V = usk*r` and `T' = e(V, Z) = T*r` and
//! proves knowledge of `r` in `T' = T*r`. Note that `V, r` are the same as the ones created in the proof of relation 2 and the user can prove that
//! `r` is the same. Also, the prover doesn't send `T'`, the verifier creates using `V` and `Z` as `T' = e(V, Z)`.
//! The idea is that since the user is already proving that `V` is randomized `usk`, the same `V` can also produce a randomized
//! pseudonym `T'` (similar to how the original weak-BB signature `usk` produced the original pseudonym `T`) and
//! user knows that randomizer `r`.
//!
//!
//! Following is the detailed protocol for user's signature generation
//! 1. User follows the above protocol for Relation 1 (verifier's challenge is generated through Fiat Shamir) and gets `T = e(usk, Z)` and proof `pi_1 = (K, S)`.
//! 2. User picks a random `r  ∈ Z_p`, creates `V, V' ∈ G1` as `V = usk*r, V' = V*-s * g*r, T' = T*r`.
//! 3. User creates a proof `pi_2 = SPK{(s, r) : V' = V*-s * g*r ∧ T' = T*r}`.
//! 4. User sends proof `pi_1, T, pi_2, V, V'` to the verifier.
//! 5. Verifier creates `T' = e(V, Z)`, checks `pi_1, pi_2` and `e(V', g_hat) == e(V, ivk_hat)`.
//!

use crate::{
    error::SyraError,
    setup::{IssuerSecretKey, PreparedSetupParams, SetupParams},
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use schnorr_pok::discrete_log_pairing::{
    PoKG1DiscreteLogInPairing, PoKG1DiscreteLogInPairingProtocol,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use short_group_sig::{
    weak_bb_sig::{PublicKeyG2, SignatureG1},
    weak_bb_sig_pok_cdh::{PoKOfSignatureG1, PoKOfSignatureG1Protocol},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Issuer's public key
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IssuerPublicKey<E: Pairing>(pub PublicKeyG2<E>);

/// User's secret key
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserSecretKey<E: Pairing>(pub SignatureG1<E>);

impl<E: Pairing> IssuerPublicKey<E> {
    pub fn new(sk: &IssuerSecretKey<E::ScalarField>, params: &SetupParams<E>) -> Self {
        Self(PublicKeyG2((params.g_hat * sk.0).into()))
    }
}

impl<E: Pairing> AsRef<E::G2Affine> for IssuerPublicKey<E> {
    fn as_ref(&self) -> &E::G2Affine {
        &self.0 .0
    }
}

impl<E: Pairing> UserSecretKey<E> {
    pub fn new(
        user_id: &E::ScalarField,
        issuer_sk: &IssuerSecretKey<E::ScalarField>,
        params: &SetupParams<E>,
    ) -> Self {
        Self(SignatureG1::new(user_id, issuer_sk, params))
    }

    pub fn verify(
        &self,
        user_id: E::ScalarField,
        issuer_pk: &IssuerPublicKey<E>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), SyraError> {
        let params = params.into();
        self.0
            .verify_given_destructured_params_with_pairing(
                &user_id,
                &issuer_pk.0,
                params.g_hat,
                params.pairing,
            )
            .map_err(|e| e.into())
    }
}

impl<E: Pairing> AsRef<E::G1Affine> for UserSecretKey<E> {
    fn as_ref(&self) -> &E::G1Affine {
        &self.0 .0
    }
}

/// Protocol to generate a pseudonym and its proof of correctness.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PseudonymGenProtocol<E: Pairing> {
    pub pok_usk: PoKG1DiscreteLogInPairingProtocol<E>,
    pub pok_usk_bb_sig: PoKOfSignatureG1Protocol<E>,
    /// Pseudonym
    #[zeroize(skip)]
    pub T: PairingOutput<E>,
    /// `T*r`
    #[zeroize(skip)]
    pub T_prime: PairingOutput<E>,
    /// For proving knowledge of `r` in `T' = T * r`, prover picks blinding `l` and creates `T*l` as the first
    /// step of Schnorr protocol. This `l` matches the blinding used in proof of knowledge of weak-BB sig
    #[zeroize(skip)]
    pub J: PairingOutput<E>,
}

/// This contains the pseudonym as well its proof of correctness
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PseudonymProof<E: Pairing> {
    pub pok_usk: PoKG1DiscreteLogInPairing<E>,
    pub pok_usk_bb_sig: PoKOfSignatureG1<E>,
    /// Pseudonym
    pub T: PairingOutput<E>,
    pub J: PairingOutput<E>,
}

impl<E: Pairing> PseudonymGenProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        Z: E::G2Affine,
        s: E::ScalarField,
        blinding: Option<E::ScalarField>,
        user_sk: UserSecretKey<E>,
        params: &SetupParams<E>,
    ) -> Self {
        let T = E::pairing(E::G1Prepared::from(user_sk.0 .0), E::G2Prepared::from(Z));
        let r = E::ScalarField::rand(rng);
        let r_blinding = E::ScalarField::rand(rng);
        let msg_blinding = blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        let pok_usk = PoKG1DiscreteLogInPairingProtocol::init(
            user_sk.0 .0.clone(),
            E::G1Affine::rand(rng),
            &Z,
        );
        let pok_usk_bb_sig = PoKOfSignatureG1Protocol::init_with_given_randomness(
            r,
            msg_blinding,
            r_blinding,
            user_sk,
            s,
            &params.g,
        );
        let T_prime = T * r;
        let J = T * r_blinding;
        Self {
            pok_usk,
            pok_usk_bb_sig,
            T,
            T_prime,
            J,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        Z: &E::G2Affine,
        issuer_pk: &IssuerPublicKey<E>,
        g: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), SyraError> {
        issuer_pk.serialize_compressed(&mut writer)?;
        self.J.serialize_compressed(&mut writer)?;
        self.pok_usk
            .challenge_contribution(&Z, &self.T, &mut writer)?;
        self.pok_usk_bb_sig.challenge_contribution(g, &mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> PseudonymProof<E> {
        let pok_usk = self.pok_usk.clone().gen_proof(challenge);
        let pok_usk_bb_sig = self.pok_usk_bb_sig.clone().gen_proof(challenge);
        PseudonymProof {
            pok_usk,
            pok_usk_bb_sig,
            T: self.T,
            J: self.J,
        }
    }
}

impl<E: Pairing> PseudonymProof<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        Z: E::G2Affine,
        issuer_pk: &IssuerPublicKey<E>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), SyraError> {
        if !self.pok_usk.verify(&self.T, Z, challenge) {
            return Err(SyraError::InvalidProof);
        }
        let T_prime = E::pairing(self.pok_usk_bb_sig.A_prime, Z);
        if (T_prime * challenge) + self.J
            != self.T * self.pok_usk_bb_sig.sc.as_ref().unwrap().response1
        {
            return Err(SyraError::InvalidProof);
        }
        let params = params.into();
        self.pok_usk_bb_sig
            .verify(
                challenge,
                issuer_pk.0 .0.clone(),
                &params.g,
                params.g_hat_prepared,
            )
            .map_err(|e| e.into())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        Z: &E::G2Affine,
        issuer_pk: &IssuerPublicKey<E>,
        g: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), SyraError> {
        issuer_pk.serialize_compressed(&mut writer)?;
        self.J.serialize_compressed(&mut writer)?;
        self.pok_usk
            .challenge_contribution(&Z, &self.T, &mut writer)?;
        self.pok_usk_bb_sig.challenge_contribution(g, &mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G2Affine};
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::Instant;

    #[test]
    fn pseudonym() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");
        let prepared_params = PreparedSetupParams::<Bls12_381>::from(params.clone());

        // Signer's setup
        let isk = IssuerSecretKey::new(&mut rng);
        let ipk = IssuerPublicKey::new(&isk, &params);

        // Signer creates user secret key
        let user_id = compute_random_oracle_challenge::<Fr, Blake2b512>(b"low entropy user-id");

        let start = Instant::now();
        let usk = UserSecretKey::new(&user_id, &isk, &params);
        println!("Time to create user secret key {:?}", start.elapsed());

        let start = Instant::now();
        usk.verify(user_id, &ipk, prepared_params.clone()).unwrap();
        println!("Time to verify user secret key {:?}", start.elapsed());

        // Verifier gives message and context to user
        let context = b"test-context";
        let msg = b"test-message";

        // Generate Z from context
        let Z = affine_group_elem_from_try_and_incr::<G2Affine, Blake2b512>(context);

        // User generates a pseudonym
        let start = Instant::now();
        let protocol =
            PseudonymGenProtocol::init(&mut rng, Z.clone(), user_id.clone(), None, usk, &params);
        let mut chal_bytes = vec![];
        protocol
            .challenge_contribution(&Z, &ipk, &params.g, &mut chal_bytes)
            .unwrap();
        // Add message to the transcript (message contributes to challenge)
        chal_bytes.extend_from_slice(msg);
        let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
        let proof = protocol.gen_proof(&challenge_prover);
        println!("Time to create proof {:?}", start.elapsed());
        println!("Size of proof {} bytes", proof.compressed_size());

        // Verifier checks the correctness of the pseudonym
        let start = Instant::now();
        let mut chal_bytes = vec![];
        proof
            .challenge_contribution(&Z, &ipk, &params.g, &mut chal_bytes)
            .unwrap();
        // Add message to the transcript (message contributes to challenge)
        chal_bytes.extend_from_slice(msg);
        let challenge_verifier = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
        proof
            .verify(&challenge_verifier, Z, &ipk, prepared_params.clone())
            .unwrap();
        println!("Time to verify proof {:?}", start.elapsed());
    }
}
