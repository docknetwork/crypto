//! Proofs of membership and non-membership with keyed-verification, i.e. the verifier needs to know the secret key to verify the proofs.
//! These are essentially keyed-verification proofs of knowledge of weak-BB signature. The protocols are as follows
//! Accumulator = `V`, secret key = `alpha`, `P` and `Q` are generators of group G1
//! Membership protocol
//!   witness = `C`, member = `y`, `C * (y + alpha) = V`
//!   1. User chooses random element `l` from Z_p.
//!   2. User creates `C' = C * l` and `C_bar = V * l - C' * y`. Note that `C_bar = C' * alpha`
//!   3. User creates proof of knowledge `pi`, of `l` and `y` in `C_bar` and sends `pi, C', C_bar` to the verifier.
//!   4. Verifier checks if `C_bar = C' * alpha` and then verifies proof `pi`
//! Non-membership protocol
//!   witness = `(C, d)`, member = `y`, `C * (y + alpha) + P * d = V`
//!   1. User chooses random element `l` from Z_p.
//!   2. User creates `C' = C * l, d' = d * l, C_hat = Q * d'` and `C_bar = V * l - C' * y - P * d'`. Note that `C_bar = C' * alpha`
//!   3. User creates proof of knowledge `pi_1`, of `l`, `y` and `d'` in `C_bar`, and proof of knowledge `pi_2`, of `d'` in `C_hat` and sends `pi_1, pi_2, C', C_hat, C_bar` to the verifier.
//!   4. Verifier checks if `C_bar = C' * alpha` and then verifies proof `pi_1` and `pi_2` and checks that `d'` is same in both

use crate::{
    error::VBAccumulatorError,
    setup::SecretKey,
    setup_keyed_verification::{PublicKey, SetupParams},
    witness::{MembershipWitness, NonMembershipWitness},
};
use ark_ec::{AffineRepr, CurveGroup};
use core::mem;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, io::Write, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use kvac::bddt_2016::keyed_proof::{
    KeyedProof, ProofOfInvalidityOfKeyedProof, ProofOfValidityOfKeyedProof,
};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    SchnorrCommitment, SchnorrResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::weak_bb_sig_pok_kv::{PoKOfSignatureG1KV, PoKOfSignatureG1KVProtocol};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default, Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct MembershipProofProtocol<G: AffineRepr>(pub PoKOfSignatureG1KVProtocol<G>);

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipProof<G: AffineRepr>(pub PoKOfSignatureG1KV<G>);

/// The part of membership proof whose verification requires knowledge of secret key.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct KeyedMembershipProof<G: AffineRepr>(pub KeyedProof<G>);

/// A proof that the `KeyedMembershipProof` can be verified successfully.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfKeyedMembershipProof<G: AffineRepr>(pub ProofOfValidityOfKeyedProof<G>);

/// A proof that the `KeyedMembershipProof` cannot be verified successfully.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfInvalidityOfKeyedMembershipProof<G: AffineRepr>(
    pub ProofOfInvalidityOfKeyedProof<G>,
);

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NonMembershipProofProtocol<G: AffineRepr> {
    #[zeroize(skip)]
    pub C_prime: G,
    #[zeroize(skip)]
    pub C_hat: G,
    #[zeroize(skip)]
    pub C_bar: G,
    pub sc_comm: SchnorrCommitment<G>,
    sc_wits: (G::ScalarField, G::ScalarField, G::ScalarField),
    pub sc_comm_2: PokDiscreteLogProtocol<G>,
}

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipProof<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub C_prime: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub C_hat: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub C_bar: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    pub sc_resp: SchnorrResponse<G>,
    pub sc_resp_2: PokDiscreteLog<G>,
}

/// The part of non-membership proof whose verification requires knowledge of secret key.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct KeyedNonMembershipProof<G: AffineRepr>(pub KeyedProof<G>);

/// A proof that the `KeyedNonMembershipProof` can be verified successfully.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfValidityOfKeyedNonMembershipProof<G: AffineRepr>(
    pub ProofOfValidityOfKeyedProof<G>,
);

/// A proof that the `KeyedNonMembershipProof` cannot be verified successfully.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProofOfInvalidityOfKeyedNonMembershipProof<G: AffineRepr>(
    pub ProofOfInvalidityOfKeyedProof<G>,
);

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MembershipWitnessCorrectnessProof<G: AffineRepr> {
    pub wit_proof: PokDiscreteLog<G>,
    pub sk_proof: PokDiscreteLog<G>,
}

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipWitnessCorrectnessProof<G: AffineRepr> {
    pub wit_proof: PokDiscreteLog<G>,
    pub sk_proof: PokDiscreteLog<G>,
}

impl<G: AffineRepr> MembershipWitnessCorrectnessProof<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        accumulator: &G,
        witness: &MembershipWitness<G>,
        member: &G::ScalarField,
        secret_key: SecretKey<G::ScalarField>,
        public_key: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Self {
        let mut challenge_bytes = vec![];
        let sk_blinding = G::ScalarField::rand(rng);
        let wit_protocol =
            PokDiscreteLogProtocol::init(secret_key.0, sk_blinding.clone(), &witness.0);
        let y = Self::compute_y(accumulator, witness, member);
        wit_protocol
            .challenge_contribution(&witness.0, &y, &mut challenge_bytes)
            .unwrap();
        let sk_protocol = PokDiscreteLogProtocol::init(secret_key.0, sk_blinding, &params.0);
        sk_protocol
            .challenge_contribution(&params.0, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let wit_proof = wit_protocol.gen_proof(&challenge);
        let sk_proof = sk_protocol.gen_proof(&challenge);
        Self {
            wit_proof,
            sk_proof,
        }
    }

    pub fn verify<D: Digest>(
        &self,
        accumulator: &G,
        witness: &MembershipWitness<G>,
        member: &G::ScalarField,
        public_key: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        if self.wit_proof.response != self.sk_proof.response {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        let mut challenge_bytes = vec![];
        let y = Self::compute_y(accumulator, witness, member);
        self.wit_proof
            .challenge_contribution(&witness.0, &y, &mut challenge_bytes)
            .unwrap();
        self.sk_proof
            .challenge_contribution(&params.0, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self.wit_proof.verify(&y, &witness.0, &challenge) {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        if !self.sk_proof.verify(&public_key.0, &params.0, &challenge) {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        Ok(())
    }

    fn compute_y(accumulator: &G, witness: &MembershipWitness<G>, member: &G::ScalarField) -> G {
        (accumulator.into_group() - (witness.0 * member)).into_affine()
    }
}

impl<G: AffineRepr> NonMembershipWitnessCorrectnessProof<G> {
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        accumulator: &G,
        witness: &NonMembershipWitness<G>,
        non_member: &G::ScalarField,
        secret_key: SecretKey<G::ScalarField>,
        public_key: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Self {
        let mut challenge_bytes = vec![];
        let sk_blinding = G::ScalarField::rand(rng);
        let wit_protocol =
            PokDiscreteLogProtocol::init(secret_key.0, sk_blinding.clone(), &witness.C);
        let y = Self::compute_y(accumulator, witness, non_member, params);
        wit_protocol
            .challenge_contribution(&witness.C, &y, &mut challenge_bytes)
            .unwrap();
        let sk_protocol = PokDiscreteLogProtocol::init(secret_key.0, sk_blinding, &params.0);
        sk_protocol
            .challenge_contribution(&params.0, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let wit_proof = wit_protocol.gen_proof(&challenge);
        let sk_proof = sk_protocol.gen_proof(&challenge);
        Self {
            wit_proof,
            sk_proof,
        }
    }

    pub fn verify<D: Digest>(
        &self,
        accumulator: &G,
        witness: &NonMembershipWitness<G>,
        non_member: &G::ScalarField,
        public_key: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        if self.wit_proof.response != self.sk_proof.response {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        let mut challenge_bytes = vec![];
        let y = Self::compute_y(accumulator, witness, non_member, params);
        self.wit_proof
            .challenge_contribution(&witness.C, &y, &mut challenge_bytes)
            .unwrap();
        self.sk_proof
            .challenge_contribution(&params.0, &public_key.0, &mut challenge_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !self.wit_proof.verify(&y, &witness.C, &challenge) {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        if !self.sk_proof.verify(&public_key.0, &params.0, &challenge) {
            return Err(VBAccumulatorError::InvalidMembershipCorrectnessProof);
        }
        Ok(())
    }

    fn compute_y(
        accumulator: &G,
        witness: &NonMembershipWitness<G>,
        non_member: &G::ScalarField,
        params: &SetupParams<G>,
    ) -> G {
        (accumulator.into_group() - (witness.C * non_member) - (params.0 * witness.d)).into_affine()
    }
}

impl<G: AffineRepr> MembershipProofProtocol<G> {
    /// Initialize a membership proof protocol.
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: G::ScalarField,
        element_blinding: Option<G::ScalarField>,
        witness: &MembershipWitness<G>,
        accumulator: &G,
    ) -> Self {
        Self(PoKOfSignatureG1KVProtocol::init(
            rng,
            &witness,
            element,
            element_blinding,
            accumulator,
        ))
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &G,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0.challenge_contribution(accumulator_value, writer)?;
        Ok(())
    }

    pub fn gen_proof(
        mut self,
        challenge: &G::ScalarField,
    ) -> Result<MembershipProof<G>, VBAccumulatorError> {
        let p = mem::take(&mut self.0).gen_proof(challenge);
        Ok(MembershipProof(p))
    }
}

impl<G: AffineRepr> MembershipProof<G> {
    pub fn verify(
        &self,
        accumulator: &G,
        secret_key: &SecretKey<G::ScalarField>,
        challenge: &G::ScalarField,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify(challenge, &secret_key, accumulator)?;
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &G,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0.challenge_contribution(accumulator_value, writer)?;
        Ok(())
    }

    pub fn verify_schnorr_proof(
        &self,
        accumulator: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify_schnorr_proof(accumulator, challenge)?;
        Ok(())
    }

    pub fn to_keyed_proof(&self) -> KeyedMembershipProof<G> {
        KeyedMembershipProof(KeyedProof {
            B_0: self.0.A_prime,
            C: self.0.A_bar,
        })
    }

    pub fn get_schnorr_response_for_element(&self) -> &G::ScalarField {
        self.0.get_resp_for_message()
    }
}

impl<G: AffineRepr> KeyedMembershipProof<G> {
    pub fn verify(&self, secret_key: &SecretKey<G::ScalarField>) -> Result<(), VBAccumulatorError> {
        self.0.verify(&secret_key.0)?;
        Ok(())
    }

    pub fn create_proof_of_validity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: &SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> ProofOfValidityOfKeyedMembershipProof<G> {
        ProofOfValidityOfKeyedMembershipProof(self.0.create_proof_of_validity::<R, D>(
            rng,
            secret_key.0,
            &pk.0,
            &params.0,
        ))
    }

    pub fn create_proof_of_invalidity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: &SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<ProofOfInvalidityOfKeyedMembershipProof<G>, VBAccumulatorError> {
        let p = self
            .0
            .create_proof_of_invalidity::<R, D>(rng, secret_key.0, &pk.0, &params.0)?;
        Ok(ProofOfInvalidityOfKeyedMembershipProof(p))
    }
}

impl<G: AffineRepr> ProofOfValidityOfKeyedMembershipProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &KeyedMembershipProof<G>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify::<D>(&proof.0, &pk.0, &params.0)?;
        Ok(())
    }
}

impl<G: AffineRepr> ProofOfInvalidityOfKeyedMembershipProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &KeyedMembershipProof<G>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify::<D>(&proof.0, &pk.0, &params.0)?;
        Ok(())
    }
}

impl<G: AffineRepr> NonMembershipProofProtocol<G> {
    /// Initialize a non-membership proof protocol.
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: G::ScalarField,
        element_blinding: Option<G::ScalarField>,
        witness: &NonMembershipWitness<G>,
        accumulator: G,
        params: &SetupParams<G>,
        Q: &G,
    ) -> Self {
        let l = G::ScalarField::rand(rng);
        let C_prime = witness.C * l;
        let d_prime = witness.d * l;
        let C_hat = *Q * d_prime;
        let C_prime_neg = C_prime.neg();
        let params_neg = params.0.into_group().neg();
        let C_bar = (accumulator * l + C_prime_neg * element + params_neg * d_prime).into_affine();
        let element_blinding = element_blinding.unwrap_or_else(|| G::ScalarField::rand(rng));
        let d_prime_blinding = G::ScalarField::rand(rng);
        let bases = [accumulator, C_prime_neg.into(), params_neg.into()];
        let randomness = vec![
            G::ScalarField::rand(rng),
            element_blinding,
            d_prime_blinding,
        ];
        let sc_wits = (l, element, d_prime.clone());
        let sc_comm = SchnorrCommitment::new(&bases, randomness);
        let sc_comm_2 = PokDiscreteLogProtocol::init(d_prime, d_prime_blinding, Q);
        Self {
            C_prime: C_prime.into(),
            C_hat: C_hat.into(),
            C_bar,
            sc_comm,
            sc_wits,
            sc_comm_2,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &G,
        params: &SetupParams<G>,
        Q: &G,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        Self::compute_challenge_contribution(
            accumulator_value,
            &self.C_prime,
            &self.C_hat,
            &self.C_bar,
            &params.0,
            &self.sc_comm.t,
            Q,
            &self.sc_comm_2.t,
            &mut writer,
        )
    }

    pub fn gen_proof(
        mut self,
        challenge: &G::ScalarField,
    ) -> Result<NonMembershipProof<G>, VBAccumulatorError> {
        let sc_resp = self
            .sc_comm
            .response(&[self.sc_wits.0, self.sc_wits.1, self.sc_wits.2], challenge)?;
        let sc_resp_2 = mem::take(&mut self.sc_comm_2).gen_proof(challenge);
        Ok(NonMembershipProof {
            C_prime: self.C_prime,
            C_hat: self.C_hat,
            C_bar: self.C_bar,
            t: self.sc_comm.t,
            sc_resp,
            sc_resp_2,
        })
    }

    fn compute_challenge_contribution<W: Write>(
        accumulator_value: &G,
        C_prime: &G,
        C_hat: &G,
        C_bar: &G,
        g: &G,
        t: &G,
        Q: &G,
        t_2: &G,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        accumulator_value.serialize_compressed(&mut writer)?;
        C_prime.serialize_compressed(&mut writer)?;
        C_hat.serialize_compressed(&mut writer)?;
        C_bar.serialize_compressed(&mut writer)?;
        g.serialize_compressed(&mut writer)?;
        t.serialize_compressed(&mut writer)?;
        Q.serialize_compressed(&mut writer)?;
        t_2.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<G: AffineRepr> NonMembershipProof<G> {
    pub fn verify(
        &self,
        accumulator: G,
        secret_key: &SecretKey<G::ScalarField>,
        challenge: &G::ScalarField,
        params: &SetupParams<G>,
        Q: &G,
    ) -> Result<(), VBAccumulatorError> {
        if self.C_bar != (self.C_prime * secret_key.0).into() {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        if self.C_hat.is_zero() {
            return Err(VBAccumulatorError::CannotBeZero);
        }
        self.verify_schnorr_proof(accumulator, challenge, params, Q)
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &G,
        params: &SetupParams<G>,
        Q: &G,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        NonMembershipProofProtocol::compute_challenge_contribution(
            accumulator_value,
            &self.C_prime,
            &self.C_hat,
            &self.C_bar,
            &params.0,
            &self.t,
            Q,
            &self.sc_resp_2.t,
            &mut writer,
        )
    }

    pub fn verify_schnorr_proof(
        &self,
        accumulator: G,
        challenge: &G::ScalarField,
        params: &SetupParams<G>,
        Q: &G,
    ) -> Result<(), VBAccumulatorError> {
        let bases = [
            accumulator,
            self.C_prime.into_group().neg().into(),
            params.0.into_group().neg().into(),
        ];
        self.sc_resp
            .is_valid(&bases, &self.C_bar, &self.t, challenge)?;
        if !self.sc_resp_2.verify(&self.C_hat, Q, challenge) {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        if *self.sc_resp.get_response(2)? != self.sc_resp_2.response {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        Ok(())
    }

    pub fn to_keyed_proof(&self) -> KeyedNonMembershipProof<G> {
        KeyedNonMembershipProof(KeyedProof {
            B_0: self.C_prime,
            C: self.C_bar,
        })
    }

    pub fn get_schnorr_response_for_element(&self) -> &G::ScalarField {
        self.sc_resp.get_response(1).unwrap()
    }
}

impl<G: AffineRepr> KeyedNonMembershipProof<G> {
    pub fn verify(&self, secret_key: &SecretKey<G::ScalarField>) -> Result<(), VBAccumulatorError> {
        self.0.verify(&secret_key.0)?;
        Ok(())
    }

    pub fn create_proof_of_validity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: &SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> ProofOfValidityOfKeyedNonMembershipProof<G> {
        ProofOfValidityOfKeyedNonMembershipProof(self.0.create_proof_of_validity::<R, D>(
            rng,
            secret_key.0,
            &pk.0,
            &params.0,
        ))
    }

    pub fn create_proof_of_invalidity<'a, R: RngCore, D: Digest>(
        &self,
        rng: &mut R,
        secret_key: &SecretKey<G::ScalarField>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<ProofOfInvalidityOfKeyedNonMembershipProof<G>, VBAccumulatorError> {
        let p = self
            .0
            .create_proof_of_invalidity::<R, D>(rng, secret_key.0, &pk.0, &params.0)?;
        Ok(ProofOfInvalidityOfKeyedNonMembershipProof(p))
    }
}

impl<G: AffineRepr> ProofOfValidityOfKeyedNonMembershipProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &KeyedNonMembershipProof<G>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify::<D>(&proof.0, &pk.0, &params.0)?;
        Ok(())
    }
}

impl<G: AffineRepr> ProofOfInvalidityOfKeyedNonMembershipProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        proof: &KeyedNonMembershipProof<G>,
        pk: &PublicKey<G>,
        params: &SetupParams<G>,
    ) -> Result<(), VBAccumulatorError> {
        self.0.verify::<D>(&proof.0, &pk.0, &params.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::positive::Accumulator;

    use crate::{
        persistence::test::{InMemoryInitialElements, InMemoryState},
        positive::PositiveAccumulator,
        universal::UniversalAccumulator,
    };
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};

    pub fn setup_positive_accum() -> (
        SetupParams<G1Affine>,
        SecretKey<Fr>,
        PublicKey<G1Affine>,
        PositiveAccumulator<Bls12_381>,
        InMemoryState<Fr>,
    ) {
        let params = SetupParams::<G1Affine>::new::<Blake2b512>(b"test");
        let seed = [0, 1, 2, 10, 11];
        let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
        let pk = PublicKey::new_from_secret_key(&sk, &params);

        let accumulator = PositiveAccumulator::initialize(&params);
        let state = InMemoryState::new();
        (params, sk, pk, accumulator, state)
    }

    pub fn setup_universal_accum(
        rng: &mut StdRng,
        max: u64,
    ) -> (
        SetupParams<G1Affine>,
        SecretKey<Fr>,
        PublicKey<G1Affine>,
        UniversalAccumulator<Bls12_381>,
        InMemoryInitialElements<Fr>,
        InMemoryState<Fr>,
    ) {
        let params = SetupParams::<G1Affine>::new::<Blake2b512>(b"test");
        let seed = [0, 1, 2, 10, 11];
        let sk = SecretKey::generate_using_seed::<Blake2b512>(&seed);
        let pk = PublicKey::new_from_secret_key(&sk, &params);

        let mut initial_elements = InMemoryInitialElements::new();
        let accumulator = UniversalAccumulator::initialize_with_all_random(
            rng,
            &params,
            max,
            &sk,
            &mut initial_elements,
        );
        let state = InMemoryState::new();
        (params, sk, pk, accumulator, initial_elements, state)
    }

    #[test]
    fn membership_proof_positive_accumulator() {
        // Proof of knowledge of membership witness
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, secret_key, public_key, mut accumulator, mut state) = setup_positive_accum();

        let mut elems = vec![];
        let mut witnesses = vec![];
        let count = 10;

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator.add(elem, &secret_key, &mut state).unwrap();
            elems.push(elem);
        }

        for i in 0..count {
            let w = accumulator
                .get_membership_witness(&elems[i], &secret_key, &state)
                .unwrap();
            let correctness_proof = MembershipWitnessCorrectnessProof::new::<StdRng, Blake2b512>(
                &mut rng,
                accumulator.value(),
                &w,
                &elems[i],
                secret_key.clone(),
                &public_key,
                &params,
            );
            correctness_proof
                .verify::<Blake2b512>(accumulator.value(), &w, &elems[i], &public_key, &params)
                .unwrap();
            witnesses.push(w);
        }

        let mut proof_create_duration = Duration::default();
        let mut proof_verif_duration = Duration::default();

        for i in 0..count {
            let start = Instant::now();
            let protocol = MembershipProofProtocol::init(
                &mut rng,
                elems[i].clone(),
                None,
                &witnesses[i],
                accumulator.value(),
            );
            proof_create_duration += start.elapsed();

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(accumulator.value(), &mut chal_bytes_prover)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            // TODO Uncomment
            // Proof can be serialized
            // test_serialization!(MembershipProof<G1Affine>, proof);

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(accumulator.value(), &mut chal_bytes_verifier)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

            assert_eq!(challenge_prover, challenge_verifier);

            let start = Instant::now();
            proof
                .verify(accumulator.value(), &secret_key, &challenge_verifier)
                .unwrap();
            proof_verif_duration += start.elapsed();

            proof
                .verify_schnorr_proof(accumulator.value(), &challenge_verifier)
                .unwrap();
            let keyed_proof = proof.to_keyed_proof();
            keyed_proof.verify(&secret_key).unwrap();

            let mut invalid_keyed_proof = keyed_proof.clone();
            invalid_keyed_proof.0.C = G1Affine::rand(&mut rng);

            let proof_of_validity = keyed_proof.create_proof_of_validity::<_, Blake2b512>(
                &mut rng,
                &secret_key,
                &public_key,
                &params,
            );
            proof_of_validity
                .verify::<Blake2b512>(&keyed_proof, &public_key, &params)
                .unwrap();
            assert!(proof_of_validity
                .verify::<Blake2b512>(&invalid_keyed_proof, &public_key, &params)
                .is_err());

            let proof_of_invalidity = invalid_keyed_proof
                .create_proof_of_invalidity::<_, Blake2b512>(
                    &mut rng,
                    &secret_key,
                    &public_key,
                    &params,
                )
                .unwrap();
            proof_of_invalidity
                .verify::<Blake2b512>(&invalid_keyed_proof, &public_key, &params)
                .unwrap();
            assert!(proof_of_invalidity
                .verify::<Blake2b512>(&keyed_proof, &public_key, &params)
                .is_err());
        }

        println!(
            "Time to create {} membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} membership proofs is {:?}",
            count, proof_verif_duration
        );
    }

    #[test]
    fn non_membership_proof_universal_accumulator() {
        // Proof of knowledge of non-membership witness
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, secret_key, public_key, mut accumulator, initial_elems, mut state) =
            setup_universal_accum(&mut rng, max);

        let Q = G1Affine::rand(&mut rng);

        let mut elems = vec![];
        let mut witnesses = vec![];
        let count = 10;

        for _ in 0..50 {
            accumulator = accumulator
                .add(Fr::rand(&mut rng), &secret_key, &initial_elems, &mut state)
                .unwrap();
        }

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            let w = accumulator
                .get_non_membership_witness(&elem, &secret_key, &mut state, &params)
                .unwrap();
            let correctness_proof = NonMembershipWitnessCorrectnessProof::new::<StdRng, Blake2b512>(
                &mut rng,
                accumulator.value(),
                &w,
                &elem,
                secret_key.clone(),
                &public_key,
                &params,
            );
            correctness_proof
                .verify::<Blake2b512>(accumulator.value(), &w, &elem, &public_key, &params)
                .unwrap();
            elems.push(elem);
            witnesses.push(w);
        }

        let mut proof_create_duration = Duration::default();
        let mut proof_verif_duration = Duration::default();

        for i in 0..count {
            let start = Instant::now();
            let protocol = NonMembershipProofProtocol::init(
                &mut rng,
                elems[i].clone(),
                None,
                &witnesses[i],
                accumulator.value().clone(),
                &params,
                &Q,
            );
            proof_create_duration += start.elapsed();

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(accumulator.value(), &params, &Q, &mut chal_bytes_prover)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(accumulator.value(), &params, &Q, &mut chal_bytes_verifier)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
            assert_eq!(challenge_prover, challenge_verifier);

            // TODO: uncomment
            // test_serialization!(NonMembershipProof<G1Affine>, proof);

            let start = Instant::now();
            proof
                .verify(
                    accumulator.value().clone(),
                    &secret_key,
                    &challenge_verifier,
                    &params,
                    &Q,
                )
                .unwrap();
            proof_verif_duration += start.elapsed();

            proof
                .verify_schnorr_proof(
                    accumulator.value().clone(),
                    &challenge_verifier,
                    &params,
                    &Q,
                )
                .unwrap();
            let keyed_proof = proof.to_keyed_proof();
            keyed_proof.verify(&secret_key).unwrap();

            let mut invalid_keyed_proof = keyed_proof.clone();
            invalid_keyed_proof.0.C = G1Affine::rand(&mut rng);

            let proof_of_validity = keyed_proof.create_proof_of_validity::<_, Blake2b512>(
                &mut rng,
                &secret_key,
                &public_key,
                &params,
            );
            proof_of_validity
                .verify::<Blake2b512>(&keyed_proof, &public_key, &params)
                .unwrap();
            assert!(proof_of_validity
                .verify::<Blake2b512>(&invalid_keyed_proof, &public_key, &params)
                .is_err());

            let proof_of_invalidity = invalid_keyed_proof
                .create_proof_of_invalidity::<_, Blake2b512>(
                    &mut rng,
                    &secret_key,
                    &public_key,
                    &params,
                )
                .unwrap();
            proof_of_invalidity
                .verify::<Blake2b512>(&invalid_keyed_proof, &public_key, &params)
                .unwrap();
            assert!(proof_of_invalidity
                .verify::<Blake2b512>(&keyed_proof, &public_key, &params)
                .is_err());
        }

        println!(
            "Time to create {} non-membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} non-membership proofs is {:?}",
            count, proof_verif_duration
        );
    }
}
