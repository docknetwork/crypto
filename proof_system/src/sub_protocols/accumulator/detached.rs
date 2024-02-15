use crate::{
    error::ProofSystemError,
    prelude::{
        DetachedAccumulatorMembershipProof, DetachedAccumulatorNonMembershipProof, StatementProof,
    },
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec, vec::Vec, UniformRand};
use chacha20poly1305::XChaCha20Poly1305;
use dock_crypto_utils::ecies;
use vb_accumulator::prelude::{
    MembershipProofProtocol, MembershipProvingKey, NonMembershipProofProtocol,
    NonMembershipProvingKey, PreparedPublicKey, PreparedSetupParams, PublicKey,
    SetupParams as AccumParams,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedAccumulatorMembershipSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E>,
    pub proving_key: &'a MembershipProvingKey<E::G1Affine>,
    pub original_accumulator_value: Option<E::G1Affine>,
    pub randomized_accumulator_value: Option<E::G1Affine>,
    pub randomizer: Option<E::ScalarField>,
    pub protocol: Option<MembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedAccumulatorNonMembershipSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E>,
    pub proving_key: &'a NonMembershipProvingKey<E::G1Affine>,
    pub original_accumulator_value: Option<E::G1Affine>,
    pub randomized_accumulator_value: Option<E::G1Affine>,
    pub randomizer: Option<E::ScalarField>,
    pub protocol: Option<NonMembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Opening<G: AffineRepr> {
    pub original_accumulator: G,
    pub randomizer: G::ScalarField,
    pub extra: Option<Vec<u8>>,
}

impl<'a, E: Pairing> DetachedAccumulatorMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E>,
        proving_key: &'a MembershipProvingKey<E::G1Affine>,
    ) -> Self {
        Self {
            id,
            params,
            public_key,
            proving_key,
            original_accumulator_value: None,
            randomizer: None,
            randomized_accumulator_value: None,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        accumulator_value: E::G1Affine,
        blinding: Option<E::ScalarField>,
        witness: crate::witness::Membership<E::G1Affine>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        // Randomize the accumulator and witness with the same value
        let randomizer = E::ScalarField::rand(rng);
        let randomized_accumulator_value = (accumulator_value * randomizer).into_affine();
        let randomized_accum_witness = witness.witness.randomize(&randomizer);
        let protocol = MembershipProofProtocol::init(
            rng,
            witness.element,
            blinding,
            &randomized_accum_witness,
            self.public_key,
            self.params,
            self.proving_key,
        );
        self.protocol = Some(protocol);
        self.original_accumulator_value = Some(accumulator_value);
        self.randomizer = Some(randomizer);
        self.randomized_accumulator_value = Some(randomized_accumulator_value);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            self.randomized_accumulator_value.as_ref().take().unwrap(),
            self.public_key,
            self.params,
            self.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<R: RngCore>(
        &mut self,
        rng: &mut R,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let accum_proof = protocol.gen_proof(challenge)?;
        // Encrypt the original accumulator value and the randomizer
        let opening = Opening {
            original_accumulator: self.original_accumulator_value.unwrap(),
            randomizer: self.randomizer.unwrap(),
            extra: None,
        };
        let mut opening_bytes = vec![];
        opening.serialize_compressed(&mut opening_bytes).unwrap();
        let encrypted = ecies::Encryption::encrypt::<R, XChaCha20Poly1305>(
            rng,
            &opening_bytes,
            &self.public_key.0,
            &self.params.P_tilde,
            None,
            None,
        );
        Ok(StatementProof::DetachedAccumulatorMembership(
            DetachedAccumulatorMembershipProof {
                accumulator: self.randomized_accumulator_value.unwrap(),
                accum_proof,
                challenge: *challenge,
                encrypted,
            },
        ))
    }

    pub fn verify_proof_contribution(
        &self,
        proof: &DetachedAccumulatorMembershipProof<E>,
        sk: &vb_accumulator::setup::SecretKey<E::ScalarField>,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), ProofSystemError> {
        // Decrypt the opening
        let decrypted = proof
            .encrypted
            .clone()
            .decrypt::<XChaCha20Poly1305>(&sk.0, None, None);
        let opening: Opening<E::G1Affine> =
            CanonicalDeserialize::deserialize_compressed(decrypted.as_slice()).unwrap();
        proof
            .accum_proof
            .verify(
                &proof.accumulator,
                &proof.challenge,
                pk,
                params,
                self.proving_key,
            )
            .map_err(|e| {
                ProofSystemError::DetachedVBAccumProofContributionFailed(self.id as u32, e)
            })?;
        // Check that the randomized accumulator is consistent with the original accumulator
        if (opening.original_accumulator * opening.randomizer).into_affine() != proof.accumulator {
            Err(ProofSystemError::IncorrectEncryptedAccumulator)
        } else {
            Ok(())
        }
    }
}

impl<'a, E: Pairing> DetachedAccumulatorNonMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E>,
        proving_key: &'a NonMembershipProvingKey<E::G1Affine>,
    ) -> Self {
        Self {
            id,
            params,
            public_key,
            proving_key,
            original_accumulator_value: None,
            randomizer: None,
            randomized_accumulator_value: None,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        accumulator_value: E::G1Affine,
        blinding: Option<E::ScalarField>,
        witness: crate::witness::NonMembership<E::G1Affine>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        // Randomize the accumulator and witness with the same value
        let randomizer = E::ScalarField::rand(rng);
        let randomized_accumulator_value = (accumulator_value * randomizer).into_affine();
        let randomized_accum_witness = witness.witness.randomize(&randomizer);
        let protocol = NonMembershipProofProtocol::init(
            rng,
            witness.element,
            blinding,
            &randomized_accum_witness,
            self.public_key,
            self.params,
            self.proving_key,
        );
        self.protocol = Some(protocol);
        self.original_accumulator_value = Some(accumulator_value);
        self.randomizer = Some(randomizer);
        self.randomized_accumulator_value = Some(randomized_accumulator_value);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            self.randomized_accumulator_value.as_ref().take().unwrap(),
            self.public_key,
            self.params,
            self.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<R: RngCore>(
        &mut self,
        rng: &mut R,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let accum_proof = protocol.gen_proof(challenge)?;
        // Encrypt the original accumulator value and the randomizer
        let opening = Opening {
            original_accumulator: self.original_accumulator_value.unwrap(),
            randomizer: self.randomizer.unwrap(),
            extra: None,
        };
        let mut opening_bytes = vec![];
        opening.serialize_compressed(&mut opening_bytes).unwrap();
        let encrypted = ecies::Encryption::encrypt::<R, XChaCha20Poly1305>(
            rng,
            &opening_bytes,
            &self.public_key.0,
            &self.params.P_tilde,
            None,
            None,
        );
        Ok(StatementProof::DetachedAccumulatorNonMembership(
            DetachedAccumulatorNonMembershipProof {
                accumulator: self.randomized_accumulator_value.unwrap(),
                accum_proof,
                challenge: *challenge,
                encrypted,
            },
        ))
    }

    pub fn verify_proof_contribution(
        &self,
        proof: &DetachedAccumulatorNonMembershipProof<E>,
        sk: &vb_accumulator::setup::SecretKey<E::ScalarField>,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), ProofSystemError> {
        // Decrypt the opening
        let decrypted = proof
            .encrypted
            .clone()
            .decrypt::<XChaCha20Poly1305>(&sk.0, None, None);
        let opening: Opening<E::G1Affine> =
            CanonicalDeserialize::deserialize_compressed(decrypted.as_slice()).unwrap();
        proof
            .accum_proof
            .verify(
                &proof.accumulator,
                &proof.challenge,
                pk,
                params,
                self.proving_key,
            )
            .map_err(|e| {
                ProofSystemError::DetachedVBAccumProofContributionFailed(self.id as u32, e)
            })?;
        // Check that the randomized accumulator is consistent with the original accumulator
        if (opening.original_accumulator * opening.randomizer).into_affine() != proof.accumulator {
            Err(ProofSystemError::IncorrectEncryptedAccumulator)
        } else {
            Ok(())
        }
    }
}
