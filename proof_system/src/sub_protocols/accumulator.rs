use crate::{error::ProofSystemError, statement_proof::StatementProof};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{io::Write, rand::RngCore};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use vb_accumulator::prelude::{
    MembershipProof, MembershipProofProtocol, MembershipProvingKey, NonMembershipProof,
    NonMembershipProofProtocol, NonMembershipProvingKey, PreparedPublicKey, PreparedSetupParams,
    PublicKey, SetupParams as AccumParams,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorMembershipSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E>,
    pub proving_key: &'a MembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
    pub protocol: Option<MembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorNonMembershipSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E>,
    pub proving_key: &'a NonMembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
    pub protocol: Option<NonMembershipProofProtocol<E>>,
}

impl<'a, E: Pairing> AccumulatorMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E>,
        proving_key: &'a MembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Self {
        Self {
            id,
            params,
            public_key,
            proving_key,
            accumulator_value,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::ScalarField>,
        witness: crate::witness::Membership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = MembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            self.public_key,
            self.params,
            self.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            &self.accumulator_value,
            self.public_key,
            self.params,
            self.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<G: AffineRepr>(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge);
        Ok(StatementProof::AccumulatorMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &MembershipProof<E>,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                &self.accumulator_value,
                challenge,
                pk,
                params,
                self.proving_key,
                c,
            )?,
            None => proof.verify(
                &self.accumulator_value,
                challenge,
                pk,
                params,
                self.proving_key,
            )?,
        }
        Ok(())
    }
}

impl<'a, E: Pairing> AccumulatorNonMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E>,
        proving_key: &'a NonMembershipProvingKey<E::G1Affine>,
        accumulator_value: E::G1Affine,
    ) -> Self {
        Self {
            id,
            params,
            public_key,
            proving_key,
            accumulator_value,
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::ScalarField>,
        witness: crate::witness::NonMembership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = NonMembershipProofProtocol::init(
            rng,
            &witness.element,
            blinding,
            &witness.witness,
            self.public_key,
            self.params,
            self.proving_key,
        );
        self.protocol = Some(protocol);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.protocol.as_ref().unwrap().challenge_contribution(
            &self.accumulator_value,
            self.public_key,
            self.params,
            self.proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution<G: AffineRepr>(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge);
        Ok(StatementProof::AccumulatorNonMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &NonMembershipProof<E>,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                &self.accumulator_value,
                challenge,
                pk,
                params,
                self.proving_key,
                c,
            )?,
            None => proof.verify(
                &self.accumulator_value,
                challenge,
                pk,
                params,
                self.proving_key,
            )?,
        }
        Ok(())
    }
}
