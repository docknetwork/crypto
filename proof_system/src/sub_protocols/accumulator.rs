use crate::error::ProofSystemError;
use crate::statement_proof::StatementProof;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::io::Write;
use ark_std::rand::RngCore;
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use vb_accumulator::prelude::{
    MembershipProof, MembershipProofProtocol, MembershipProvingKey, NonMembershipProof,
    NonMembershipProofProtocol, NonMembershipProvingKey, PublicKey, SetupParams as AccumParams,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorMembershipSubProtocol<'a, E: PairingEngine> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E::G2Affine>,
    pub proving_key: &'a MembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
    pub protocol: Option<MembershipProofProtocol<E>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorNonMembershipSubProtocol<'a, E: PairingEngine> {
    pub id: usize,
    pub params: &'a AccumParams<E>,
    pub public_key: &'a PublicKey<E::G2Affine>,
    pub proving_key: &'a NonMembershipProvingKey<E::G1Affine>,
    pub accumulator_value: E::G1Affine,
    pub protocol: Option<NonMembershipProofProtocol<E>>,
}

impl<'a, E: PairingEngine> AccumulatorMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E::G2Affine>,
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
        blinding: Option<E::Fr>,
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

    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &MembershipProof<E>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                &self.accumulator_value,
                challenge,
                self.public_key,
                self.params,
                self.proving_key,
                c,
            )?,
            None => proof.verify(
                &self.accumulator_value,
                challenge,
                self.public_key,
                self.params,
                self.proving_key,
            )?,
        }
        Ok(())
    }
}

impl<'a, E: PairingEngine> AccumulatorNonMembershipSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E::G2Affine>,
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
        blinding: Option<E::Fr>,
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

    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(&challenge);
        Ok(StatementProof::AccumulatorNonMembership(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &NonMembershipProof<E>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                &self.accumulator_value,
                challenge,
                self.public_key,
                self.params,
                self.proving_key,
                c,
            )?,
            None => proof.verify(
                &self.accumulator_value,
                challenge,
                self.public_key,
                self.params,
                self.proving_key,
            )?,
        }
        Ok(())
    }
}
