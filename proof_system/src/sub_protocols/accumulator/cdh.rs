#![allow(non_snake_case)]
//! Membership and non-membership protocols using CDH approach with BB and weak-BB signatures

use crate::{error::ProofSystemError, statement_proof::StatementProof};
use ark_ec::pairing::Pairing;
use ark_std::{io::Write, rand::RngCore};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use short_group_sig::common::ProvingKey;
use vb_accumulator::{
    kb_positive_accumulator::{
        proofs_cdh::{
            KBPositiveAccumulatorMembershipProof as KBPosMemProof,
            KBPositiveAccumulatorMembershipProofProtocol as KBPosMemProtocol,
            KBPositiveAccumulatorMembershipProofProtocol,
        },
        setup::{
            PreparedPublicKey as KBAccumPreparedPk, PreparedSetupParams as KBAccumPreparedParams,
            PublicKey as KBAccumPk, SetupParams as KBAccumParams,
        },
    },
    kb_universal_accumulator::proofs_cdh::{
        KBUniversalAccumulatorMembershipProof as KBUniMemProof,
        KBUniversalAccumulatorMembershipProofProtocol as KBUniMemProtocol,
        KBUniversalAccumulatorNonMembershipProof as KBUniNonMemProof,
        KBUniversalAccumulatorNonMembershipProofProtocol as KBUniNonMemProtocol,
    },
    proofs_cdh::{
        MembershipProof as VBMemProof, MembershipProofProtocol as VBMemProtocol,
        NonMembershipProof as VBNonMemProof, NonMembershipProofProtocol as VBNonMemProtocol,
    },
    setup::{PreparedPublicKey, PreparedSetupParams, PublicKey, SetupParams as AccumParams},
};

macro_rules! impl_cdh_protocol_struct_and_funcs {
    ($(#[$doc:meta])*
    $name: ident, $statement_proof_variant: ident, $witness_type: ident, $wit_group: path, $protocol: ident, $proof: ident, $error_type: ident) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name<'a, E: Pairing> {
            pub id: usize,
            pub accumulator_value: E::G1Affine,
            pub params: Option<&'a AccumParams<E>>,
            pub public_key: Option<&'a PublicKey<E>>,
            pub protocol: Option<$protocol<E>>,
        }

        impl<'a, E: Pairing> $name<'a, E> {
            pub fn new_for_prover(id: usize, accumulator_value: E::G1Affine) -> Self {
                Self {
                    id,
                    accumulator_value,
                    params: None,
                    public_key: None,
                    protocol: None,
                }
            }

            pub fn new_for_verifier(
                id: usize,
                accumulator_value: E::G1Affine,
                params: &'a AccumParams<E>,
                public_key: &'a PublicKey<E>,
            ) -> Self {
                Self {
                    id,
                    accumulator_value,
                    params: Some(params),
                    public_key: Some(public_key),
                    protocol: None,
                }
            }

            pub fn init<R: RngCore>(
                &mut self,
                rng: &mut R,
                blinding: Option<E::ScalarField>,
                witness: crate::witness::$witness_type<$wit_group>,
            ) -> Result<(), ProofSystemError> {
                if self.protocol.is_some() {
                    return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
                }
                self.protocol = Some($protocol::init(
                    rng,
                    witness.element,
                    blinding,
                    &self.accumulator_value,
                    &witness.witness,
                ));
                Ok(())
            }

            pub fn challenge_contribution<W: Write>(
                &self,
                writer: W,
            ) -> Result<(), ProofSystemError> {
                if self.protocol.is_none() {
                    return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                        self.id,
                    ));
                }
                self.protocol
                    .as_ref()
                    .unwrap()
                    .challenge_contribution(&self.accumulator_value, writer)?;
                Ok(())
            }

            pub fn gen_proof_contribution(
                &mut self,
                challenge: &E::ScalarField,
            ) -> Result<StatementProof<E>, ProofSystemError> {
                if self.protocol.is_none() {
                    return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                        self.id,
                    ));
                }
                let protocol = self.protocol.take().unwrap();
                let proof = protocol.gen_proof(challenge)?;
                Ok(StatementProof::$statement_proof_variant(proof))
            }

            pub fn verify_proof_contribution(
                &self,
                challenge: &E::ScalarField,
                proof: &$proof<E>,
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
                        c,
                    ),
                    None => proof.verify(&self.accumulator_value, challenge, pk, params),
                }
                .map_err(|e| ProofSystemError::$error_type(self.id as u32, e))
            }
        }
    };
}

impl_cdh_protocol_struct_and_funcs!(
    VBAccumulatorMembershipCDHSubProtocol,
    VBAccumulatorMembershipCDH,
    Membership,
    E::G1Affine,
    VBMemProtocol,
    VBMemProof,
    VBAccumProofContributionFailed
);

impl_cdh_protocol_struct_and_funcs!(
    KBUniversalAccumulatorMembershipCDHSubProtocol,
    KBUniversalAccumulatorMembershipCDH,
    KBUniMembership,
    E::G1Affine,
    KBUniMemProtocol,
    KBUniMemProof,
    KBAccumProofContributionFailed
);

impl_cdh_protocol_struct_and_funcs!(
    KBUniversalAccumulatorNonMembershipCDHSubProtocol,
    KBUniversalAccumulatorNonMembershipCDH,
    KBUniNonMembership,
    E::G1Affine,
    KBUniNonMemProtocol,
    KBUniNonMemProof,
    KBAccumProofContributionFailed
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VBAccumulatorNonMembershipCDHSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub accumulator_value: E::G1Affine,
    pub Q: E::G1Affine,
    pub params: &'a AccumParams<E>,
    pub public_key: Option<&'a PublicKey<E>>,
    pub protocol: Option<VBNonMemProtocol<E>>,
}

impl<'a, E: Pairing> VBAccumulatorNonMembershipCDHSubProtocol<'a, E> {
    pub fn new_for_prover(
        id: usize,
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
        params: &'a AccumParams<E>,
    ) -> Self {
        Self {
            id,
            accumulator_value,
            Q,
            params,
            public_key: None,
            protocol: None,
        }
    }

    pub fn new_for_verifier(
        id: usize,
        accumulator_value: E::G1Affine,
        Q: E::G1Affine,
        params: &'a AccumParams<E>,
        public_key: &'a PublicKey<E>,
    ) -> Self {
        Self {
            id,
            accumulator_value,
            Q,
            params,
            public_key: Some(public_key),
            protocol: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        blinding: Option<E::ScalarField>,
        witness: crate::witness::NonMembership<E::G1Affine>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        self.protocol = Some(VBNonMemProtocol::init(
            rng,
            witness.element,
            blinding,
            self.accumulator_value,
            &witness.witness,
            &self.params,
            self.Q,
        ));
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
            &self.params,
            &self.Q,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge)?;
        Ok(StatementProof::VBAccumulatorNonMembershipCDH(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &VBNonMemProof<E>,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        match pairing_checker {
            Some(c) => proof.verify_with_randomized_pairing_checker(
                self.accumulator_value,
                challenge,
                pk,
                params,
                self.Q,
                c,
            ),
            None => proof.verify(self.accumulator_value, challenge, pk, params, self.Q),
        }
        .map_err(|e| ProofSystemError::VBAccumProofContributionFailed(self.id as u32, e))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KBPositiveAccumulatorMembershipCDHSubProtocol<'a, E: Pairing> {
    pub id: usize,
    pub accumulator_value: E::G1Affine,
    pub params: &'a KBAccumParams<E>,
    pub public_key: &'a KBAccumPk<E>,
    pub proving_key: &'a ProvingKey<E::G1Affine>,
    pub protocol: Option<KBPosMemProtocol<E>>,
}

impl<'a, E: Pairing> KBPositiveAccumulatorMembershipCDHSubProtocol<'a, E> {
    pub fn new(
        id: usize,
        params: &'a KBAccumParams<E>,
        public_key: &'a KBAccumPk<E>,
        proving_key: &'a ProvingKey<E::G1Affine>,
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
        witness: crate::witness::KBPosMembership<E>,
    ) -> Result<(), ProofSystemError> {
        if self.protocol.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let protocol = KBPositiveAccumulatorMembershipProofProtocol::init(
            rng,
            witness.element,
            blinding,
            &witness.witness,
            &self.accumulator_value,
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

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.protocol.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let protocol = self.protocol.take().unwrap();
        let proof = protocol.gen_proof(challenge)?;
        Ok(StatementProof::KBPositiveAccumulatorMembershipCDH(proof))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &KBPosMemProof<E>,
        pk: impl Into<KBAccumPreparedPk<E>>,
        params: impl Into<KBAccumPreparedParams<E>>,
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
            ),
            None => proof.verify(
                &self.accumulator_value,
                challenge,
                pk,
                params,
                self.proving_key,
            ),
        }
        .map_err(|e| ProofSystemError::KBAccumProofContributionFailed(self.id as u32, e))
    }
}
