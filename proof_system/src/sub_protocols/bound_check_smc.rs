use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec, UniformRand};

use crate::{
    error::ProofSystemError,
    prelude::bound_check_smc::SmcParamsWithPairingAndCommitmentKey,
    statement::bound_check_smc::SmcParamsAndCommitmentKey,
    statement_proof::{BoundCheckSmcInnerProof, BoundCheckSmcProof, StatementProof},
    sub_protocols::{enforce_and_get_u64, schnorr::SchnorrProtocol, should_use_cls},
};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use smc_range_proof::prelude::{CCSArbitraryRangeProofProtocol, CLSRangeProofProtocol};

#[derive(Clone, Debug, PartialEq)]
pub enum SmcProtocol<E: Pairing> {
    CCS(CCSArbitraryRangeProofProtocol<E>),
    CLS(CLSRangeProofProtocol<E>),
}

/// Runs the set-membership check based protocol for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the commitments accompanying the proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckSmcProtocol<'a, E: Pairing> {
    pub id: usize,
    pub min: u64,
    pub max: u64,
    pub params_and_comm_key: &'a SmcParamsAndCommitmentKey<E>,
    pub comm: Option<E::G1Affine>,
    pub smc_protocol: Option<SmcProtocol<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: Pairing> BoundCheckSmcProtocol<'a, E> {
    pub fn new(id: usize, min: u64, max: u64, params: &'a SmcParamsAndCommitmentKey<E>) -> Self {
        Self {
            id,
            min,
            max,
            params_and_comm_key: params,
            comm: None,
            smc_protocol: None,
            sp: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key_as_slice: &'a [E::G1Affine],
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let msg_as_u64 = enforce_and_get_u64::<E::ScalarField>(&message)?;
        let randomness = E::ScalarField::rand(rng);
        let comm_key = &self.params_and_comm_key.comm_key;
        self.comm = Some(comm_key.commit(&message, &randomness));
        let smc_protocol = if should_use_cls(self.min, self.max) {
            let p = CLSRangeProofProtocol::init(
                rng,
                msg_as_u64,
                randomness.clone(),
                self.min,
                self.max,
                comm_key,
                &self.params_and_comm_key.params,
            )?;
            SmcProtocol::CLS(p)
        } else {
            let p = CCSArbitraryRangeProofProtocol::init(
                rng,
                msg_as_u64,
                randomness.clone(),
                self.min,
                self.max,
                comm_key,
                &self.params_and_comm_key.params,
            )?;
            SmcProtocol::CCS(p)
        };
        self.smc_protocol = Some(smc_protocol);
        self.init_schnorr_protocol(rng, comm_key_as_slice, message, blinding, randomness)
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [E::G1Affine],
        message: E::ScalarField,
        blinding: Option<E::ScalarField>,
        blinding_for_smc: E::ScalarField,
    ) -> Result<(), ProofSystemError> {
        let blinding = if blinding.is_none() {
            E::ScalarField::rand(rng)
        } else {
            blinding.unwrap()
        };
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);

        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, &comm_key, self.comm.unwrap());
        sp.init(rng, blindings.clone(), vec![message, blinding_for_smc])?;
        self.sp = Some(sp);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        let comm_key = &self.params_and_comm_key.comm_key;
        match &self.smc_protocol {
            Some(SmcProtocol::CCS(c)) => c.challenge_contribution(
                self.comm.as_ref().unwrap(),
                comm_key,
                &self.params_and_comm_key.params,
                &mut writer,
            )?,
            Some(SmcProtocol::CLS(c)) => c.challenge_contribution(
                self.comm.as_ref().unwrap(),
                comm_key,
                &self.params_and_comm_key.params,
                &mut writer,
            )?,
            None => {
                return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                    self.id,
                ))
            }
        }
        self.sp
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let proof = match self.smc_protocol.take().unwrap() {
            SmcProtocol::CCS(c) => {
                let p = c.gen_proof(challenge);
                BoundCheckSmcInnerProof::CCS(p)
            }
            SmcProtocol::CLS(c) => {
                let p = c.gen_proof(challenge);
                BoundCheckSmcInnerProof::CLS(p)
            }
        };
        Ok(StatementProof::BoundCheckSmc(BoundCheckSmcProof {
            proof,
            comm: self.comm.take().unwrap(),
            sp: self
                .sp
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &BoundCheckSmcProof<E>,
        comm_key_as_slice: &[E::G1Affine],
        params: SmcParamsWithPairingAndCommitmentKey<E>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        let comm_key = &self.params_and_comm_key.comm_key;
        match &proof.proof {
            BoundCheckSmcInnerProof::CCS(c) => match pairing_checker {
                Some(pc) => c
                    .verify_given_randomized_pairing_checker(
                        &proof.comm,
                        challenge,
                        self.min,
                        self.max,
                        comm_key,
                        params.params,
                        pc,
                    )
                    .map_err(|e| {
                        ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e)
                    })?,
                None => c
                    .verify(
                        &proof.comm,
                        challenge,
                        self.min,
                        self.max,
                        comm_key,
                        params.params,
                    )
                    .map_err(|e| {
                        ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e)
                    })?,
            },
            BoundCheckSmcInnerProof::CLS(c) => match pairing_checker {
                Some(pc) => c
                    .verify_given_randomized_pairing_checker(
                        &proof.comm,
                        challenge,
                        self.min,
                        self.max,
                        comm_key,
                        params.params,
                        pc,
                    )
                    .map_err(|e| {
                        ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e)
                    })?,
                None => c
                    .verify(
                        &proof.comm,
                        challenge,
                        self.min,
                        self.max,
                        comm_key,
                        params.params,
                    )
                    .map_err(|e| {
                        ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e)
                    })?,
            },
        }

        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key_as_slice, proof.comm);

        sp.verify_proof_contribution(challenge, &proof.sp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key_as_slice: &[E::G1Affine],
        proof: &BoundCheckSmcProof<E>,
        params: &SmcParamsAndCommitmentKey<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        let comm_key = &params.comm_key;
        match &proof.proof {
            BoundCheckSmcInnerProof::CCS(c) => {
                c.challenge_contribution(&proof.comm, comm_key, &params.params, &mut writer)?
            }
            BoundCheckSmcInnerProof::CLS(c) => {
                c.challenge_contribution(&proof.comm, comm_key, &params.params, &mut writer)?
            }
        }
        comm_key_as_slice.serialize_compressed(&mut writer)?;
        proof.comm.serialize_compressed(&mut writer)?;
        proof.sp.t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}
