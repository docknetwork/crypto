use crate::{
    error::ProofSystemError,
    prelude::bound_check_smc_with_kv::SmcParamsAndCommitmentKeyAndSecretKey,
    statement::bound_check_smc::SmcParamsAndCommitmentKey,
    statement_proof::{BoundCheckSmcWithKVInnerProof, BoundCheckSmcWithKVProof, StatementProof},
    sub_protocols::{enforce_and_get_u64, schnorr::SchnorrProtocol, should_use_cls},
};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec, UniformRand};
use smc_range_proof::{
    ccs_range_proof::kv_arbitrary_range::CCSArbitraryRangeProofWithKVProtocol,
    prelude::CLSRangeProofWithKVProtocol,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SmcProtocolWithKV<E: Pairing> {
    CCS(CCSArbitraryRangeProofWithKVProtocol<E>),
    CLS(CLSRangeProofWithKVProtocol<E>),
}

/// Runs the set-membership check based protocol with keyed-verification for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the commitments accompanying the proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckSmcWithKVProtocol<'a, E: Pairing> {
    pub id: usize,
    pub min: u64,
    pub max: u64,
    pub params_and_comm_key: Option<&'a SmcParamsAndCommitmentKey<E>>,
    pub params_and_comm_key_and_sk: Option<&'a SmcParamsAndCommitmentKeyAndSecretKey<E>>,
    pub comm: Option<E::G1Affine>,
    pub smc_protocol: Option<SmcProtocolWithKV<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: Pairing> BoundCheckSmcWithKVProtocol<'a, E> {
    pub fn new_for_prover(
        id: usize,
        min: u64,
        max: u64,
        params: &'a SmcParamsAndCommitmentKey<E>,
    ) -> Self {
        Self {
            id,
            min,
            max,
            params_and_comm_key: Some(params),
            params_and_comm_key_and_sk: None,
            comm: None,
            smc_protocol: None,
            sp: None,
        }
    }

    pub fn new_for_verifier(
        id: usize,
        min: u64,
        max: u64,
        params: &'a SmcParamsAndCommitmentKeyAndSecretKey<E>,
    ) -> Self {
        Self {
            id,
            min,
            max,
            params_and_comm_key: None,
            params_and_comm_key_and_sk: Some(params),
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
        let params = self
            .params_and_comm_key
            .ok_or(ProofSystemError::SmcParamsNotProvided)?;
        let msg_as_u64 = enforce_and_get_u64::<E::ScalarField>(&message)?;
        let randomness = E::ScalarField::rand(rng);
        let comm_key = &params.comm_key;
        self.comm = Some(comm_key.commit(&message, &randomness));
        let smc_protocol = if should_use_cls(self.min, self.max) {
            let p = CLSRangeProofWithKVProtocol::init(
                rng,
                msg_as_u64,
                randomness.clone(),
                self.min,
                self.max,
                comm_key,
                &params.params,
            )?;
            SmcProtocolWithKV::CLS(p)
        } else {
            let p = CCSArbitraryRangeProofWithKVProtocol::init(
                rng,
                msg_as_u64,
                randomness.clone(),
                self.min,
                self.max,
                comm_key,
                &params.params,
            )?;
            SmcProtocolWithKV::CCS(p)
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
        let params = self
            .params_and_comm_key
            .ok_or(ProofSystemError::SmcParamsNotProvided)?;
        let comm_key = &params.comm_key;
        match &self.smc_protocol {
            Some(SmcProtocolWithKV::CCS(c)) => c.challenge_contribution(
                self.comm.as_ref().unwrap(),
                comm_key,
                &params.params,
                &mut writer,
            )?,
            Some(SmcProtocolWithKV::CLS(c)) => c.challenge_contribution(
                self.comm.as_ref().unwrap(),
                comm_key,
                &params.params,
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
            SmcProtocolWithKV::CCS(c) => {
                let p = c.gen_proof(challenge);
                BoundCheckSmcWithKVInnerProof::CCS(p)
            }
            SmcProtocolWithKV::CLS(c) => {
                let p = c.gen_proof(challenge);
                BoundCheckSmcWithKVInnerProof::CLS(p)
            }
        };
        Ok(StatementProof::BoundCheckSmcWithKV(
            BoundCheckSmcWithKVProof {
                proof,
                comm: self.comm.take().unwrap(),
                sp: self
                    .sp
                    .take()
                    .unwrap()
                    .gen_proof_contribution_as_struct(challenge)?,
            },
        ))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &BoundCheckSmcWithKVProof<E>,
        comm_key_as_slice: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        let params = self
            .params_and_comm_key_and_sk
            .ok_or(ProofSystemError::SmcParamsNotProvided)?;
        let comm_key = params.get_comm_key();
        match &proof.proof {
            BoundCheckSmcWithKVInnerProof::CCS(c) => {
                c.verify(
                    &proof.comm,
                    challenge,
                    self.min,
                    self.max,
                    comm_key,
                    params.get_smc_params(),
                    &params.sk,
                )
                .map_err(|e| ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e))?
            }
            BoundCheckSmcWithKVInnerProof::CLS(c) => {
                c.verify(
                    &proof.comm,
                    challenge,
                    self.min,
                    self.max,
                    comm_key,
                    params.get_smc_params(),
                    &params.sk,
                )
                .map_err(|e| ProofSystemError::SmcRangeProofContributionFailed(self.id as u32, e))?
            }
        }

        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key_as_slice, proof.comm);

        sp.verify_proof_contribution(challenge, &proof.sp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key_as_slice: &[E::G1Affine],
        proof: &BoundCheckSmcWithKVProof<E>,
        params: &SmcParamsAndCommitmentKeyAndSecretKey<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        let comm_key = params.get_comm_key();
        let get_smc_params = params.get_smc_params();
        match &proof.proof {
            BoundCheckSmcWithKVInnerProof::CCS(c) => {
                c.challenge_contribution(&proof.comm, comm_key, get_smc_params, &mut writer)?
            }
            BoundCheckSmcWithKVInnerProof::CLS(c) => {
                c.challenge_contribution(&proof.comm, comm_key, get_smc_params, &mut writer)?
            }
        }
        comm_key_as_slice.serialize_compressed(&mut writer)?;
        proof.comm.serialize_compressed(&mut writer)?;
        proof.sp.t.serialize_compressed(&mut writer)?;
        Ok(())
    }
}
