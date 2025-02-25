use crate::{
    error::ProofSystemError,
    prelude::bound_check_smc_with_kv::SmcParamsKVAndCommitmentKeyAndSecretKey,
    statement::bound_check_smc_with_kv::SmcParamsKVAndCommitmentKey,
    statement_proof::{BoundCheckSmcWithKVInnerProof, BoundCheckSmcWithKVProof, StatementProof},
    sub_protocols::{enforce_and_get_u64, schnorr::SchnorrProtocol},
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec, UniformRand,
};
use smc_range_proof::{
    ccs_range_proof::kv_arbitrary_range::CCSArbitraryRangeProofWithKVProtocol,
    prelude::CLSRangeProofWithKVProtocol,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SmcProtocolWithKV<G: AffineRepr> {
    CCS(CCSArbitraryRangeProofWithKVProtocol<G>),
    CLS(CLSRangeProofWithKVProtocol<G>),
}

/// Runs the set-membership check based protocol with keyed-verification for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the commitments accompanying the proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckSmcWithKVProtocol<'a, G: AffineRepr> {
    pub id: usize,
    pub min: u64,
    pub max: u64,
    pub params_and_comm_key: Option<&'a SmcParamsKVAndCommitmentKey<G>>,
    pub params_and_comm_key_and_sk: Option<&'a SmcParamsKVAndCommitmentKeyAndSecretKey<G>>,
    pub comm: Option<G>,
    pub smc_protocol: Option<SmcProtocolWithKV<G>>,
    pub sp: Option<SchnorrProtocol<'a, G>>,
}

impl<'a, G: AffineRepr> BoundCheckSmcWithKVProtocol<'a, G> {
    pub fn new_for_prover(
        id: usize,
        min: u64,
        max: u64,
        params: &'a SmcParamsKVAndCommitmentKey<G>,
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
        params: &'a SmcParamsKVAndCommitmentKeyAndSecretKey<G>,
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
        comm_key_as_slice: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let params = self
            .params_and_comm_key
            .ok_or(ProofSystemError::SmcParamsNotProvided)?;
        let msg_as_u64 = enforce_and_get_u64::<G::ScalarField>(&message)?;
        let randomness = G::ScalarField::rand(rng);
        let comm_key = &params.comm_key;
        self.comm = Some(comm_key.commit(&message, &randomness));
        let p = CLSRangeProofWithKVProtocol::init(
            rng,
            msg_as_u64,
            randomness.clone(),
            self.min,
            self.max,
            comm_key,
            &params.params,
        )?;

        self.smc_protocol = Some(SmcProtocolWithKV::CLS(p));
        self.init_schnorr_protocol(rng, comm_key_as_slice, message, blinding, randomness)
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
        blinding_for_smc: G::ScalarField,
    ) -> Result<(), ProofSystemError> {
        let blinding = if blinding.is_none() {
            G::ScalarField::rand(rng)
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

    pub fn gen_proof_contribution<E: Pairing<G1Affine = G>>(
        &mut self,
        challenge: &G::ScalarField,
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
        // Don't generate response for index 0 since its response will come from proofs of one of the signatures.
        let skip_for = BTreeSet::from([0]);
        Ok(StatementProof::BoundCheckSmcWithKV(
            BoundCheckSmcWithKVProof {
                proof,
                comm: self.comm.take().unwrap(),
                sp: self
                    .sp
                    .take()
                    .unwrap()
                    .gen_partial_proof_contribution_as_struct(challenge, &skip_for)?,
            },
        ))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &BoundCheckSmcWithKVProof<G>,
        comm_key_as_slice: &[G],
        resp_for_message: G::ScalarField,
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
        let missing_resp = BTreeMap::from([(0, resp_for_message)]);
        sp.verify_partial_proof_contribution(challenge, &proof.sp, missing_resp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key_as_slice: &[G],
        proof: &BoundCheckSmcWithKVProof<G>,
        params: &SmcParamsKVAndCommitmentKeyAndSecretKey<G>,
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
