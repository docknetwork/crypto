use crate::{
    error::ProofSystemError,
    statement_proof::{
        R1CSLegoGroth16Proof, R1CSLegoGroth16ProofWhenAggregatingSnarks, StatementProof,
    },
    sub_protocols::schnorr::SchnorrProtocol,
};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use legogroth16::{
    calculate_d,
    circom::{CircomCircuit, WitnessCalculator, R1CS},
    create_random_proof, rerandomize_proof_1, verify_proof, PreparedVerifyingKey, Proof,
    ProvingKey, VerifyingKey,
};

#[derive(Clone, Debug, PartialEq)]
pub struct R1CSLegogroth16Protocol<'a, E: Pairing> {
    pub id: usize,
    /// The SNARK proving key, will be `None` if invoked by verifier.
    pub proving_key: Option<&'a ProvingKey<E>>,
    /// The SNARK verifying key, will be `None` if invoked by prover.
    pub verifying_key: Option<&'a VerifyingKey<E>>,
    pub snark_proof: Option<Proof<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: Pairing> R1CSLegogroth16Protocol<'a, E> {
    /// Create an instance of this protocol for the prover.
    pub fn new_for_prover(id: usize, proving_key: &'a ProvingKey<E>) -> Self {
        Self {
            id,
            proving_key: Some(proving_key),
            verifying_key: None,
            snark_proof: None,
            sp: None,
        }
    }

    /// Create an instance of this protocol for the verifier.
    pub fn new_for_verifier(id: usize, verifying_key: &'a VerifyingKey<E>) -> Self {
        Self {
            id,
            proving_key: None,
            verifying_key: Some(verifying_key),
            snark_proof: None,
            sp: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        r1cs: R1CS<E>,
        wasm_bytes: &[u8],
        comm_key: &'a [E::G1Affine],
        witness: crate::witness::R1CSCircomWitness<E>,
        blindings: BTreeMap<usize, E::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;

        // blinding for the commitment in the snark proof
        let v = E::ScalarField::rand(rng);

        let mut wits_calc = WitnessCalculator::<E>::from_wasm_bytes(wasm_bytes)?;
        let wires = wits_calc.calculate_witnesses(witness.inputs.clone().into_iter(), true)?;
        let circuit = CircomCircuit {
            r1cs,
            wires: Some(wires),
        };
        let snark_proof = create_random_proof(circuit, v, proving_key, rng)?;

        self.init_schnorr_protocol(
            rng,
            comm_key,
            witness,
            blindings,
            proving_key.vk.commit_witness_count as u32,
            v,
            snark_proof,
        )
    }

    pub fn init_with_old_randomness_and_proof<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [E::G1Affine],
        witness: crate::witness::R1CSCircomWitness<E>,
        blindings: BTreeMap<usize, E::ScalarField>,
        old_v: E::ScalarField,
        proof: Proof<E>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;

        // new blinding for the commitment in the snark proof
        let v = E::ScalarField::rand(rng);

        let snark_proof = rerandomize_proof_1(
            &proof,
            old_v,
            v,
            &proving_key.vk,
            &proving_key.common.eta_delta_inv_g1,
            rng,
        );

        self.init_schnorr_protocol(
            rng,
            comm_key,
            witness,
            blindings,
            proving_key.vk.commit_witness_count as u32,
            v,
            snark_proof,
        )
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.sp
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }

    /// Generate responses for the Schnorr protocol
    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        Ok(StatementProof::R1CSLegoGroth16(R1CSLegoGroth16Proof {
            snark_proof: self.snark_proof.take().unwrap(),
            sp: self
                .sp
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    /// Verify that the snark proof and the Schnorr proof are valid.
    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        inputs: &[E::ScalarField],
        proof: &R1CSLegoGroth16Proof<E>,
        comm_key: &[E::G1Affine],
        pvk: &PreparedVerifyingKey<E>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        let snark_proof = &proof.snark_proof;
        match pairing_checker {
            Some(c) => {
                let d = calculate_d(pvk, snark_proof, inputs)?;
                c.add_multiple_sources_and_target(
                    &[snark_proof.a, snark_proof.c, d],
                    [
                        snark_proof.b.into(),
                        pvk.delta_g2_neg_pc.clone(),
                        pvk.gamma_g2_neg_pc.clone(),
                    ],
                    &pvk.alpha_g1_beta_g2,
                );
            }
            None => verify_proof(pvk, &proof.snark_proof, inputs).map_err(|e| {
                ProofSystemError::LegoSnarkProofContributionFailed(self.id as u32, e)
            })?,
        }

        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key, proof.snark_proof.d);

        sp.verify_proof_contribution(challenge, &proof.sp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn verify_proof_contribution_using_prepared_when_aggregating_snark(
        &self,
        challenge: &E::ScalarField,
        proof: &R1CSLegoGroth16ProofWhenAggregatingSnarks<E>,
        comm_key: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key, proof.commitment);
        sp.verify_proof_contribution(challenge, &proof.sp)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key: &[E::G1Affine],
        proof: &R1CSLegoGroth16Proof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        comm_key.serialize_compressed(&mut writer)?;
        proof.snark_proof.d.serialize_compressed(&mut writer)?;
        proof.sp.t.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn compute_challenge_contribution_when_aggregating_snark<W: Write>(
        comm_key: &[E::G1Affine],
        proof: &R1CSLegoGroth16ProofWhenAggregatingSnarks<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        comm_key.serialize_compressed(&mut writer)?;
        proof.commitment.serialize_compressed(&mut writer)?;
        proof.sp.t.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn schnorr_comm_key(vk: &VerifyingKey<E>) -> Vec<E::G1Affine> {
        vk.get_commitment_key_for_witnesses()
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [E::G1Affine],
        witness: crate::witness::R1CSCircomWitness<E>,
        blindings: BTreeMap<usize, E::ScalarField>,
        commit_witness_count: u32,
        v: E::ScalarField,
        snark_proof: Proof<E>,
    ) -> Result<(), ProofSystemError> {
        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, comm_key, snark_proof.d);
        let mut private_inputs = witness.get_first_n_private_inputs(commit_witness_count)?;
        private_inputs.push(v);
        sp.init(rng, blindings, private_inputs)?;
        self.snark_proof = Some(snark_proof);
        self.sp = Some(sp);
        Ok(())
    }
}
