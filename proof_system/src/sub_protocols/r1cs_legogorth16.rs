use crate::error::ProofSystemError;
use crate::statement_proof::{R1CSLegoGroth16Proof, StatementProof};
use crate::sub_protocols::schnorr::SchnorrProtocol;
use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::CanonicalSerialize;
use ark_std::collections::BTreeMap;
use ark_std::io::Write;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use legogroth16::circom::{CircomCircuit, WitnessCalculator, R1CS};
use legogroth16::{
    create_random_proof, prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof,
    ProvingKey, VerifyingKey,
};

#[derive(Clone, Debug, PartialEq)]
pub struct R1CSLegogroth16Protocol<'a, E: PairingEngine> {
    pub id: usize,
    /// The SNARK proving key, will be `None` if invoked by verifier.
    pub proving_key: Option<&'a ProvingKey<E>>,
    /// The SNARK verifying key, will be `None` if invoked by prover.
    pub verifying_key: Option<&'a VerifyingKey<E>>,
    pub snark_proof: Option<Proof<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: PairingEngine> R1CSLegogroth16Protocol<'a, E> {
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
        blindings: BTreeMap<usize, E::Fr>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;

        let mut wits_calc = WitnessCalculator::<E>::from_wasm_bytes(wasm_bytes)?;
        let wires = wits_calc.calculate_witnesses(witness.inputs.clone().into_iter(), false)?;
        let circuit = CircomCircuit {
            r1cs,
            wires: Some(wires),
        };

        // blinding for the commitment in the snark proof
        let v = E::Fr::rand(rng);
        let snark_proof = create_random_proof(circuit, v, proving_key, rng)?;

        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, comm_key, snark_proof.d);
        let mut private_inputs = witness.get_private_inputs(proving_key.vk.commit_witness_count)?;
        private_inputs.push(v);
        sp.init(rng, blindings, private_inputs)?;
        self.snark_proof = Some(snark_proof);
        self.sp = Some(sp);
        Ok(())
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
    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
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
        challenge: &E::Fr,
        inputs: &[E::Fr],
        proof: &R1CSLegoGroth16Proof<E>,
        comm_key: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        let verifying_key = self
            .verifying_key
            .ok_or(ProofSystemError::LegoGroth16VerifyingKeyNotProvided)?;
        let pvk = prepare_verifying_key(verifying_key);
        self.verify_proof_contribution_using_prepared(challenge, inputs, proof, comm_key, &pvk)
    }

    pub fn verify_proof_contribution_using_prepared(
        &self,
        challenge: &E::Fr,
        inputs: &[E::Fr],
        proof: &R1CSLegoGroth16Proof<E>,
        comm_key: &[E::G1Affine],
        pvk: &PreparedVerifyingKey<E>,
    ) -> Result<(), ProofSystemError> {
        verify_proof(pvk, &proof.snark_proof, inputs)?;

        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key, proof.snark_proof.d);

        sp.verify_proof_contribution_as_struct(challenge, &proof.sp)
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key: &[E::G1Affine],
        proof: &R1CSLegoGroth16Proof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        comm_key.serialize_unchecked(&mut writer)?;
        proof.snark_proof.d.serialize_unchecked(&mut writer)?;
        proof.sp.t.serialize_unchecked(&mut writer)?;
        Ok(())
    }

    pub fn schnorr_comm_key(vk: &VerifyingKey<E>) -> Vec<E::G1Affine> {
        vk.get_commitment_key_for_witnesses()
    }
}
