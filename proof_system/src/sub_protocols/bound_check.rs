use crate::error::ProofSystemError;
use crate::statement_proof::{BoundCheckLegoGroth16Proof, StatementProof};
use crate::sub_protocols::schnorr::SchnorrProtocol;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, AllocationMode};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use ark_std::{
    cmp::Ordering,
    collections::BTreeMap,
    format,
    io::{Read, Write},
    rand::RngCore,
    vec, UniformRand,
};
use legogroth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof,
    ProvingKey, VerifyingKey,
};

/// Runs the LegoGroth16 protocol for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the LegoGroth16 proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckProtocol<'a, E: PairingEngine> {
    pub id: usize,
    pub min: E::Fr,
    pub max: E::Fr,
    pub proving_key: Option<&'a ProvingKey<E>>,
    pub verifying_key: Option<&'a VerifyingKey<E>>,
    pub snark_proof: Option<Proof<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: PairingEngine> BoundCheckProtocol<'a, E> {
    pub fn new_for_prover(
        id: usize,
        min: E::Fr,
        max: E::Fr,
        proving_key: &'a ProvingKey<E>,
    ) -> Self {
        Self {
            id,
            min,
            max,
            proving_key: Some(proving_key),
            verifying_key: None,
            snark_proof: None,
            sp: None,
        }
    }

    pub fn new_for_verifier(
        id: usize,
        min: E::Fr,
        max: E::Fr,
        verifying_key: &'a VerifyingKey<E>,
    ) -> Self {
        Self {
            id,
            min,
            max,
            proving_key: None,
            verifying_key: Some(verifying_key),
            snark_proof: None,
            sp: None,
        }
    }

    /// Runs the LegoGroth16 protocol to prove that the message is bounded and initialize a Schnorr proof of knowledge
    /// protocol to prove knowledge of the committed message
    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        message: E::Fr,
        blinding: Option<E::Fr>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;
        let circuit = BoundCheckCircuit {
            min: Some(self.min),
            max: Some(self.max),
            value: Some(message),
        };
        // blinding for the commitment in the snark proof
        let v = E::Fr::rand(rng);
        let snark_proof = create_random_proof(circuit, v, proving_key, rng)?;

        // blinding used to prove knowledge of message in `snark_proof.d`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding = if blinding.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding.unwrap()
        };
        let comm_key = vec![
            proving_key.vk.gamma_abc_g1[1 + 2],
            proving_key.vk.eta_gamma_inv_g1,
        ];
        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, &comm_key, snark_proof.d);
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);
        sp.init(rng, blindings, vec![message, v])?;
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
        Ok(StatementProof::BoundCheckLegoGroth16(
            BoundCheckLegoGroth16Proof {
                snark_proof: self.snark_proof.take().unwrap(),
                sp: self
                    .sp
                    .take()
                    .unwrap()
                    .gen_proof_contribution_as_struct(challenge)?,
            },
        ))
    }

    /// Verify that the snark proof and the Schnorr proof are valid.
    pub fn verify_proof_contribution<G: AffineCurve>(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::BoundCheckLegoGroth16(proof) => {
                let verifying_key = self
                    .verifying_key
                    .ok_or(ProofSystemError::LegoGroth16VerifyingKeyNotProvided)?;
                let pvk = prepare_verifying_key(verifying_key);
                verify_proof(&pvk, &proof.snark_proof, &[self.min, self.max])?;

                let comm_key = vec![
                    verifying_key.gamma_abc_g1[1 + 2],
                    verifying_key.eta_gamma_inv_g1,
                ];

                // NOTE: value of id is dummy
                let sp = SchnorrProtocol::new(10000, &comm_key, proof.snark_proof.d);

                sp.verify_proof_contribution_as_struct(challenge, &proof.sp)?;
                Ok(())
            }

            _ => Err(ProofSystemError::ProofIncompatibleWithBoundCheckProtocol),
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        verifying_key: &VerifyingKey<E>,
        proof: &BoundCheckLegoGroth16Proof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        vec![
            verifying_key.gamma_abc_g1[1 + 2],
            verifying_key.eta_gamma_inv_g1,
        ]
        .serialize_unchecked(&mut writer)?;
        proof.snark_proof.d.serialize_unchecked(&mut writer)?;
        proof.sp.t.serialize_unchecked(&mut writer)?;
        Ok(())
    }

    pub fn validate_bounds(
        min: E::Fr,
        max: E::Fr,
        vk: &VerifyingKey<E>,
    ) -> Result<(), ProofSystemError> {
        if vk.gamma_abc_g1.len() < 4 {
            return Err(ProofSystemError::LegoGroth16Error(
                legogroth16::error::Error::SynthesisError(SynthesisError::MalformedVerifyingKey),
            ));
        }

        // For comparisons to be valid, both max must be <= (p-1)/2. This is enforced in the
        // circuit as well.
        let max_allowed = E::Fr::modulus_minus_one_div_two();
        let max_big = max.into_repr();
        match max_big.cmp(&max_allowed) {
            Ordering::Greater => return Err(ProofSystemError::BoundCheckMaxGreaterThanAllowed),
            _ => (),
        }

        // min must be < max
        let min_big = min.into_repr();
        match min_big.cmp(&max_big) {
            Ordering::Less => (),
            _ => return Err(ProofSystemError::BoundCheckMaxNotGreaterThanMin),
        }

        Ok(())
    }
}

// NOTE: For range check, the following circuits assume that the numbers are of same size as field
// elements which might not always be true in practice. If the upper bound on the byte-size of the numbers
// is known, then the no. of constraints in the circuit can be reduced.

/// Enforce min <= value <= max
#[derive(Clone)]
pub struct BoundCheckCircuit<F: Field> {
    min: Option<F>,
    max: Option<F>,
    value: Option<F>,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for BoundCheckCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let val = FpVar::new_variable(
            cs.clone(),
            || self.value.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Witness,
        )?;

        let min = FpVar::new_variable(
            cs.clone(),
            || self.min.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Input,
        )?;
        let max = FpVar::new_variable(
            cs.clone(),
            || self.max.ok_or(SynthesisError::AssignmentMissing),
            AllocationMode::Input,
        )?;

        // val strictly than or equal to max, i.e. val <= max
        val.enforce_cmp(&max, Ordering::Less, true)?;
        // val strictly greater than or equal to max, i.e. val >= min
        val.enforce_cmp(&min, Ordering::Greater, true)?;
        Ok(())
    }
}

/// Generate SNARK proving key and verification key for a circuit that checks that given a witness
/// `w` and public inputs `min` and `max`, `min <= w <= max`
pub fn generate_snark_srs_bound_check<E, R>(rng: &mut R) -> Result<ProvingKey<E>, ProofSystemError>
where
    E: PairingEngine,
    R: Rng,
{
    let circuit = BoundCheckCircuit::<E::Fr> {
        min: None,
        max: None,
        value: None,
    };
    generate_random_parameters::<E, _, R>(circuit, 1, rng).map_err(|e| e.into())
}
