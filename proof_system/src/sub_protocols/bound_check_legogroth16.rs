use crate::error::ProofSystemError;
use crate::statement_proof::{BoundCheckLegoGroth16Proof, StatementProof};
use crate::sub_protocols::schnorr::SchnorrProtocol;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, AllocationMode},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{
    cmp::Ordering, collections::BTreeMap, io::Write, rand::RngCore, vec, vec::Vec, UniformRand,
};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;
use legogroth16::{
    calculate_d, create_random_proof, generate_random_parameters, prepare_verifying_key,
    rerandomize_proof_1, verify_proof, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};

/// Runs the LegoGroth16 protocol for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the LegoGroth16 proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckProtocol<'a, E: PairingEngine> {
    pub id: usize,
    pub min: u64,
    pub max: u64,
    /// The SNARK proving key, will be `None` if invoked by verifier.
    pub proving_key: Option<&'a ProvingKey<E>>,
    /// The SNARK verifying key, will be `None` if invoked by prover.
    pub verifying_key: Option<&'a VerifyingKey<E>>,
    pub snark_proof: Option<Proof<E>>,
    pub sp: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: PairingEngine> BoundCheckProtocol<'a, E> {
    /// Create an instance of this protocol for the prover.
    pub fn new_for_prover(id: usize, min: u64, max: u64, proving_key: &'a ProvingKey<E>) -> Self {
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

    /// Create an instance of this protocol for the verifier.
    pub fn new_for_verifier(
        id: usize,
        min: u64,
        max: u64,
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
        comm_key: &'a [E::G1Affine],
        message: E::Fr,
        blinding: Option<E::Fr>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;

        // blinding for the commitment in the snark proof
        let v = E::Fr::rand(rng);

        let circuit = BoundCheckCircuit {
            min: Some(E::Fr::from(self.min)),
            max: Some(E::Fr::from(self.max)),
            value: Some(message),
        };
        let snark_proof = create_random_proof(circuit, v, proving_key, rng)?;

        /*// blinding used to prove knowledge of message in `snark_proof.d`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding = if blinding.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding.unwrap()
        };
        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, comm_key, snark_proof.d);
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);
        sp.init(rng, blindings, vec![message, v])?;
        self.snark_proof = Some(snark_proof);
        self.sp = Some(sp);
        Ok(())*/
        self.init_schnorr_protocol(rng, comm_key, message, blinding, v, snark_proof)
    }

    pub fn init_with_old_randomness_and_proof<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [E::G1Affine],
        message: E::Fr,
        blinding: Option<E::Fr>,
        old_v: E::Fr,
        proof: Proof<E>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let proving_key = self
            .proving_key
            .ok_or(ProofSystemError::LegoGroth16ProvingKeyNotProvided)?;

        // new blinding for the commitment in the snark proof
        let v = E::Fr::rand(rng);

        let snark_proof = rerandomize_proof_1(
            &proof,
            old_v,
            v,
            &proving_key.vk,
            &proving_key.common.eta_delta_inv_g1,
            rng,
        );

        self.init_schnorr_protocol(rng, comm_key, message, blinding, v, snark_proof)
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
    pub fn verify_proof_contribution(
        &self,
        challenge: &E::Fr,
        proof: &BoundCheckLegoGroth16Proof<E>,
        comm_key: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        let verifying_key = self
            .verifying_key
            .ok_or(ProofSystemError::LegoGroth16VerifyingKeyNotProvided)?;
        let pvk = prepare_verifying_key(verifying_key);
        self.verify_proof_contribution_using_prepared(challenge, proof, comm_key, &pvk, &mut None)
    }

    pub fn verify_proof_contribution_using_prepared(
        &self,
        challenge: &E::Fr,
        proof: &BoundCheckLegoGroth16Proof<E>,
        comm_key: &[E::G1Affine],
        pvk: &PreparedVerifyingKey<E>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        let pub_inp = &[E::Fr::from(self.min), E::Fr::from(self.max)];
        let snark_proof = &proof.snark_proof;
        match pairing_checker {
            Some(c) => {
                let d = calculate_d(pvk, snark_proof, pub_inp)?;
                c.add_prepared_sources_and_target(
                    &[snark_proof.a, snark_proof.c, d],
                    vec![
                        snark_proof.b.into(),
                        pvk.delta_g2_neg_pc.clone(),
                        pvk.gamma_g2_neg_pc.clone(),
                    ],
                    &pvk.alpha_g1_beta_g2,
                );
            }
            None => verify_proof(pvk, snark_proof, pub_inp)?,
        }

        // NOTE: value of id is dummy
        let sp = SchnorrProtocol::new(10000, comm_key, proof.snark_proof.d);

        sp.verify_proof_contribution_as_struct(challenge, &proof.sp)
    }

    pub fn compute_challenge_contribution<W: Write>(
        comm_key: &[E::G1Affine],
        proof: &BoundCheckLegoGroth16Proof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        comm_key.serialize_unchecked(&mut writer)?;
        proof.snark_proof.d.serialize_unchecked(&mut writer)?;
        proof.sp.t.serialize_unchecked(&mut writer)?;
        Ok(())
    }

    pub fn validate_bounds(min: u64, max: u64) -> Result<(), ProofSystemError> {
        if max <= min {
            return Err(ProofSystemError::BoundCheckMaxNotGreaterThanMin);
        }
        Ok(())
    }

    pub fn validate_verification_key(vk: &VerifyingKey<E>) -> Result<(), ProofSystemError> {
        if vk.gamma_abc_g1.len() < 4 {
            return Err(ProofSystemError::LegoGroth16Error(
                legogroth16::error::Error::SynthesisError(SynthesisError::MalformedVerifyingKey),
            ));
        }
        Ok(())
    }

    pub fn schnorr_comm_key(vk: &VerifyingKey<E>) -> Vec<E::G1Affine> {
        vec![vk.gamma_abc_g1[1 + 2], vk.eta_gamma_inv_g1]
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [E::G1Affine],
        message: E::Fr,
        blinding: Option<E::Fr>,
        v: E::Fr,
        snark_proof: Proof<E>,
    ) -> Result<(), ProofSystemError> {
        // blinding used to prove knowledge of message in `snark_proof.d`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding = if blinding.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding.unwrap()
        };
        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(10000, comm_key, snark_proof.d);
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);
        sp.init(rng, blindings, vec![message, v])?;
        self.snark_proof = Some(snark_proof);
        self.sp = Some(sp);
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

        // val strictly less than or equal to max, i.e. val <= max
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::{rand::prelude::StdRng, rand::SeedableRng};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn valid_bounds() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let proving_key = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).unwrap();
        let pvk = prepare_verifying_key(&proving_key.vk);

        for (min, max, value) in [
            (100, 200, 100),
            (100, 200, 200),
            (100, 200, 101),
            (100, 200, 199),
            (100, 200, 150),
        ] {
            let circuit = BoundCheckCircuit {
                min: Some(Fr::from(min)),
                max: Some(Fr::from(max)),
                value: Some(Fr::from(value)),
            };
            let v = Fr::rand(&mut rng);
            let proof = create_random_proof(circuit, v, &proving_key, &mut rng).unwrap();
            verify_proof(&pvk, &proof, &[Fr::from(min), Fr::from(max)]).unwrap();
        }

        let circuit = BoundCheckCircuit {
            min: Some(Fr::from(100)),
            max: Some(Fr::from(200)),
            value: Some(Fr::from(99)),
        };
        let v = Fr::rand(&mut rng);
        assert!(create_random_proof(circuit, v, &proving_key, &mut rng).is_err());

        for (min, max, value) in [(100, 200, 99), (100, 200, 201)] {
            // To create valid proof
            let circuit = BoundCheckCircuit {
                min: Some(Fr::from(1)),
                max: Some(Fr::from(1000)),
                value: Some(Fr::from(value)),
            };
            let v = Fr::rand(&mut rng);
            let proof = create_random_proof(circuit, v, &proving_key, &mut rng).unwrap();
            assert!(verify_proof(&pvk, &proof, &[Fr::from(min), Fr::from(max)],).is_err());
        }
    }
}
