use crate::error::ProofSystemError;
use crate::statement;
use crate::statement::PedersenCommitment;
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
    ProvingKey,
};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BoundCheckProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: statement::BoundCheckLegoGroth16<E>,
    pub snark_proof: Option<Proof<E>>,
    pub sp: Option<SchnorrProtocol<E::G1Affine>>,
}

impl<E: PairingEngine> BoundCheckProtocol<E> {
    pub fn new(id: usize, statement: statement::BoundCheckLegoGroth16<E>) -> Self {
        Self {
            id,
            statement,
            snark_proof: None,
            sp: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        message: E::Fr,
        blinding: Option<E::Fr>,
    ) -> Result<(), ProofSystemError> {
        if self.sp.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let circuit = BoundCheckCircuit {
            min: Some(self.statement.min),
            max: Some(self.statement.max),
            value: Some(message),
        };
        let v = E::Fr::rand(rng);
        let snark_proof = create_random_proof(circuit, v, &self.statement.snark_proving_key, rng)?;
        let blinding = if blinding.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding.unwrap()
        };
        // NOTE: value of id is dummy
        let mut sp = SchnorrProtocol::new(
            10000,
            PedersenCommitment {
                // 1st instance variable is One and the next 2 for public inputs min and max.
                bases: vec![
                    self.statement.snark_proving_key.vk.gamma_abc_g1[1 + 2],
                    self.statement.snark_proving_key.vk.eta_gamma_inv_g1,
                ],
                commitment: snark_proof.d,
            },
        );
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
        // TODO: Add more
        Ok(())
    }

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

    pub fn verify_proof_contribution<G: AffineCurve>(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::BoundCheckLegoGroth16(proof) => {
                let pvk = prepare_verifying_key(&self.statement.snark_proving_key.vk);
                verify_proof(
                    &pvk,
                    &proof.snark_proof,
                    &[self.statement.min, self.statement.max],
                )?;

                // NOTE: value of id is dummy
                let sp = SchnorrProtocol::new(
                    10000,
                    PedersenCommitment {
                        // 1st instance variable is One and the next 2 for public inputs min and max.
                        bases: vec![
                            self.statement.snark_proving_key.vk.gamma_abc_g1[1 + 2],
                            self.statement.snark_proving_key.vk.eta_gamma_inv_g1,
                        ],
                        commitment: proof.snark_proof.d,
                    },
                );

                sp.verify_proof_contribution_as_struct(challenge, &proof.sp)?;
                Ok(())
            }

            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        stat: &statement::BoundCheckLegoGroth16<E>,
        proof: &BoundCheckLegoGroth16Proof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        vec![
            stat.snark_proving_key.vk.gamma_abc_g1[1 + 2],
            stat.snark_proving_key.vk.eta_gamma_inv_g1,
        ]
        .serialize_unchecked(&mut writer)?;
        proof.snark_proof.d.serialize_unchecked(&mut writer)?;
        proof.sp.t.serialize_unchecked(&mut writer)?;
        // TODO: Add more
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
