use crate::utils::chunks_count;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, AllocationMode, Boolean, EqGadget};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

/// Circuit to check that each of `values` has bit size at most `required_bit_size`
#[derive(Clone)]
pub struct BitsizeCheckCircuit<F: PrimeField> {
    pub required_bit_size: u8,
    pub num_values: u8,
    pub values: Option<Vec<F>>,
    /// Allocate the value as public input or private, used to switch between Groth16 and LegoGroth16.
    /// For Groth16, its true, for LegoGroth16, its false
    pub alloc_as_public: bool,
}

impl<F: PrimeField> BitsizeCheckCircuit<F> {
    pub fn new(
        required_bit_size: u8,
        num_values: Option<u8>,
        values: Option<Vec<F>>,
        alloc_as_public: bool,
    ) -> Self {
        let num_values = if num_values.is_some() {
            num_values.unwrap()
        } else {
            chunks_count::<F>(required_bit_size)
        };
        Self {
            required_bit_size,
            num_values,
            values,
            alloc_as_public,
        }
    }
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for BitsizeCheckCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let values = match self.values {
            Some(vals) => vals.into_iter().map(|v| Some(v)).collect::<Vec<_>>(),
            _ => (0..self.num_values).map(|_| None).collect::<Vec<_>>(),
        };

        // Allocate variables for main witnesses (`values`) first as they need to be in the commitment
        let mut vars = Vec::with_capacity(values.len());
        for value in values {
            vars.push(FpVar::new_variable(
                cs.clone(),
                || value.ok_or(SynthesisError::AssignmentMissing),
                if self.alloc_as_public {
                    AllocationMode::Input
                } else {
                    AllocationMode::Witness
                },
            )?);
        }

        // For each variable, ensure that only last `self.required_bit_size` _may_ be set, rest *must* be unset
        let modulus_bits = ConstraintF::size_in_bits();
        let zero_bits = modulus_bits - self.required_bit_size as usize;
        for v in vars {
            let bits = v.to_bits_be()?;
            for b in bits[..zero_bits].iter() {
                b.enforce_equal(&Boolean::constant(false))?;
            }
        }

        Ok(())
    }
}
