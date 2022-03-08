use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, AllocationMode, Boolean, EqGadget};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::borrow::Borrow;

#[derive(Clone)]
pub struct BitsizeCheckCircuit<F: PrimeField> {
    pub required_bit_size: u8,
    pub num_values: u8,
    pub values: Option<Vec<F>>,
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
            let scalar_size = F::size_in_bits();
            let bit_size = required_bit_size as usize;
            // ceil(scalar_size / bit_size)
            ((scalar_size + bit_size - 1) / bit_size) as u8
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
