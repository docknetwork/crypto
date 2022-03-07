//! For STROBE (used in merlin) sponge (from ark-sponge)
//! Sponge construction takes in arbitrary length input vector and
//! outputs the desired number of outputs (output)

use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_sponge::{Absorb, AbsorbWithLength};

/// Wrap Scalarfield so as to allow implementing the Absorb trait and create sponge functionality
pub struct HashInput<G: AffineCurve> {
    input_el: G::ScalarField,
}

impl<G: AffineCurve> Absorb for HashInput<G> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.input_el.serialize(dest).unwrap()
    }

    fn to_sponge_bytes_as_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.to_sponge_bytes(&mut result);
        result
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(field_cast(self.input_el).unwrap())
    }

    fn to_sponge_field_elements_as_vec<F: PrimeField>(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.to_sponge_field_elements(&mut result);
        result
    }

    fn batch_to_sponge_bytes(batch: &[Self], dest: &mut Vec<u8>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_bytes(dest)
        }
    }

    fn batch_to_sponge_bytes_as_vec(batch: &[Self]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        Self::batch_to_sponge_bytes(batch, &mut result);
        result
    }

    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_field_elements(dest)
        }
    }

    fn batch_to_sponge_field_elements_as_vec<F: PrimeField>(batch: &[Self]) -> Vec<F>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        Self::batch_to_sponge_field_elements(batch, &mut result);
        result
    }
}

/// If `F1` and `F2` have the same prime modulus, this method returns `Some(input)`
/// but cast to `F2`, and returns `None` otherwise. Utility for implementing Absordb for HashInput
pub(crate) fn field_cast<F1: PrimeField, F2: PrimeField>(input: F1) -> Option<F2> {
    if F1::characteristic() != F2::characteristic() {
        // Trying to absorb non-native field elements.
        None
    } else {
        let mut buf = Vec::new();
        input.serialize(&mut buf).unwrap();
        Some(F2::from_le_bytes_mod_order(&buf))
    }
}
