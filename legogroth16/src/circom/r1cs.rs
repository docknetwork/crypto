use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
    vec::Vec,
};

/// A linear combination
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct LC<E: Pairing>(pub Vec<(usize, E::ScalarField)>);

impl<E: Pairing> LC<E> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn terms(&self) -> &[(usize, E::ScalarField)] {
        &self.0
    }
}

/// A single constraint. Comprised of 3 linear combinations as `a * b - c = 0`
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Constraint<E: Pairing> {
    pub a: LC<E>,
    pub b: LC<E>,
    pub c: LC<E>,
}

/// Only the following curves are supported.
#[derive(Clone, Debug, PartialEq)]
pub enum Curve {
    Bn128,
    Bls12_381,
}

impl Default for Curve {
    fn default() -> Self {
        Curve::Bls12_381
    }
}

/// Result of the parsed R1CS file.
#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CS<E: Pairing> {
    pub curve: Curve,
    /// Total number of public values in the circuit. Includes public inputs and outputs and the always
    /// present input "1".
    pub num_public: u32,
    /// Total number of private values in the circuit. Includes the private input as well as the intermediate
    /// wires.
    pub num_private: u32,
    pub constraints: Vec<Constraint<E>>,
    /// The indices of the vector specify the wire index and the value specifies the label index
    pub wire_to_label_mapping: Vec<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct R1CSFile<E: Pairing> {
    /// R1CS file version. This is different from the Circom compiler version.
    pub version: u32,
    pub header: Header<E>,
    pub constraints: Vec<Constraint<E>>,
    pub wire_mapping: Vec<u64>,
}

/// Header section of R1CS file
#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Header<E: Pairing> {
    /// Size in bytes of a field element
    pub field_size: u32,
    /// Order of the largest subgroup of the curves
    pub subgroup_order: Vec<u8>,
    /// The curve used when compiling the circuit. Specified with flag `-p` with Circom.
    pub curve: Curve,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
    pub phantom: PhantomData<E>,
}

impl<E: Pairing> From<R1CSFile<E>> for R1CS<E> {
    fn from(file: R1CSFile<E>) -> Self {
        let num_inputs = 1 + file.header.n_pub_in + file.header.n_pub_out;
        let num_variables = file.header.n_wires;
        let num_aux = num_variables - num_inputs;
        R1CS {
            curve: file.header.curve,
            num_private: num_aux,
            num_public: num_inputs,
            constraints: file.constraints,
            wire_to_label_mapping: file.wire_mapping.iter().map(|e| *e as usize).collect(),
        }
    }
}

impl<E: Pairing> R1CS<E> {
    #[cfg(feature = "std")]
    pub fn from_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, crate::circom::CircomError> {
        Ok(R1CSFile::new_from_file(path)?.into())
    }
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, SerializationError, Valid, Validate};

    impl Valid for Curve {
        fn check(&self) -> Result<(), SerializationError> {
            Ok(())
        }
    }

    impl CanonicalSerialize for Curve {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Bn128 => CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress),
                Self::Bls12_381 => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::Bn128 => 0u8.serialized_size(compress),
                Self::Bls12_381 => 1u8.serialized_size(compress),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Bn128 => 0u8.serialize_uncompressed(&mut writer),
                Self::Bls12_381 => 1u8.serialize_uncompressed(&mut writer),
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::Bn128 => 0u8.uncompressed_size(),
                Self::Bls12_381 => 1u8.uncompressed_size(),
            }
        }
    }

    impl CanonicalDeserialize for Curve {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            // let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match u8::deserialize_with_mode(&mut reader, compress, validate)? {
                0u8 => Ok(Curve::Bn128),
                1u8 => Ok(Curve::Bls12_381),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}
