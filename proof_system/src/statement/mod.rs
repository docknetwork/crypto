use ark_ec::{AffineCurve, PairingEngine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

pub mod accumulator;
pub mod bbs_plus;
pub mod bound_check_legogroth16;
pub mod ped_comm;
pub mod saver;

pub use serialization::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Statement<E: PairingEngine, G: AffineCurve> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(bbs_plus::PoKBBSSignatureG1<E>),
    PedersenCommitment(ped_comm::PedersenCommitment<G>),
    AccumulatorMembership(accumulator::AccumulatorMembership<E>),
    AccumulatorNonMembership(accumulator::AccumulatorNonMembership<E>),
    /// Proving verifiable encryption using SAVER
    SaverProver(saver::SaverProver<E>),
    SaverVerifier(saver::SaverVerifier<E>),
    /// Proving witness satisfies publicly known bounds inclusively (<=, >=).
    BoundCheckLegoGroth16Prover(bound_check_legogroth16::BoundCheckLegoGroth16Prover<E>),
    BoundCheckLegoGroth16Verifier(bound_check_legogroth16::BoundCheckLegoGroth16Verifier<E>),
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Statements<E, G>(pub Vec<Statement<E, G>>)
where
    E: PairingEngine,
    G: AffineCurve;

impl<E, G> Statements<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Statement<E, G>) -> usize {
        self.0.push(item);
        self.0.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for Statement<E, G> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    CanonicalSerialize::serialize(&2u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::PedersenCommitment(s) => {
                    CanonicalSerialize::serialize(&3u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverProver(s) => {
                    CanonicalSerialize::serialize(&4u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::SaverVerifier(s) => {
                    CanonicalSerialize::serialize(&5u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    CanonicalSerialize::serialize(&6u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    CanonicalSerialize::serialize(&7u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
                Self::SaverProver(s) => 4u8.serialized_size() + s.serialized_size(),
                Self::SaverVerifier(s) => 5u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16Prover(s) => 6u8.serialized_size() + s.serialized_size(),
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialized_size() + s.serialized_size()
                }
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::SaverProver(s) => {
                    4u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::SaverVerifier(s) => {
                    5u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::PoKBBSSignatureG1(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorMembership(s) => {
                    1u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::AccumulatorNonMembership(s) => {
                    2u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::PedersenCommitment(s) => {
                    3u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::SaverProver(s) => {
                    4u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::SaverVerifier(s) => {
                    5u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorMembership(s) => 1u8.uncompressed_size() + s.uncompressed_size(),
                Self::AccumulatorNonMembership(s) => {
                    2u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::PedersenCommitment(s) => 3u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverProver(s) => 4u8.uncompressed_size() + s.uncompressed_size(),
                Self::SaverVerifier(s) => 5u8.uncompressed_size() + s.uncompressed_size(),
                Self::BoundCheckLegoGroth16Prover(s) => {
                    6u8.uncompressed_size() + s.uncompressed_size()
                }
                Self::BoundCheckLegoGroth16Verifier(s) => {
                    7u8.uncompressed_size() + s.uncompressed_size()
                }
            }
        }
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for Statement<E, G> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::PoKBBSSignatureG1(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                4u8 => Ok(Self::SaverProver(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                5u8 => Ok(Self::SaverVerifier(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                4u8 => Ok(Self::SaverProver(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                5u8 => Ok(Self::SaverVerifier(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                4u8 => Ok(Self::SaverProver(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                5u8 => Ok(Self::SaverVerifier(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                6u8 => Ok(Self::BoundCheckLegoGroth16Prover(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                7u8 => Ok(Self::BoundCheckLegoGroth16Verifier(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use crate::test_utils::{setup_positive_accum, setup_universal_accum, sig_setup};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;
    use ark_std::{
        collections::BTreeMap,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use vb_accumulator::prelude::{Accumulator, MembershipProvingKey, NonMembershipProvingKey};

    #[test]
    fn statement_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (_, params_1, keypair_1, _) = sig_setup(&mut rng, 5);
        let (pos_params, pos_keypair, pos_accumulator, _) = setup_positive_accum(&mut rng);
        let (uni_params, uni_keypair, uni_accumulator, _, _) = setup_universal_accum(&mut rng, 100);
        let mem_prk =
            MembershipProvingKey::<<Bls12_381 as PairingEngine>::G1Affine>::generate_using_rng(
                &mut rng,
            );
        let non_mem_prk =
            NonMembershipProvingKey::<<Bls12_381 as PairingEngine>::G1Affine>::generate_using_rng(
                &mut rng,
            );

        let mut statements: Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine> =
            Statements::new();

        let stmt_1 = bbs_plus::PoKBBSSignatureG1::new_statement_from_params(
            params_1.clone(),
            keypair_1.public_key.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_1);

        statements.add(stmt_1);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_2 = accumulator::AccumulatorMembership::new_statement_from_params::<
            <Bls12_381 as PairingEngine>::G1Affine,
        >(
            pos_params.clone(),
            pos_keypair.public_key.clone(),
            mem_prk.clone(),
            pos_accumulator.value().clone(),
        );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_2);

        statements.add(stmt_2);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_3 = accumulator::AccumulatorNonMembership::new_statement_from_params::<
            <Bls12_381 as PairingEngine>::G1Affine,
        >(
            uni_params.clone(),
            uni_keypair.public_key.clone(),
            non_mem_prk.clone(),
            uni_accumulator.value().clone(),
        );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_3);

        statements.add(stmt_3);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let bases = (0..5)
            .map(|_| G1Proj::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &bases,
            &scalars.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let stmt_4 = ped_comm::PedersenCommitment::new_statement_from_params(bases, commitment);
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_4);

        statements.add(stmt_4);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    }
}
