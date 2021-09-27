use crate::impl_collection;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};
use bbs_plus::signature::SignatureG1 as BBSSignatureG1;
use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use vb_accumulator::witness::{MembershipWitness, NonMembershipWitness};

pub use serialization::*;

/// Secret data known only to the prover and whose knowledge is to proven
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Witness<E: PairingEngine> {
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    AccumulatorMembership(Membership<E>),
    AccumulatorNonMembership(NonMembership<E>),
    PedersenCommitment(#[serde_as(as = "Vec<FieldBytes>")] Vec<E::Fr>),
}

// impl_collection!(Witnesses, Witness);
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Witnesses<E>(pub Vec<Witness<E>>)
where
    E: PairingEngine;

/// Secret data corresponding when proving knowledge of BBS+ sig
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub signature: BBSSignatureG1<E>,
    #[serde_as(as = "BTreeMap<_, FieldBytes>")]
    pub unrevealed_messages: BTreeMap<usize, E::Fr>,
}

/// Secret data corresponding when proving proving accumulator membership
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Membership<E: PairingEngine> {
    #[serde_as(as = "FieldBytes")]
    pub element: E::Fr,
    pub witness: MembershipWitness<E::G1Affine>,
}

/// Secret data corresponding when proving proving accumulator non-membership
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct NonMembership<E: PairingEngine> {
    #[serde_as(as = "FieldBytes")]
    pub element: E::Fr,
    pub witness: NonMembershipWitness<E::G1Affine>,
}

impl<E> Witnesses<E>
where
    E: PairingEngine,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Witness<E>) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a `Witness` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_witness(
        signature: BBSSignatureG1<E>,
        unrevealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Witness<E> {
        Witness::PoKBBSSignatureG1(PoKBBSSignatureG1 {
            signature,
            unrevealed_messages,
        })
    }
}

/// Create a `Witness` variant for proving membership in accumulator
impl<E: PairingEngine> Membership<E> {
    pub fn new_as_witness(element: E::Fr, witness: MembershipWitness<E::G1Affine>) -> Witness<E> {
        Witness::AccumulatorMembership(Membership { element, witness })
    }
}

/// Create a `Witness` variant for proving non-membership in accumulator
impl<E: PairingEngine> NonMembership<E> {
    pub fn new_as_witness(
        element: E::Fr,
        witness: NonMembershipWitness<E::G1Affine>,
    ) -> Witness<E> {
        Witness::AccumulatorNonMembership(NonMembership { element, witness })
    }
}

mod serialization {
    use super::*;

    // TODO: Following code contains duplication that can possible be removed using macros

    impl<E: PairingEngine> CanonicalSerialize for Witness<E> {
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
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::PoKBBSSignatureG1(s) => 0u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorMembership(s) => 1u8.serialized_size() + s.serialized_size(),
                Self::AccumulatorNonMembership(s) => 2u8.serialized_size() + s.serialized_size(),
                Self::PedersenCommitment(s) => 3u8.serialized_size() + s.serialized_size(),
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
            }
        }
    }

    impl<E: PairingEngine> CanonicalDeserialize for Witness<E> {
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
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    Membership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembership::<E>::deserialize_uncompressed(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    Vec::<E::Fr>::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::PoKBBSSignatureG1(
                    PoKBBSSignatureG1::<E>::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::AccumulatorMembership(
                    Membership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                2u8 => Ok(Self::AccumulatorNonMembership(
                    NonMembership::<E>::deserialize_unchecked(&mut reader)?,
                )),
                3u8 => Ok(Self::PedersenCommitment(
                    Vec::<E::Fr>::deserialize_unchecked(&mut reader)?,
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
    use crate::test_utils::sig_setup;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::ProjectiveCurve;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn witness_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (msgs, _, _, sig) = sig_setup(&mut rng, 5);

        let mut witnesses: Witnesses<Bls12_381> = Witnesses::new();

        let wit_1 = PoKBBSSignatureG1::new_as_witness(
            sig,
            msgs.into_iter()
                .enumerate()
                .map(|(i, m)| (i, m))
                .collect::<BTreeMap<usize, Fr>>(),
        );
        test_serialization!(Witness<Bls12_381>, wit_1);

        witnesses.add(wit_1);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_2 = Membership::new_as_witness(
            Fr::rand(&mut rng),
            MembershipWitness(G1Proj::rand(&mut rng).into_affine()),
        );
        test_serialization!(Witness<Bls12_381>, wit_2);

        witnesses.add(wit_2);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_3 = NonMembership::new_as_witness(
            Fr::rand(&mut rng),
            NonMembershipWitness {
                d: Fr::rand(&mut rng),
                C: G1Proj::rand(&mut rng).into_affine(),
            },
        );
        test_serialization!(Witness<Bls12_381>, wit_3);

        witnesses.add(wit_3);
        test_serialization!(Witnesses<Bls12_381>, witnesses);

        let wit_4 = Witness::PedersenCommitment(vec![
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ]);
        test_serialization!(Witness<Bls12_381>, wit_4);

        witnesses.add(wit_4);
        test_serialization!(Witnesses<Bls12_381>, witnesses);
    }
}
