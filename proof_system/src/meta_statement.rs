//! Used to express relation between `Statement`s

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeSet,
    io::{Read, Write},
    vec,
    vec::Vec,
};
use serde::{Deserialize, Serialize};

pub use serialization::*;

/// Reference to a witness described as the tuple (`statement_id`, `witness_id`)
pub type WitnessRef = (usize, usize);

/// Statement describing relation between statements
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaStatement {
    WitnessEquality(EqualWitnesses),
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MetaStatements(pub Vec<MetaStatement>);

/// Describes equality between one or more witnesses across statements. Eg. if witness 3 of statement
/// 0 is to be proven equal to witness 5 of statement 1, then its written as
/// ```
/// use ark_std::collections::BTreeSet;
/// use proof_system::statement::EqualWitnesses;
/// let mut eq = BTreeSet::new();
/// eq.insert((0, 3));
/// eq.insert((1, 5));
/// let eq_w = EqualWitnesses(eq);
/// ```
///
/// Multiple such equalities can be represented as separate `EqualWitnesses` and each will be a separate
/// `MetaStatement`
/// ```
/// // 1st witness equality
/// let mut eq_1 = BTreeSet::new();
/// eq_1.insert((0, 3));
/// eq_1.insert((1, 5));
/// let eq_1_w = EqualWitnesses(eq_1);
///
/// // 2nd witness equality
/// let mut eq_2 = BTreeSet::new();
/// eq_2.insert((0, 4));
/// eq_2.insert((1, 9));
/// let eq_2_w = EqualWitnesses(eq_2);
///
/// let mut meta_statements = MetaStatements::new();
/// meta_statements.add(MetaStatement::WitnessEquality(eq_1_w));
/// meta_statements.add(MetaStatement::WitnessEquality(eq_2_w));
/// ```
///
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct EqualWitnesses(pub BTreeSet<WitnessRef>);

impl EqualWitnesses {
    /// A witness equality should have at least 2 witness references.
    pub fn is_valid(&self) -> bool {
        self.0.len() > 1
    }
}

impl MetaStatements {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: MetaStatement) -> usize {
        self.0.push(item);
        self.0.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Given multiple `MetaStatement::WitnessEquality` which might have common witness references,
    /// return a list of `EqualWitnesses` with no common references. The objective is the same as
    /// when given a collection of sets; return a new collection of sets such that all sets in the new
    /// collection are pairwise distinct.
    pub fn disjoint_witness_equalities(&self) -> Vec<EqualWitnesses> {
        let mut equalities = vec![];
        let mut disjoints = vec![];
        for stmt in &self.0 {
            match stmt {
                MetaStatement::WitnessEquality(eq_wits) => {
                    equalities.push(eq_wits);
                }
            }
        }
        while !equalities.is_empty() {
            // Traverse `equalities` in reverse as that doesn't change index on removal
            let mut current = equalities.pop().unwrap().0.clone();
            if !equalities.is_empty() {
                let mut i = equalities.len() - 1;
                loop {
                    if !current.is_disjoint(&equalities[i].0) {
                        current = current.union(&equalities.remove(i).0).cloned().collect();
                    }
                    if i == 0 {
                        break;
                    }
                    i -= 1;
                }
            }
            disjoints.push(EqualWitnesses(current));
        }
        disjoints
    }
}

mod serialization {
    use super::*;

    impl CanonicalSerialize for MetaStatement {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::WitnessEquality(s) => 0u8.serialized_size() + s.serialized_size(),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::WitnessEquality(s) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::WitnessEquality(s) => 0u8.uncompressed_size() + s.uncompressed_size(),
            }
        }
    }

    impl CanonicalDeserialize for MetaStatement {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::WitnessEquality(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::WitnessEquality(
                    EqualWitnesses::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::WitnessEquality(
                    EqualWitnesses::deserialize_unchecked(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disjoint_witness_equality() {
        macro_rules! check {
            ($input:expr, $output: expr) => {
                let mut meta_statements = MetaStatements::new();
                for i in $input.into_iter() {
                    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                        i.into_iter().collect::<BTreeSet<WitnessRef>>(),
                    )));
                }
                let disjoints = meta_statements.disjoint_witness_equalities();
                assert_eq!(disjoints.len(), $output.len());
                for o in $output.into_iter() {
                    assert!(disjoints.contains({
                        let mut set = BTreeSet::new();
                        for r in o.clone().into_iter() {
                            set.insert(r);
                        }
                        &EqualWitnesses(set)
                    }));
                }
            };
        }

        check!(
            vec![
                vec![(0, 1), (1, 1)],
                vec![(0, 1), (1, 2)],
                vec![(0, 3), (1, 4)]
            ],
            vec![vec![(0, 1), (1, 1), (1, 2)], vec![(0, 3), (1, 4)],]
        );

        check!(
            vec![
                vec![(0, 1), (1, 1)],
                vec![(0, 5), (1, 2)],
                vec![(0, 3), (1, 4)],
            ],
            vec![
                vec![(0, 1), (1, 1)],
                vec![(0, 5), (1, 2)],
                vec![(0, 3), (1, 4)]
            ]
        );

        check!(
            vec![
                vec![(0, 1), (1, 1), (2, 1)],
                vec![(0, 5), (1, 2), (3, 1)],
                vec![(0, 3), (1, 4), (1, 1), (3, 1)],
            ],
            vec![vec![
                (0, 1),
                (1, 1),
                (2, 1),
                (0, 5),
                (1, 2),
                (3, 1),
                (0, 3),
                (1, 4)
            ]]
        );

        check!(
            vec![
                vec![(1, 1), (4, 1)],
                vec![(1, 2), (6, 5)],
                vec![(0, 3), (1, 4), (2, 1), (3, 1), (5, 2)],
                vec![(0, 0), (1, 9), (5, 5), (6, 1)],
                vec![(0, 0), (1, 9), (5, 6), (6, 6)]
            ],
            vec![
                vec![(4, 1), (1, 1)],
                vec![(6, 5), (1, 2)],
                vec![(0, 3), (1, 4), (2, 1), (3, 1), (5, 2)],
                vec![(0, 0), (1, 9), (5, 5), (5, 6), (6, 1), (6, 6)],
            ]
        );

        check!(
            vec![
                vec![(0, 2), (1, 3)],
                vec![(0, 3), (1, 4), (2, 0), (5, 0)],
                vec![(2, 0), (5, 0)],
                vec![(3, 0), (6, 0)],
                vec![(4, 0), (7, 0)]
            ],
            vec![
                vec![(0, 2), (1, 3)],
                vec![(0, 3), (1, 4), (2, 0), (5, 0)],
                vec![(3, 0), (6, 0)],
                vec![(4, 0), (7, 0)],
            ]
        );
    }
}
