use ark_ec::{AffineCurve, PairingEngine};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec,
    vec::Vec,
};

use bbs_plus::setup::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};

use ark_std::collections::BTreeSet;
pub use serialization::*;
use vb_accumulator::{
    proofs::{MembershipProvingKey, NonMembershipProvingKey},
    setup::{PublicKey as AccumPublicKey, SetupParams as AccumParams},
};

use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

/// Reference to a witness described as the tuple (`statement_id`, `witness_id`)
pub type WitnessRef = (usize, usize);

/// Type of proof and the public (known to both prover and verifier) values for the proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Statement<E: PairingEngine, G: AffineCurve> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    /// Membership in Accumulator
    AccumulatorMembership(AccumulatorMembership<E>),
    /// Non-membership in Accumulator
    AccumulatorNonMembership(AccumulatorNonMembership<E>),
    /// Proof of knowledge of committed elements in a Pedersen commitment
    PedersenCommitment(PedersenCommitment<G>),
}

/// Statement describing relation between statements
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaStatement {
    WitnessEquality(EqualWitnesses),
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MetaStatements(pub Vec<MetaStatement>);

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Statements<E, G>(pub Vec<Statement<E, G>>)
where
    E: PairingEngine,
    G: AffineCurve;

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub params: BBSSignatureParamsG1<E>,
    pub public_key: BBSPublicKeyG2<E>,
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, FieldBytes>")]
    pub revealed_messages: BTreeMap<usize, E::Fr>,
}

/// Public values like setup params, public key, proving key and accumulator for proving membership
/// in positive and universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: MembershipProvingKey<E::G1Affine>,
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
}

/// Public values like setup params, public key, proving key and accumulator for proving non-membership
/// in universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorNonMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: NonMembershipProvingKey<E::G1Affine>,
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
}

/// Proving knowledge of scalars `s_i` in Pedersen commitment `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitment<G: AffineCurve> {
    /// The bases `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "Vec<AffineGroupBytes>")]
    pub bases: Vec<G>,
    /// The Pedersen commitment `C` in `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: G,
}

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
    pub fn is_valid(&self) -> bool {
        self.0.len() > 1
    }
}

impl MetaStatements {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: MetaStatement) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Given multiple `MetaStatement::WitnessEquality` which might have common witness references,
    /// return a list of `EqualWitnesses` with no common references. The objective is same as
    /// when given a collection of sets, return a new collection of sets such that all sets in the new
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
        while equalities.len() > 0 {
            // Traverse `equalities` in reverse as that doesn't change index on removal
            let mut current = equalities.pop().unwrap().0.clone();
            if equalities.len() > 0 {
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

impl<E, G> Statements<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Statement<E, G>) {
        self.0.push(item)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a `Statement` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: BBSSignatureParamsG1<E>,
        public_key: BBSPublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E, G> {
        Statement::PoKBBSSignatureG1(Self {
            params,
            public_key,
            revealed_messages,
        })
    }
}

/// Create a `Statement` variant for proving membership in accumulator
impl<E: PairingEngine> AccumulatorMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving non-membership in accumulator
impl<E: PairingEngine> AccumulatorNonMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorNonMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineCurve> PedersenCommitment<G> {
    pub fn new_as_statement<E: PairingEngine>(bases: Vec<G>, commitment: G) -> Statement<E, G> {
        Statement::PedersenCommitment(Self { bases, commitment })
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for Statement<E, G> {
        impl_serialize!();
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for Statement<E, G> {
        impl_deserialize!();
    }

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
    use crate::test_serialization;
    use crate::test_utils::{setup_positive_accum, setup_universal_accum, sig_setup};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_ff::fields::PrimeField;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use vb_accumulator::prelude::Accumulator;

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

        let stmt_1 = PoKBBSSignatureG1::new_as_statement(
            params_1.clone(),
            keypair_1.public_key.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_1);

        statements.add(stmt_1);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_2 =
            AccumulatorMembership::new_as_statement::<<Bls12_381 as PairingEngine>::G1Affine>(
                pos_params.clone(),
                pos_keypair.public_key.clone(),
                mem_prk.clone(),
                pos_accumulator.value().clone(),
            );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_2);

        statements.add(stmt_2);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_3 =
            AccumulatorNonMembership::new_as_statement::<<Bls12_381 as PairingEngine>::G1Affine>(
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
        let stmt_4 = Statement::PedersenCommitment(PedersenCommitment { bases, commitment });
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_4);

        statements.add(stmt_4);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    }

    #[test]
    fn disjoint_witness_equality() {
        macro_rules! check {
            ($input:expr, $output: expr) => {
                let mut meta_statements = MetaStatements::new();
                for i in $input.into_iter() {
                    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                        i.into_iter().collect::<BTreeSet<(usize, usize)>>(),
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
