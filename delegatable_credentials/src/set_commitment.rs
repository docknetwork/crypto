//! Set commitment scheme (SCDS) as defined in Fig.2 of [this paper](https://eprint.iacr.org/2021/1680.pdf)
//! Aggregation is taken from section 3.4 of [this paper](https://eprint.iacr.org/2022/680.pdf)
//! The set commitment is a KZG polynomial commitment to a monic polynomial whose roots are the set members.
//! The above paper defines the characteristic polynomial of a set as `(x+a1)*(x+a2)*(x+a3)*..` but this
//! implementation is using `(x-a1)*(x-a2)*(x-a3)*..` for set members `a1, a2, ...` to reuse existing code

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeSet,
    io::{Read, Write},
    ops::{Div, Neg},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::DelegationError;
use crate::error::DelegationError::UnequalSizeOfSequence;
use crate::util::{generator_pair, generator_pair_deterministic};
use dock_crypto_utils::ec::{batch_normalize_projective_into_affine, pairing_product};
use dock_crypto_utils::hashing_utils::field_elem_from_seed;
use dock_crypto_utils::msm::{variable_base_msm, WindowTable};
use dock_crypto_utils::poly::poly_from_roots;
use dock_crypto_utils::{ff::powers, serde_utils::*};

// TODO: Makes sense to split this into P1 and P2 as prover does not need P2 vector and verifier does not need P1 vector
/// KZG polynomial commitment SRS (Structured Reference String) used by the set commitment scheme
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SetCommitmentSRS<E: PairingEngine> {
    #[serde_as(as = "Vec<AffineGroupBytes>")]
    pub P1: Vec<E::G1Affine>,
    #[serde_as(as = "Vec<AffineGroupBytes>")]
    pub P2: Vec<E::G2Affine>,
}

impl<E: PairingEngine> SetCommitmentSRS<E> {
    /// Generate a trapdoor and then create the SRS and return both
    pub fn generate_with_random_trapdoor<R: RngCore, D: Digest>(
        rng: &mut R,
        max_size: usize,
        setup_params_label: Option<&[u8]>,
    ) -> (Self, E::Fr) {
        let td = E::Fr::rand(rng);
        let pp = Self::generate_with_trapdoor::<R, D>(rng, &td, max_size, setup_params_label);
        (pp, td)
    }

    /// Generates the trapdoor deterministically from the given seed and then generate SRS from it.
    pub fn generate_with_trapdoor_seed<R: RngCore, D>(
        rng: &mut R,
        max_size: usize,
        trapdoor_seed: &[u8],
        setup_params_label: Option<&[u8]>,
    ) -> (Self, E::Fr)
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let td = field_elem_from_seed::<E::Fr, D>(
            trapdoor_seed,
            "SET-COMMITMENT_TRAPDOOR-SALT".as_bytes(),
        );
        let pp = Self::generate_with_trapdoor::<R, D>(rng, &td, max_size, setup_params_label);
        (pp, td)
    }

    pub fn generate_with_trapdoor<R: RngCore, D: Digest>(
        rng: &mut R,
        td: &E::Fr,
        max_size: usize,
        setup_params_label: Option<&[u8]>,
    ) -> Self {
        let (P1, P2) = match setup_params_label {
            Some(label) => generator_pair_deterministic::<E, D>(label),
            None => generator_pair::<E, R>(rng),
        };
        let powers = powers(td, max_size + 1);
        let P1_table = WindowTable::new(max_size + 1, P1.into_projective());
        let P2_table = WindowTable::new(max_size + 1, P2.into_projective());
        Self {
            P1: batch_normalize_projective_into_affine(P1_table.multiply_many(&powers)),
            P2: batch_normalize_projective_into_affine(P2_table.multiply_many(&powers)),
        }
    }

    pub fn size(&self) -> usize {
        self.P1.len() - 1
    }

    /// Returns group element `P1`
    pub fn get_P1(&self) -> &E::G1Affine {
        &self.P1[0]
    }

    /// Returns group element `P2`
    pub fn get_P2(&self) -> &E::G2Affine {
        &self.P2[0]
    }

    /// Returns group element `s*P1` where `s` is the trapdoor
    pub fn get_s_P1(&self) -> &E::G1Affine {
        &self.P1[1]
    }

    /// Returns group element `s*P2` where `s` is the trapdoor
    pub fn get_s_P2(&self) -> &E::G2Affine {
        &self.P2[1]
    }

    /// Evaluate the polynomial whose roots are members of the given set at trapdoor in group G1
    pub fn eval_P1(&self, set: BTreeSet<E::Fr>) -> E::G1Projective {
        Self::eval::<E::G1Affine>(set, &self.P1)
    }

    /// Evaluate the polynomial whose roots are members of the given set at trapdoor in group G2
    pub fn eval_P2(&self, set: BTreeSet<E::Fr>) -> E::G2Projective {
        Self::eval::<E::G2Affine>(set, &self.P2)
    }

    /// Evaluate the polynomial whose roots are members of the given set
    pub fn eval<G: AffineCurve>(set: BTreeSet<G::ScalarField>, powers: &[G]) -> G::Projective {
        let set_size = set.len();
        let poly = poly_from_roots(&set.into_iter().collect::<Vec<_>>());
        variable_base_msm(&powers[0..=set_size], &poly.coeffs[0..=set_size])
    }
}

/// Commitment to a set
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetCommitment<E: PairingEngine>(pub E::G1Affine);

/// Opening to the set commitment. Contains the randomness in the commitment.
#[derive(Clone, Debug)]
pub enum SetCommitmentOpening<E: PairingEngine> {
    /// When the committed set doesn't have the trapdoor.
    SetWithoutTrapdoor(E::Fr),
    /// When the committed set has the trapdoor. 1st element is the randomness used in the commitment and 2nd element is the trapdoor
    SetWithTrapdoor(E::Fr, E::Fr),
}

/// Witness of the subset of set which is committed in certain commitment. It is commitment to difference of
/// the set and this subset. Used in proving that a certain set is indeed the subset of a committed set.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SubsetWitness<E: PairingEngine>(pub E::G1Affine);

/// A constant size aggregation of several subset witnesses
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregateSubsetWitness<E: PairingEngine>(pub E::G1Affine);

impl<E: PairingEngine> SetCommitment<E> {
    /// Commit to the given set.
    pub fn new<R: RngCore>(
        rng: &mut R,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, SetCommitmentOpening<E>), DelegationError> {
        let r = E::Fr::rand(rng);
        Self::new_with_given_randomness(r, set, srs)
    }

    /// Commit to the given set with provided randomness
    pub fn new_with_given_randomness(
        randomness: E::Fr,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, SetCommitmentOpening<E>), DelegationError> {
        let set_size = set.len();

        if set_size > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                set_size,
                srs.size(),
            ));
        }

        let P1_table = WindowTable::new(set_size, srs.get_P1().into_projective());
        let s_P1 = srs.get_s_P1().into_projective();
        // Check if set contains the trapdoor
        for s in set.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Ok((
                    SetCommitment(P1_table.multiply(&randomness).into_affine()),
                    SetCommitmentOpening::SetWithTrapdoor(randomness, *s),
                ));
            }
        }
        Ok((
            SetCommitment(Self::commit_in_P1(randomness.into_repr(), set, srs)),
            SetCommitmentOpening::SetWithoutTrapdoor(randomness),
        ))
    }

    /// Commit to the given set when provided with a commitment to the randomness.
    /// It is assumed that `comm_rand` is indeed of the form `r*P1` where `r` is the randomness. A PoK would
    /// be verified by the caller before calling this function.
    pub fn new_with_given_commitment_to_randomness(
        comm_rand: E::G1Affine,
        trapdoor: &E::Fr,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        let set_size = set.len();

        if set_size > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                set_size,
                srs.size(),
            ));
        }

        let P1_table = WindowTable::new(set_size, srs.get_P1().into_projective());
        let s_P1 = srs.get_s_P1().into_projective();
        // Check if set contains the trapdoor
        for s in set.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Ok(SetCommitment(comm_rand));
            }
        }
        let mut prod = E::Fr::one();
        for s in set {
            prod *= *trapdoor - s;
        }
        Ok(SetCommitment(comm_rand.mul(prod).into_affine()))
    }

    /// Checks if the commitment can be opened with the given opening and for the given set.
    pub fn open_set(
        &self,
        opening: &SetCommitmentOpening<E>,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        match opening {
            SetCommitmentOpening::SetWithTrapdoor(r, s) => {
                let P1 = srs.get_P1().into_projective();
                let s_P1 = P1.mul(s.into_repr()).into_affine();
                let C = P1.mul(r.into_repr()).into_affine();
                if !set.contains(s) || (C != self.0) || (s_P1 != *srs.get_s_P1()) {
                    return Err(DelegationError::InvalidOpening);
                }
                Ok(())
            }
            SetCommitmentOpening::SetWithoutTrapdoor(r) => {
                if Self::commit_in_P1(r.into_repr(), set, srs) != self.0 {
                    return Err(DelegationError::InvalidOpening);
                }
                Ok(())
            }
        }
    }

    /// Same as `Self::open_subset_unchecked` but additionally checks if the subset is indeed a subset and the opening is valid.
    pub fn open_subset(
        &self,
        opening: &SetCommitmentOpening<E>,
        subset: BTreeSet<E::Fr>,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<SubsetWitness<E>, DelegationError> {
        if !subset.is_subset(&set) {
            return Err(DelegationError::NotASubset);
        }
        // Check if the opening is correct
        self.open_set(opening, set.clone(), srs)?;

        self.open_subset_unchecked(opening, subset, set, srs)
    }

    /// Returns witness for the given subset of a set which is committed in this commitment
    pub fn open_subset_unchecked(
        &self,
        opening: &SetCommitmentOpening<E>,
        subset: BTreeSet<E::Fr>,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<SubsetWitness<E>, DelegationError> {
        let subset_size = subset.len();
        if subset_size == 0 {
            return Ok(SubsetWitness(self.0.clone()));
        }
        match opening {
            SetCommitmentOpening::SetWithTrapdoor(_, s) => {
                if subset.contains(s) {
                    Err(DelegationError::ShouldNotContainTrapdoor)
                } else {
                    let poly = poly_from_roots(&subset.into_iter().collect::<Vec<_>>());
                    let mut e = poly.evaluate(s);
                    e.inverse_in_place().unwrap();
                    Ok(SubsetWitness(self.0.mul(e).into()))
                }
            }
            SetCommitmentOpening::SetWithoutTrapdoor(r) => {
                let diff = set.difference(&subset).cloned().collect::<BTreeSet<_>>();
                let witness = if diff.is_empty() {
                    // Subset is same as the set
                    srs.get_P1().mul(r.into_repr()).into_affine()
                } else {
                    // Commit to remaining elements
                    Self::commit_in_P1(r.into_repr(), diff, srs)
                };
                Ok(SubsetWitness(witness))
            }
        }
    }

    /// Randomize the set commitment and the corresponding opening
    pub fn randomize(
        mut self,
        mut opening: SetCommitmentOpening<E>,
        randomness: E::Fr,
    ) -> (Self, SetCommitmentOpening<E>) {
        self.0 = self.0.mul(randomness.into_repr()).into_affine();
        opening.randomize(randomness);
        (self, opening)
    }

    /// Create a KZG polynomial commitment to the set in group G1
    fn commit_in_P1(
        r: <<E as PairingEngine>::Fr as PrimeField>::BigInt,
        set: BTreeSet<E::Fr>,
        srs: &SetCommitmentSRS<E>,
    ) -> E::G1Affine {
        srs.eval_P1(set).mul(r).into_affine()
    }
}

impl<E: PairingEngine> SetCommitmentOpening<E> {
    /// `new_randomness = `old_randomness * randomness`
    pub fn randomize(&mut self, randomness: E::Fr) {
        match self {
            SetCommitmentOpening::SetWithTrapdoor(ref mut r, _) => {
                *r *= randomness;
            }
            SetCommitmentOpening::SetWithoutTrapdoor(ref mut r) => {
                *r *= randomness;
            }
        }
    }
}

impl<E: PairingEngine> SubsetWitness<E> {
    pub fn verify(
        &self,
        subset: BTreeSet<E::Fr>,
        set_commitment: &SetCommitment<E>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if subset.len() == 0 {
            return if self.0 == set_commitment.0 {
                Ok(())
            } else {
                Err(DelegationError::InvalidWitness)
            };
        }
        let P1_table = WindowTable::new(subset.len(), srs.get_P1().into_projective());
        let s_P1 = srs.get_s_P1().into_projective();
        // Check if subset contains the trapdoor
        for s in subset.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Err(DelegationError::ShouldNotContainTrapdoor);
            }
        }
        // Check if e(witness, Ch(subset)) == e(set_commitment, P2) => e(witness, Ch(subset))*e(-set_commitment, P2) == 1
        if pairing_product::<E>(
            &[self.0, -set_commitment.0],
            &[srs.eval_P2(subset).into_affine(), *srs.get_P2()],
        )
        .is_one()
        {
            Ok(())
        } else {
            Err(DelegationError::InvalidWitness)
        }
    }
}

impl<E: PairingEngine> AggregateSubsetWitness<E> {
    /// Generates `n` challenges, 1 for each witness and computes the aggregate witness as the sum `\sum_{i in 0..n}(W_i*t_i)`
    /// where `W_i` and `t_i` are the witnesses and challenges respectively
    pub fn new<D>(
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::Fr>>,
        witnesses: Vec<SubsetWitness<E>>,
    ) -> Result<Self, DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        let n = commitments.len();
        if subsets.len() != n {
            return Err(UnequalSizeOfSequence(subsets.len(), n));
        }
        if witnesses.len() != n {
            return Err(UnequalSizeOfSequence(witnesses.len(), n));
        }
        let t = Self::challenges::<D>(witnesses.len(), &commitments, &subsets);
        Ok(Self(
            variable_base_msm(&witnesses.iter().map(|w| w.0).collect::<Vec<_>>(), &t).into_affine(),
        ))
    }

    pub fn randomize(&self, r: &E::Fr) -> Self {
        Self(self.0.mul(r.into_repr()).into_affine())
    }

    /// Memory efficient version of `Self::verify` as it does not keep the polynomial from subset union in memory
    /// but slower in runtime
    pub fn verify_memory_efficient<D>(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::Fr>>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::NeedSameNoOfCommitmentsAndSubsets(
                commitments.len(),
                subsets.len(),
            ));
        }
        let t = Self::challenges::<D>(commitments.len(), &commitments, &subsets);

        // Union of all subsets
        let mut union = BTreeSet::new();
        for s in &subsets {
            union.append(&mut s.clone());
        }
        if union.len() > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                union.len(),
                srs.size(),
            ));
        }
        let mut g1 = vec![];
        let mut g2 = vec![];
        for (i, c) in commitments.into_iter().enumerate() {
            g1.push(c.0);

            // Commit to the difference of the union and this subset
            let diff = union
                .difference(&subsets[i])
                .cloned()
                .collect::<BTreeSet<_>>();
            let p = if diff.is_empty() {
                srs.get_P2().into_projective()
            } else {
                srs.eval_P2(diff)
            };

            g2.push(p.mul(t[i].into_repr()).into_affine());
        }
        let union_eval = if union.is_empty() {
            srs.get_P2().into_projective()
        } else {
            srs.eval_P2(union)
        };
        g1.push(self.0.neg());
        g2.push(union_eval.into_affine());
        if !pairing_product::<E>(&g1, &g2).is_one() {
            return Err(DelegationError::InvalidWitness);
        }
        Ok(())
    }

    pub fn verify<D>(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::Fr>>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::NeedSameNoOfCommitmentsAndSubsets(
                commitments.len(),
                subsets.len(),
            ));
        }
        let t = Self::challenges::<D>(commitments.len(), &commitments, &subsets);
        let mut union = BTreeSet::new();
        for s in &subsets {
            union.append(&mut s.clone());
        }
        if union.len() > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                union.len(),
                srs.size(),
            ));
        }

        let l = union.len();
        let union_poly = poly_from_roots(&union.into_iter().collect::<Vec<_>>());
        let union_eval = if l == 0 {
            srs.get_P2().into_projective()
        } else {
            variable_base_msm(&srs.P2[0..=l], &union_poly.coeffs[0..=l])
        };
        let mut g1 = vec![];
        let mut g2 = vec![];
        for (i, c) in commitments.into_iter().enumerate() {
            g1.push(c.0);
            if subsets[i].is_empty() {
                g2.push(union_eval.mul(t[i].into_repr()));
                continue;
            }
            if subsets[i].len() == l {
                g2.push(srs.get_P2().mul(t[i].into_repr()));
                continue;
            }
            // Set difference is equivalent to polynomial division here
            let subset_poly = poly_from_roots(&subsets[i].clone().into_iter().collect::<Vec<_>>());
            let div_poly = union_poly.div(&subset_poly);
            let l = div_poly.coeffs.len();
            let div_eval = variable_base_msm(&srs.P2[0..l], &div_poly.coeffs[0..l]);
            g2.push(div_eval.mul(t[i].into_repr()));
        }

        g1.push(self.0.neg());
        g2.push(union_eval);
        if !pairing_product::<E>(&g1, &batch_normalize_projective_into_affine(g2)).is_one() {
            return Err(DelegationError::InvalidWitness);
        }
        Ok(())
    }

    fn challenges<D>(
        n: usize,
        commitments: &[SetCommitment<E>],
        subsets: &[BTreeSet<E::Fr>],
    ) -> Vec<E::Fr>
    where
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    {
        (0..n)
            .zip(commitments.iter().zip(subsets.iter()))
            .map(|(i, (c, s))| {
                field_elem_from_seed::<E::Fr, D>(
                    &{
                        let mut bytes = vec![];
                        bytes.extend_from_slice(&i.to_le_bytes());
                        c.serialize(&mut bytes).unwrap();
                        for j in s {
                            j.serialize(&mut bytes).unwrap()
                        }
                        bytes
                    },
                    &[],
                )
            })
            .collect::<Vec<_>>()
    }
}

// TODO: Add DisjointsetWitness

mod serialization {
    use super::*;

    impl<E: PairingEngine> CanonicalSerialize for SetCommitmentOpening<E> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::SetWithoutTrapdoor(r) => {
                    CanonicalSerialize::serialize(&0u8, &mut writer)?;
                    CanonicalSerialize::serialize(r, &mut writer)
                }
                Self::SetWithTrapdoor(r, s) => {
                    CanonicalSerialize::serialize(&1u8, &mut writer)?;
                    CanonicalSerialize::serialize(r, &mut writer)?;
                    CanonicalSerialize::serialize(s, &mut writer)
                }
            }
        }

        fn serialized_size(&self) -> usize {
            match self {
                Self::SetWithoutTrapdoor(r) => 0u8.serialized_size() + r.serialized_size(),
                Self::SetWithTrapdoor(r, s) => {
                    1u8.serialized_size() + r.serialized_size() + s.serialized_size()
                }
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::SetWithoutTrapdoor(r) => {
                    0u8.serialize_uncompressed(&mut writer)?;
                    r.serialize_uncompressed(&mut writer)
                }
                Self::SetWithTrapdoor(r, s) => {
                    1u8.serialize_uncompressed(&mut writer)?;
                    r.serialize_uncompressed(&mut writer)?;
                    s.serialize_uncompressed(&mut writer)
                }
            }
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            match self {
                Self::SetWithoutTrapdoor(r) => {
                    0u8.serialize_unchecked(&mut writer)?;
                    r.serialize_unchecked(&mut writer)
                }
                Self::SetWithTrapdoor(r, s) => {
                    1u8.serialize_unchecked(&mut writer)?;
                    r.serialize_unchecked(&mut writer)?;
                    s.serialize_unchecked(&mut writer)
                }
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::SetWithoutTrapdoor(r) => 0u8.uncompressed_size() + r.uncompressed_size(),
                Self::SetWithTrapdoor(r, s) => {
                    1u8.uncompressed_size() + r.uncompressed_size() + s.uncompressed_size()
                }
            }
        }
    }

    impl<E: PairingEngine> CanonicalDeserialize for SetCommitmentOpening<E> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let t: u8 = CanonicalDeserialize::deserialize(&mut reader)?;
            match t {
                0u8 => Ok(Self::SetWithoutTrapdoor(CanonicalDeserialize::deserialize(
                    &mut reader,
                )?)),
                1u8 => Ok(Self::SetWithTrapdoor(
                    CanonicalDeserialize::deserialize(&mut reader)?,
                    CanonicalDeserialize::deserialize(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_uncompressed(&mut reader)? {
                0u8 => Ok(Self::SetWithoutTrapdoor(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                1u8 => Ok(Self::SetWithTrapdoor(
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                    CanonicalDeserialize::deserialize_uncompressed(&mut reader)?,
                )),
                _ => Err(SerializationError::InvalidData),
            }
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            match u8::deserialize_unchecked(&mut reader)? {
                0u8 => Ok(Self::SetWithoutTrapdoor(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
                )),
                1u8 => Ok(Self::SetWithTrapdoor(
                    CanonicalDeserialize::deserialize_unchecked(&mut reader)?,
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
    use ark_bls12_381::Bls12_381;
    use ark_ec::{PairingEngine, ProjectiveCurve};
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};
    use blake2::Blake2b;
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn characteristic_poly() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (srs, td) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, 3, None);

        // let set = (0..3).map(|_| Fr::rand(&mut rng)).collect::<BTreeSet<_>>();
        let ls = (0..3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let poly = poly_from_roots(&ls);
        let eval = poly.evaluate(&td);

        // let l = sp.P1.mul(eval.into_repr()).into_affine();
        let l = srs.get_P1().mul(eval.into_repr()).into_affine();

        assert_eq!(poly.coeffs.len(), 4);
        let r = variable_base_msm(&srs.P1, &poly.coeffs).into_affine();
        assert_eq!(l, r);

        let set = ls.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            srs.eval_P1(set.clone()).into_affine(),
            srs.get_P1().mul(eval.into_repr()).into_affine()
        );
    }

    #[test]
    fn commit_and_open_full() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 10;
        let (srs, td) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_size, None);

        fn check<R: RngCore>(
            rng: &mut R,
            set_size: usize,
            pp: &SetCommitmentSRS<Bls12_381>,
            trapdoor: &Fr,
        ) {
            let set = (0..set_size)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();

            let start = Instant::now();
            let (comm, o) = SetCommitment::new(rng, set.clone(), &pp).unwrap();
            println!(
                "Time to commit to set of size {}: {:?}",
                set_size,
                start.elapsed()
            );

            comm.open_set(&o, set.clone(), &pp).unwrap();

            // Commitment with given randomness
            let r = Fr::rand(rng);
            let P_r = pp.get_P1().mul(r).into_affine();

            let start = Instant::now();
            let comm1 = SetCommitment::new_with_given_commitment_to_randomness(
                P_r,
                trapdoor,
                set.clone(),
                &pp,
            )
            .unwrap();
            println!(
                "Time to commit to set of size {} when given commitment to randomness: {:?}",
                set_size,
                start.elapsed()
            );

            let o1 = SetCommitmentOpening::SetWithoutTrapdoor(r);
            comm1.open_set(&o1, set.clone(), &pp).unwrap();

            // Randomize commitment and opening
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            comm.open_set(&o, set, &pp).unwrap();

            // Create a new set with trapdoor and check opening
            let mut new_set = (0..set_size - 1)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();
            new_set.insert(*trapdoor);
            let (comm, o) = SetCommitment::new(rng, new_set.clone(), &pp).unwrap();
            comm.open_set(&o, new_set.clone(), &pp).unwrap();

            // Randomize commitment and opening
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            comm.open_set(&o, new_set, &pp).unwrap();
        }

        // When set is same of same size as public params
        check(&mut rng, 10, &srs, &td);

        // When set is smaller than public params
        check(&mut rng, 6, &srs, &td);
    }

    #[test]
    fn commit_and_open_subset() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 10;
        let (srs, trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_size, None);

        fn check<R: RngCore>(
            rng: &mut R,
            set: BTreeSet<Fr>,
            pp: &SetCommitmentSRS<Bls12_381>,
            subset_has_trapdoor: bool,
        ) {
            let (comm, o) = SetCommitment::new(rng, set.clone(), &pp).unwrap();
            comm.open_set(&o, set.clone(), &pp).unwrap();

            // A proper subset
            let mut iter = set.iter().cloned();
            let mut subset = BTreeSet::new();
            subset.insert(iter.next().unwrap());
            subset.insert(iter.next().unwrap());
            subset.insert(iter.next().unwrap());
            let witness = comm
                .open_subset(&o, subset.clone(), set.clone(), &pp)
                .unwrap();

            witness.verify(subset.clone(), &comm, &pp).unwrap();

            // When subset is same as set
            if subset_has_trapdoor {
                assert!(comm.open_subset(&o, set.clone(), set.clone(), &pp).is_err());
            } else {
                let witness = comm.open_subset(&o, set.clone(), set.clone(), &pp).unwrap();
                witness.verify(set.clone(), &comm, &pp).unwrap();
            }

            // When subset is empty
            let witness = comm
                .open_subset(&o, BTreeSet::new(), set.clone(), &pp)
                .unwrap();
            witness.verify(BTreeSet::new(), &comm, &pp).unwrap();

            // Randomize commitment and opening and check witness
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            let witness = comm
                .open_subset(&o, subset.clone(), set.clone(), &pp)
                .unwrap();
            witness.verify(subset.clone(), &comm, &pp).unwrap();

            // Create invalid witness
            let new_set = (0..pp.size() - 2)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();
            let (comm1, o1) = SetCommitment::new(rng, new_set.clone(), &pp).unwrap();

            let witness_with_invalid_opening = comm
                .open_subset_unchecked(&o1, subset.clone(), set.clone(), &pp)
                .unwrap();
            assert!(witness_with_invalid_opening
                .verify(subset.clone(), &comm, &pp)
                .is_err());

            let witness_with_invalid_subset = comm1
                .open_subset_unchecked(&o1, subset.clone(), new_set.clone(), &pp)
                .unwrap();
            assert!(witness_with_invalid_subset
                .verify(subset, &comm1, &pp)
                .is_err());
        }

        let set = (0..max_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<BTreeSet<_>>();
        check(&mut rng, set, &srs, false);

        let set = (0..max_size - 3)
            .map(|_| Fr::rand(&mut rng))
            .collect::<BTreeSet<_>>();
        check(&mut rng, set, &srs, false);

        let mut set = (0..max_size - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<BTreeSet<_>>();
        set.insert(trapdoor);
        check(&mut rng, set, &srs, true);
    }

    #[test]
    fn subset_witness_aggregation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let count = 5;
        let set_size = 10;
        let subset_size = 3;
        let max_size = set_size * count;
        let (srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_size, None);

        let sets = (0..count)
            .map(|_| {
                (0..set_size)
                    .map(|_| Fr::rand(&mut rng))
                    .collect::<BTreeSet<_>>()
            })
            .collect::<Vec<_>>();
        let mut commitments = vec![];
        let mut openings = vec![];
        let mut subsets = vec![];
        let mut witnesses = vec![];
        let mut time_to_verify_witnesses_individually = std::time::Duration::new(0, 0);
        for i in 0..count {
            let (comm, o) = SetCommitment::new(&mut rng, sets[i].clone(), &srs).unwrap();
            let mut iter = sets[i].iter().cloned();
            let mut subset = BTreeSet::new();
            for _ in 0..subset_size {
                subset.insert(iter.next().unwrap());
                subset.insert(iter.next().unwrap());
                subset.insert(iter.next().unwrap());
            }
            let witness = comm
                .open_subset(&o, subset.clone(), sets[i].clone(), &srs)
                .unwrap();
            let start = Instant::now();
            witness.verify(subset.clone(), &comm, &srs).unwrap();
            time_to_verify_witnesses_individually += start.elapsed();

            subsets.push(subset);
            witnesses.push(witness);
            commitments.push(comm);
            openings.push(o);
        }

        let start = Instant::now();
        let witness =
            AggregateSubsetWitness::new::<Blake2b>(commitments.clone(), subsets.clone(), witnesses)
                .unwrap();
        let time_to_aggregate = start.elapsed();

        let start = Instant::now();
        witness
            .verify_memory_efficient::<Blake2b>(commitments.clone(), subsets.clone(), &srs)
            .unwrap();
        let time_to_verify_naive = start.elapsed();

        let start = Instant::now();
        witness
            .verify::<Blake2b>(commitments.clone(), subsets, &srs)
            .unwrap();
        let time_to_verify = start.elapsed();

        print!(
            "For {} witnesses of subsets of size {} from set of size {}",
            count, subset_size, set_size
        );
        println!(
            "Time to verify witnesses individually {:?}",
            time_to_verify_witnesses_individually
        );
        println!("Time to aggregate witnesses {:?}", time_to_aggregate);
        println!(
            "Time to verify aggregate witness using naive {:?}",
            time_to_verify_naive
        );
        println!("Time to verify aggregate witness {:?}", time_to_verify);

        // Aggregate witnesses from all empty subsets
        let witness0 = commitments[0]
            .open_subset(&openings[0], BTreeSet::new(), sets[0].clone(), &srs)
            .unwrap();
        let witness1 = commitments[1]
            .open_subset(&openings[1], BTreeSet::new(), sets[1].clone(), &srs)
            .unwrap();
        let witness2 = commitments[2]
            .open_subset(&openings[2], BTreeSet::new(), sets[2].clone(), &srs)
            .unwrap();

        let witness = AggregateSubsetWitness::new::<Blake2b>(
            commitments[0..3].to_vec(),
            vec![BTreeSet::new(); 3],
            vec![witness0.clone(), witness1.clone(), witness2.clone()],
        )
        .unwrap();
        witness
            .verify::<Blake2b>(commitments[0..3].to_vec(), vec![BTreeSet::new(); 3], &srs)
            .unwrap();
        witness
            .verify_memory_efficient::<Blake2b>(
                commitments[0..3].to_vec(),
                vec![BTreeSet::new(); 3],
                &srs,
            )
            .unwrap();

        // Aggregate witnesses from empty as well as non-empty subsets

        let mut iter = sets[3].iter().cloned();
        let mut subset = BTreeSet::new();
        subset.insert(iter.next().unwrap());
        subset.insert(iter.next().unwrap());
        let witness3 = commitments[3]
            .open_subset(&openings[3], subset.clone(), sets[3].clone(), &srs)
            .unwrap();

        let witness = AggregateSubsetWitness::new::<Blake2b>(
            commitments[0..4].to_vec(),
            vec![
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                subset.clone(),
            ],
            vec![witness0, witness1, witness2, witness3],
        )
        .unwrap();
        witness
            .verify::<Blake2b>(
                commitments[0..4].to_vec(),
                vec![
                    BTreeSet::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                    subset.clone(),
                ],
                &srs,
            )
            .unwrap();
        witness
            .verify_memory_efficient::<Blake2b>(
                commitments[0..4].to_vec(),
                vec![
                    BTreeSet::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                    subset.clone(),
                ],
                &srs,
            )
            .unwrap();

        // Aggregate witnesses when subsets are same as the sets
        let witness0 = commitments[0]
            .open_subset(&openings[0], sets[0].clone(), sets[0].clone(), &srs)
            .unwrap();
        let witness1 = commitments[1]
            .open_subset(&openings[1], sets[1].clone(), sets[1].clone(), &srs)
            .unwrap();
        let witness2 = commitments[2]
            .open_subset(&openings[2], sets[2].clone(), sets[2].clone(), &srs)
            .unwrap();

        let witness = AggregateSubsetWitness::new::<Blake2b>(
            commitments[0..3].to_vec(),
            vec![sets[0].clone(), sets[1].clone(), sets[2].clone()],
            vec![witness0.clone(), witness1.clone(), witness2.clone()],
        )
        .unwrap();
        witness
            .verify::<Blake2b>(
                commitments[0..3].to_vec(),
                vec![sets[0].clone(), sets[1].clone(), sets[2].clone()],
                &srs,
            )
            .unwrap();
        witness
            .verify_memory_efficient::<Blake2b>(
                commitments[0..3].to_vec(),
                vec![sets[0].clone(), sets[1].clone(), sets[2].clone()],
                &srs,
            )
            .unwrap();
    }

    #[test]
    fn timing_commitment_and_witness_creation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 100;
        let (srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_size, None);

        let step = 10;
        let mut set = BTreeSet::new();

        for _ in (step..max_size).step_by(step) {
            let new_elems = (0..step)
                .map(|_| Fr::rand(&mut rng))
                .collect::<BTreeSet<_>>();
            set.extend(new_elems.into_iter());
            let set_size = set.len();

            let start = Instant::now();
            let (comm, o) = SetCommitment::new(&mut rng, set.clone(), &srs).unwrap();
            println!(
                "Time to commit to set of size {}: {:?}",
                set_size,
                start.elapsed()
            );

            for j in (1..=step).step_by(2) {
                let mut iter = set.iter().cloned();
                let mut subset = BTreeSet::new();
                for _ in 0..j {
                    subset.insert(iter.next().unwrap());
                }
                let subset_size = subset.len();

                let start = Instant::now();
                let witness = comm
                    .open_subset(&o, subset.clone(), set.clone(), &srs)
                    .unwrap();
                let time_to_create = start.elapsed();

                let start = Instant::now();
                witness.verify(subset, &comm, &srs).unwrap();
                let time_to_verify = start.elapsed();

                println!(
                    "For witness of subset size {} from set size {}",
                    subset_size, set_size
                );
                println!("Time to create {:?}", time_to_create);
                println!("Time to verify {:?}", time_to_verify);
            }
        }
    }
}
