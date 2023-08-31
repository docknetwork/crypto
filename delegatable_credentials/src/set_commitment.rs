//! Set commitment scheme (SCDS) as defined in Fig.2 of [this paper](https://eprint.iacr.org/2021/1680.pdf)
//! Aggregation is taken from section 3.4 of [this paper](https://eprint.iacr.org/2022/680.pdf)
//! The set commitment is a KZG polynomial commitment to a monic polynomial whose roots are the set members.
//! The above paper defines the characteristic polynomial of a set as `(x+a1)*(x+a2)*(x+a3)*..` but this
//! implementation is using `(x-a1)*(x-a2)*(x-a3)*..` for set members `a1, a2, ...` to reuse existing code

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    Field, One, PrimeField, Zero,
};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};
use ark_std::{
    collections::BTreeSet,
    io::{Read, Write},
    ops::{Div, Mul, Neg},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use digest::{Digest, DynDigest};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    error::{DelegationError, DelegationError::UnequalSizeOfSequence},
    util::{generator_pair, generator_pair_deterministic},
};
use dock_crypto_utils::{
    ff::powers, hashing_utils::field_elem_from_try_and_incr, misc::le_bytes_iter, msm::WindowTable,
    poly::poly_from_roots, serde_utils::*,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// TODO: Makes sense to split this into P1 and P2 as prover does not need P2 vector and verifier does not need P1 vector
/// KZG polynomial commitment SRS (Structured Reference String) used by the set commitment scheme
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SetCommitmentSRS<E: Pairing> {
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub P1: Vec<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub P2: Vec<E::G2Affine>,
}

macro_rules! impl_srs {
    () => {
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
        pub fn eval_P1(&self, set: BTreeSet<E::ScalarField>) -> E::G1 {
            Self::eval::<E::G1Affine>(set, &self.P1)
        }

        /// Evaluate the polynomial whose roots are members of the given set at trapdoor in group G2
        pub fn eval_P2(&self, set: BTreeSet<E::ScalarField>) -> E::G2 {
            Self::eval::<E::G2Affine>(set, &self.P2)
        }

        /// Evaluate the polynomial whose roots are members of the given set
        pub fn eval<G: AffineRepr>(set: BTreeSet<G::ScalarField>, powers: &[G]) -> G::Group {
            let set_size = set.len();
            let poly = poly_from_roots(&set.into_iter().collect::<Vec<_>>());
            G::Group::msm_unchecked(&powers[0..=set_size], &poly.coeffs[0..=set_size])
        }
    };
}

impl<E: Pairing> SetCommitmentSRS<E> {
    /// Generate a trapdoor and then create the SRS and return both
    pub fn generate_with_random_trapdoor<R: RngCore, D: Digest>(
        rng: &mut R,
        max_size: u32,
        setup_params_label: Option<&[u8]>,
    ) -> (Self, E::ScalarField) {
        let td = E::ScalarField::rand(rng);
        let pp = Self::generate_with_trapdoor::<R, D>(rng, &td, max_size, setup_params_label);
        (pp, td)
    }

    /// Generates the trapdoor deterministically from the given seed and then generate SRS from it.
    pub fn generate_with_trapdoor_seed<R: RngCore, D>(
        rng: &mut R,
        max_size: u32,
        trapdoor_seed: &[u8],
        setup_params_label: Option<&[u8]>,
    ) -> (Self, E::ScalarField)
    where
        D: Digest + DynDigest + Default + Clone,
    {
        let hasher = <DefaultFieldHasher<D> as HashToField<E::ScalarField>>::new(
            b"SET-COMMITMENT_TRAPDOOR-SALT",
        );
        let td = hasher.hash_to_field(trapdoor_seed, 1).pop().unwrap();
        let pp = Self::generate_with_trapdoor::<R, D>(rng, &td, max_size, setup_params_label);
        (pp, td)
    }

    pub fn generate_with_trapdoor<R: RngCore, D: Digest>(
        rng: &mut R,
        td: &E::ScalarField,
        max_size: u32,
        setup_params_label: Option<&[u8]>,
    ) -> Self {
        let (P1, P2) = match setup_params_label {
            Some(label) => generator_pair_deterministic::<E, D>(label),
            None => generator_pair::<E, R>(rng),
        };
        let powers = powers(td, max_size + 1);
        let P1_table = WindowTable::new(max_size as usize + 1, P1.into_group());
        let P2_table = WindowTable::new(max_size as usize + 1, P2.into_group());
        Self {
            P1: E::G1::normalize_batch(&P1_table.multiply_many(&powers)),
            P2: E::G2::normalize_batch(&P2_table.multiply_many(&powers)),
        }
    }

    impl_srs!();
}

#[serde_as]
#[derive(
    Clone, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedSetCommitmentSRS<E: Pairing> {
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub P1: Vec<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub P2: Vec<E::G2Affine>,
    #[serde_as(as = "ArkObjectBytes")]
    pub prepared_P2: E::G2Prepared,
}

impl<E: Pairing> From<SetCommitmentSRS<E>> for PreparedSetCommitmentSRS<E> {
    fn from(srs: SetCommitmentSRS<E>) -> Self {
        let prepared_P2 = E::G2Prepared::from(*srs.get_P2());
        Self {
            P1: srs.P1,
            P2: srs.P2,
            prepared_P2,
        }
    }
}

impl<E: Pairing> PreparedSetCommitmentSRS<E> {
    impl_srs!();
}

/// Commitment to a set
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetCommitment<E: Pairing>(pub E::G1Affine);

/// Opening to the set commitment. Contains the randomness in the commitment.
#[derive(Clone, Debug)]
pub enum SetCommitmentOpening<E: Pairing> {
    /// When the committed set doesn't have the trapdoor.
    SetWithoutTrapdoor(E::ScalarField),
    /// When the committed set has the trapdoor. 1st element is the randomness used in the commitment and 2nd element is the trapdoor
    SetWithTrapdoor(E::ScalarField, E::ScalarField),
}

/// Witness of the subset of set which is committed in certain commitment. It is commitment to difference of
/// the set and this subset. Used in proving that a certain set is indeed the subset of a committed set.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SubsetWitness<E: Pairing>(pub E::G1Affine);

/// A constant size aggregation of several subset witnesses
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AggregateSubsetWitness<E: Pairing>(pub E::G1Affine);

impl<E: Pairing> SetCommitment<E> {
    /// Commit to the given set.
    pub fn new<R: RngCore>(
        rng: &mut R,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, SetCommitmentOpening<E>), DelegationError> {
        let r = E::ScalarField::rand(rng);
        Self::new_with_given_randomness(r, set, srs)
    }

    /// Commit to the given set with provided randomness
    pub fn new_with_given_randomness(
        randomness: E::ScalarField,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, SetCommitmentOpening<E>), DelegationError> {
        let set_size = set.len();

        if set_size > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                set_size,
                srs.size(),
            ));
        }

        let P1_table = WindowTable::new(set_size, srs.get_P1().into_group());
        let s_P1 = srs.get_s_P1().into_group();
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
            SetCommitment(Self::commit_in_P1(randomness.into_bigint(), set, srs)),
            SetCommitmentOpening::SetWithoutTrapdoor(randomness),
        ))
    }

    /// Commit to the given set when provided with a commitment to the randomness.
    /// It is assumed that `comm_rand` is indeed of the form `r*P1` where `r` is the randomness. A PoK would
    /// be verified by the caller before calling this function.
    pub fn new_with_given_commitment_to_randomness(
        comm_rand: E::G1Affine,
        trapdoor: &E::ScalarField,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        let set_size = set.len();

        if set_size > srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                set_size,
                srs.size(),
            ));
        }

        let P1_table = WindowTable::new(set_size, srs.get_P1().into_group());
        let s_P1 = srs.get_s_P1().into_group();
        // Check if set contains the trapdoor
        for s in set.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Ok(SetCommitment(comm_rand));
            }
        }
        let mut prod = E::ScalarField::one();
        for s in set {
            prod *= *trapdoor - s;
        }
        Ok(SetCommitment(comm_rand.mul(prod).into_affine()))
    }

    /// Checks if the commitment can be opened with the given opening and for the given set.
    pub fn open_set(
        &self,
        opening: &SetCommitmentOpening<E>,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        match opening {
            SetCommitmentOpening::SetWithTrapdoor(r, s) => {
                let P1 = srs.get_P1().into_group();
                let s_P1 = P1.mul_bigint(s.into_bigint()).into_affine();
                let C = P1.mul_bigint(r.into_bigint()).into_affine();
                if !set.contains(s) || (C != self.0) || (s_P1 != *srs.get_s_P1()) {
                    return Err(DelegationError::InvalidOpening);
                }
                Ok(())
            }
            SetCommitmentOpening::SetWithoutTrapdoor(r) => {
                if Self::commit_in_P1(r.into_bigint(), set, srs) != self.0 {
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
        subset: BTreeSet<E::ScalarField>,
        set: BTreeSet<E::ScalarField>,
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
        subset: BTreeSet<E::ScalarField>,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<SubsetWitness<E>, DelegationError> {
        let subset_size = subset.len();
        if subset_size == 0 {
            return Ok(SubsetWitness(self.0));
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
                    srs.get_P1().mul_bigint(r.into_bigint()).into_affine()
                } else {
                    // Commit to remaining elements
                    Self::commit_in_P1(r.into_bigint(), diff, srs)
                };
                Ok(SubsetWitness(witness))
            }
        }
    }

    /// Randomize the set commitment and the corresponding opening
    pub fn randomize(
        mut self,
        mut opening: SetCommitmentOpening<E>,
        randomness: E::ScalarField,
    ) -> (Self, SetCommitmentOpening<E>) {
        self.0 = self.0.mul_bigint(randomness.into_bigint()).into_affine();
        opening.randomize(randomness);
        (self, opening)
    }

    /// Create a KZG polynomial commitment to the set in group G1
    fn commit_in_P1(
        r: <E::ScalarField as PrimeField>::BigInt,
        set: BTreeSet<E::ScalarField>,
        srs: &SetCommitmentSRS<E>,
    ) -> E::G1Affine {
        srs.eval_P1(set).mul_bigint(r).into_affine()
    }
}

impl<E: Pairing> SetCommitmentOpening<E> {
    /// `new_randomness = `old_randomness * randomness`
    pub fn randomize(&mut self, randomness: E::ScalarField) {
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

impl<E: Pairing> SubsetWitness<E> {
    pub fn verify<'a>(
        &self,
        subset: BTreeSet<E::ScalarField>,
        set_commitment: &SetCommitment<E>,
        srs: impl Into<&'a PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        if subset.is_empty() {
            return if self.0 == set_commitment.0 {
                Ok(())
            } else {
                Err(DelegationError::InvalidWitness)
            };
        }
        let srs = srs.into();
        let P1_table = WindowTable::new(subset.len(), srs.get_P1().into_group());
        let s_P1 = srs.get_s_P1().into_group();
        // Check if subset contains the trapdoor
        for s in subset.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Err(DelegationError::ShouldNotContainTrapdoor);
            }
        }
        // Check if e(witness, Ch(subset)) == e(set_commitment, P2) => e(witness, Ch(subset))*e(-set_commitment, P2) == 1
        if E::multi_pairing(
            [self.0, (-set_commitment.0.into_group()).into_affine()],
            [
                E::G2Prepared::from(srs.eval_P2(subset)),
                srs.prepared_P2.clone(),
            ],
        )
        .is_zero()
        {
            Ok(())
        } else {
            Err(DelegationError::InvalidWitness)
        }
    }
}

impl<E: Pairing> AggregateSubsetWitness<E> {
    /// Generates `n` challenges, 1 for each witness and computes the aggregate witness as the sum `\sum_{i in 0..n}(W_i*t_i)`
    /// where `W_i` and `t_i` are the witnesses and challenges respectively
    pub fn new<D: Digest>(
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::ScalarField>>,
        witnesses: Vec<SubsetWitness<E>>,
    ) -> Result<Self, DelegationError> {
        let n = commitments.len();
        if subsets.len() != n {
            return Err(UnequalSizeOfSequence(subsets.len(), n));
        }
        if witnesses.len() != n {
            return Err(UnequalSizeOfSequence(witnesses.len(), n));
        }
        let t = Self::challenges::<D>(
            witnesses
                .len()
                .try_into()
                .map_err(|_| DelegationError::TooManyWitnesses(witnesses.len()))?,
            &commitments,
            &subsets,
        );
        Ok(Self(
            E::G1::msm_unchecked(&witnesses.iter().map(|w| w.0).collect::<Vec<_>>(), &t)
                .into_affine(),
        ))
    }

    pub fn randomize(&self, r: &E::ScalarField) -> Self {
        Self(self.0.mul_bigint(r.into_bigint()).into_affine())
    }

    /// Memory efficient version of `Self::verify` as it does not keep the polynomial from subset union in memory
    /// but slower in runtime
    pub fn verify_memory_efficient<D: Digest>(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::ScalarField>>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::NeedSameNoOfCommitmentsAndSubsets(
                commitments.len(),
                subsets.len(),
            ));
        }
        let t = Self::challenges::<D>(
            commitments
                .len()
                .try_into()
                .map_err(|_| DelegationError::TooManyCommitments(commitments.len()))?,
            &commitments,
            &subsets,
        );

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
                srs.get_P2().into_group()
            } else {
                srs.eval_P2(diff)
            };

            g2.push(p.mul_bigint(t[i].into_bigint()));
        }
        let union_eval = if union.is_empty() {
            srs.get_P2().into_group()
        } else {
            srs.eval_P2(union)
        };
        g1.push(self.0.into_group().neg().into());
        g2.push(union_eval);
        if !E::multi_pairing(g1, E::G2::normalize_batch(&g2)).is_zero() {
            return Err(DelegationError::InvalidWitness);
        }
        Ok(())
    }

    pub fn verify<D: Digest>(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<BTreeSet<E::ScalarField>>,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::NeedSameNoOfCommitmentsAndSubsets(
                commitments.len(),
                subsets.len(),
            ));
        }
        let t = Self::challenges::<D>(
            commitments
                .len()
                .try_into()
                .map_err(|_| DelegationError::TooManyCommitments(commitments.len()))?,
            &commitments,
            &subsets,
        );
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
            srs.get_P2().into_group()
        } else {
            E::G2::msm_unchecked(&srs.P2[0..=l], &union_poly.coeffs[0..=l])
        };
        let mut g1 = vec![];
        let mut g2 = vec![];
        for (i, c) in commitments.into_iter().enumerate() {
            g1.push(c.0);
            if subsets[i].is_empty() {
                g2.push(union_eval.mul_bigint(t[i].into_bigint()));
                continue;
            }
            if subsets[i].len() == l {
                g2.push(srs.get_P2().mul_bigint(t[i].into_bigint()));
                continue;
            }
            // Set difference is equivalent to polynomial division here
            let subset_poly = poly_from_roots(&subsets[i].clone().into_iter().collect::<Vec<_>>());
            let div_poly = union_poly.div(&subset_poly);
            let l = div_poly.coeffs.len();
            let div_eval = E::G2::msm_unchecked(&srs.P2[0..l], &div_poly.coeffs[0..l]);
            g2.push(div_eval.mul_bigint(t[i].into_bigint()));
        }

        g1.push((-self.0.into_group()).into_affine());
        g2.push(union_eval);
        if !E::multi_pairing(g1, E::G2::normalize_batch(&g2)).is_zero() {
            return Err(DelegationError::InvalidWitness);
        }
        Ok(())
    }

    fn challenges<D: Digest>(
        n: u32,
        commitments: &[SetCommitment<E>],
        subsets: &[BTreeSet<E::ScalarField>],
    ) -> Vec<E::ScalarField> {
        le_bytes_iter(n)
            .zip(commitments)
            .zip(subsets)
            .map(|((ctr_bytes, c), s)| {
                let mut bytes = vec![];
                bytes.extend_from_slice(&ctr_bytes);
                c.serialize_compressed(&mut bytes).unwrap();
                for j in s {
                    j.serialize_compressed(&mut bytes).unwrap()
                }

                field_elem_from_try_and_incr::<_, D>(&bytes)
            })
            .collect()
    }
}

// TODO: Add DisjointsetWitness

mod serialization {
    use super::*;
    use ark_serialize::{Compress, Validate};

    impl<E: Pairing> Valid for SetCommitmentOpening<E> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::SetWithoutTrapdoor(r) => r.check(),
                Self::SetWithTrapdoor(r, s) => {
                    r.check()?;
                    s.check()
                }
            }
        }
    }

    impl<E: Pairing> CanonicalSerialize for SetCommitmentOpening<E> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::SetWithoutTrapdoor(r) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)
                }
                Self::SetWithTrapdoor(r, s) => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(s, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::SetWithoutTrapdoor(r) => {
                    0u8.serialized_size(compress) + r.serialized_size(compress)
                }
                Self::SetWithTrapdoor(r, s) => {
                    1u8.serialized_size(compress)
                        + r.serialized_size(compress)
                        + s.serialized_size(compress)
                }
            }
        }
    }

    impl<E: Pairing> CanonicalDeserialize for SetCommitmentOpening<E> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::SetWithoutTrapdoor(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                )),
                1u8 => Ok(Self::SetWithTrapdoor(
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
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
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn characteristic_poly() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let (srs, td) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, 3, None);

        // let set = (0..3).map(|_| Fr::rand(&mut rng)).collect::<BTreeSet<_>>();
        let ls = (0..3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let poly = poly_from_roots(&ls);
        let eval = poly.evaluate(&td);

        // let l = sp.P1.mul(eval.into_bigint()).into_affine();
        let l = srs.get_P1().mul_bigint(eval.into_bigint()).into_affine();

        assert_eq!(poly.coeffs.len(), 4);
        let r = <Bls12_381 as Pairing>::G1::msm_unchecked(&srs.P1, &poly.coeffs).into_affine();
        assert_eq!(l, r);

        let set = ls.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            srs.eval_P1(set).into_affine(),
            srs.get_P1().mul_bigint(eval.into_bigint()).into_affine()
        );
    }

    #[test]
    fn commit_and_open_full() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 10;
        let (srs, td) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, max_size, None);

        fn check<R: RngCore>(
            rng: &mut R,
            set_size: u32,
            pp: &SetCommitmentSRS<Bls12_381>,
            trapdoor: &Fr,
        ) {
            let set = (0..set_size)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();

            let start = Instant::now();
            let (comm, o) = SetCommitment::new(rng, set.clone(), pp).unwrap();
            println!(
                "Time to commit to set of size {}: {:?}",
                set_size,
                start.elapsed()
            );

            comm.open_set(&o, set.clone(), pp).unwrap();

            // Commitment with given randomness
            let r = Fr::rand(rng);
            let P_r = pp.get_P1().mul(r).into_affine();

            let start = Instant::now();
            let comm1 = SetCommitment::new_with_given_commitment_to_randomness(
                P_r,
                trapdoor,
                set.clone(),
                pp,
            )
            .unwrap();
            println!(
                "Time to commit to set of size {} when given commitment to randomness: {:?}",
                set_size,
                start.elapsed()
            );

            let o1 = SetCommitmentOpening::SetWithoutTrapdoor(r);
            comm1.open_set(&o1, set.clone(), pp).unwrap();

            // Randomize commitment and opening
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            comm.open_set(&o, set, pp).unwrap();

            // Create a new set with trapdoor and check opening
            let mut new_set = (0..set_size - 1)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();
            new_set.insert(*trapdoor);
            let (comm, o) = SetCommitment::new(rng, new_set.clone(), pp).unwrap();
            comm.open_set(&o, new_set.clone(), pp).unwrap();

            // Randomize commitment and opening
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            comm.open_set(&o, new_set, pp).unwrap();
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
            Blake2b512,
        >(&mut rng, max_size, None);

        fn check<R: RngCore>(
            rng: &mut R,
            set: BTreeSet<Fr>,
            pp: &SetCommitmentSRS<Bls12_381>,
            subset_has_trapdoor: bool,
        ) {
            let (comm, o) = SetCommitment::new(rng, set.clone(), pp).unwrap();
            comm.open_set(&o, set.clone(), pp).unwrap();

            let prep_pp = PreparedSetCommitmentSRS::from(pp.clone());

            // A proper subset
            let mut iter = set.iter().cloned();
            let mut subset = BTreeSet::new();
            subset.insert(iter.next().unwrap());
            subset.insert(iter.next().unwrap());
            subset.insert(iter.next().unwrap());
            let witness = comm
                .open_subset(&o, subset.clone(), set.clone(), pp)
                .unwrap();

            witness.verify(subset.clone(), &comm, &prep_pp).unwrap();

            // When subset is same as set
            if subset_has_trapdoor {
                assert!(comm.open_subset(&o, set.clone(), set.clone(), pp).is_err());
            } else {
                let witness = comm.open_subset(&o, set.clone(), set.clone(), pp).unwrap();
                witness.verify(set.clone(), &comm, &prep_pp).unwrap();
            }

            // When subset is empty
            let witness = comm
                .open_subset(&o, BTreeSet::new(), set.clone(), pp)
                .unwrap();
            witness.verify(BTreeSet::new(), &comm, &prep_pp).unwrap();

            // Randomize commitment and opening and check witness
            let r = Fr::rand(rng);
            let (comm, o) = comm.randomize(o, r);
            let witness = comm
                .open_subset(&o, subset.clone(), set.clone(), pp)
                .unwrap();
            witness.verify(subset.clone(), &comm, &prep_pp).unwrap();

            // Create invalid witness
            let new_set = (0..pp.size() - 2)
                .map(|_| Fr::rand(rng))
                .collect::<BTreeSet<_>>();
            let (comm1, o1) = SetCommitment::new(rng, new_set.clone(), pp).unwrap();

            let witness_with_invalid_opening = comm
                .open_subset_unchecked(&o1, subset.clone(), set.clone(), pp)
                .unwrap();
            assert!(witness_with_invalid_opening
                .verify(subset.clone(), &comm, &prep_pp)
                .is_err());

            let witness_with_invalid_subset = comm1
                .open_subset_unchecked(&o1, subset.clone(), new_set, pp)
                .unwrap();
            assert!(witness_with_invalid_subset
                .verify(subset, &comm1, &prep_pp)
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
            Blake2b512,
        >(&mut rng, max_size, None);

        let prep_srs = PreparedSetCommitmentSRS::from(srs.clone());

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
        for i in 0..count as usize {
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
            witness.verify(subset.clone(), &comm, &prep_srs).unwrap();
            time_to_verify_witnesses_individually += start.elapsed();

            subsets.push(subset);
            witnesses.push(witness);
            commitments.push(comm);
            openings.push(o);
        }

        let start = Instant::now();
        let witness = AggregateSubsetWitness::new::<Blake2b512>(
            commitments.clone(),
            subsets.clone(),
            witnesses,
        )
        .unwrap();
        let time_to_aggregate = start.elapsed();

        let start = Instant::now();
        witness
            .verify_memory_efficient::<Blake2b512>(commitments.clone(), subsets.clone(), &srs)
            .unwrap();
        let time_to_verify_naive = start.elapsed();

        let start = Instant::now();
        witness
            .verify::<Blake2b512>(commitments.clone(), subsets, &srs)
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

        let witness = AggregateSubsetWitness::new::<Blake2b512>(
            commitments[0..3].to_vec(),
            vec![BTreeSet::new(); 3],
            vec![witness0.clone(), witness1.clone(), witness2.clone()],
        )
        .unwrap();
        witness
            .verify::<Blake2b512>(commitments[0..3].to_vec(), vec![BTreeSet::new(); 3], &srs)
            .unwrap();
        witness
            .verify_memory_efficient::<Blake2b512>(
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

        let witness = AggregateSubsetWitness::new::<Blake2b512>(
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
            .verify::<Blake2b512>(
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
            .verify_memory_efficient::<Blake2b512>(
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

        let witness = AggregateSubsetWitness::new::<Blake2b512>(
            commitments[0..3].to_vec(),
            vec![sets[0].clone(), sets[1].clone(), sets[2].clone()],
            vec![witness0, witness1, witness2],
        )
        .unwrap();
        witness
            .verify::<Blake2b512>(
                commitments[0..3].to_vec(),
                vec![sets[0].clone(), sets[1].clone(), sets[2].clone()],
                &srs,
            )
            .unwrap();
        witness
            .verify_memory_efficient::<Blake2b512>(
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
            Blake2b512,
        >(&mut rng, max_size, None);

        let prep_srs = PreparedSetCommitmentSRS::from(srs.clone());

        let step = 10;
        let mut set = BTreeSet::new();

        for _ in (step..max_size).step_by(step as usize) {
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
                witness.verify(subset, &comm, &prep_srs).unwrap();
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
