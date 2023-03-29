use crate::error::DelegationError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Mul, Neg},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use dock_crypto_utils::poly::poly_from_roots;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(
    Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct SecretKey<E: Pairing>(pub E::ScalarField);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<E: Pairing>(pub E::G2Affine);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedPublicKey<E: Pairing>(pub E::G2Prepared);

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        Self(E::ScalarField::rand(rng))
    }
}

impl<E: Pairing> PublicKey<E> {
    pub fn new(secret_key: &SecretKey<E>, P2: &E::G2Affine) -> Self {
        Self(P2.mul_bigint(secret_key.0.into_bigint()).into_affine())
    }
}

impl<E: Pairing> From<PublicKey<E>> for PreparedPublicKey<E> {
    fn from(pk: PublicKey<E>) -> Self {
        Self(E::G2Prepared::from(pk.0))
    }
}

/// The accumulator. Contains (`(\prod_{i}(trapdoor - members[i]) * 1/secret_key) * P1`, `(\prod_{i}(trapdoor - members[i]) * 1/secret_key)`, `\prod_{i}(trapdoor - members[i])`)
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Accumulator<E: Pairing>(pub E::G1Affine, pub E::ScalarField, pub E::ScalarField);

/// As an optimization for creating non-membership witnesses, the accumulator manager can persist the accumulator polynomial
/// and keep it updated as per the accumulator. This is the polynomial with the roots as the current accumulator members
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AccumulatorPolynomial<E: Pairing>(pub DensePolynomial<E::ScalarField>);

/// Non-membership witness
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct NonMembershipWitness<E: Pairing>(pub E::G2Affine, pub E::ScalarField);

/// Randomized version of the non-membership witness. Used to remain unlinkable while proving non-membership during credential show.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomizedNonMembershipWitness<E: Pairing>(pub E::G2Affine, pub E::G1Affine);

impl<E: Pairing> Accumulator<E> {
    /// Create a new accumulator using the trapdoor and the secret key. It can be created without the
    /// knowledge of the trapdoor but that will be expensive so a more practical approach is for the accumulator
    /// manager to know the trapdoor.
    pub fn new_using_trapdoor(
        members: &[E::ScalarField],
        trapdoor: &E::ScalarField,
        secret_key: &SecretKey<E>,
        P1: &E::G1Affine,
    ) -> (Self, AccumulatorPolynomial<E>) {
        // `accumulator = (\prod_{i}(trapdoor - members[i]) * 1/secret_key) * P1`
        let accum_poly = poly_from_roots::<E::ScalarField>(members);
        let eval = accum_poly.evaluate(trapdoor);
        let aux = secret_key.0.inverse().unwrap() * eval;
        (
            Self(P1.mul_bigint(aux.into_bigint()).into_affine(), aux, eval),
            AccumulatorPolynomial(accum_poly),
        )
    }

    pub fn add_using_trapdoor(&mut self, additions: &[E::ScalarField], trapdoor: &E::ScalarField) {
        let eval = Self::eval_at_trapdoor(additions, trapdoor);
        self.0 = self.0.mul_bigint(eval.into_bigint()).into_affine();
        self.1 *= eval;
        self.2 *= eval;
    }

    pub fn remove_using_trapdoor(
        &mut self,
        removals: &[E::ScalarField],
        trapdoor: &E::ScalarField,
    ) {
        let eval = Self::eval_at_trapdoor(removals, trapdoor);
        let eval_inv = eval.inverse().unwrap();
        self.0 = self.0.mul_bigint(eval_inv.into_bigint()).into_affine();
        self.1 *= eval_inv;
        self.2 *= eval_inv;
    }

    pub fn accumulated(&self) -> &E::G1Affine {
        &self.0
    }

    fn eval_at_trapdoor(elements: &[E::ScalarField], trapdoor: &E::ScalarField) -> E::ScalarField {
        elements
            .iter()
            .fold(E::ScalarField::one(), |p, e| (*trapdoor - *e) * p)
    }
}

impl<E: Pairing> AccumulatorPolynomial<E> {
    pub fn add_using_trapdoor(&mut self, additions: &[E::ScalarField], trapdoor: &E::ScalarField) {
        let eval = Accumulator::<E>::eval_at_trapdoor(additions, trapdoor);
        self.0 = &self.0 * eval;
    }

    pub fn remove_using_trapdoor(
        &mut self,
        removals: &[E::ScalarField],
        trapdoor: &E::ScalarField,
    ) {
        let eval = Accumulator::<E>::eval_at_trapdoor(removals, trapdoor);
        self.0 = &self.0 * eval.inverse().unwrap();
    }
}

impl<E: Pairing> NonMembershipWitness<E> {
    /// Create from all current members of the accumulator. Using the trapdoor as its more efficient.
    pub fn from_members_using_trapdoor(
        non_member: &E::ScalarField,
        members: &[E::ScalarField],
        trapdoor: &E::ScalarField,
        P2: &E::G2Affine,
    ) -> Result<Self, DelegationError> {
        let poly = DenseOrSparsePolynomial::from(poly_from_roots(members));
        Self::from_poly(non_member, poly, trapdoor, P2)
    }

    /// This is broken for now.
    // TODO: Fix me
    pub fn from_eval_using_trapdoor(
        non_member: &E::ScalarField,
        eval: &E::ScalarField,
        trapdoor: &E::ScalarField,
        P2: &E::G2Affine,
    ) -> Result<Self, DelegationError> {
        use num_integer::Integer;

        let div = (*trapdoor - *non_member).into_bigint().into();
        let eval_repr = eval.into_bigint().into();
        let (q, d) = eval_repr.div_rem(&div);
        let q = E::ScalarField::from(q);
        let d = E::ScalarField::from(d);
        Ok(Self(P2.mul(q).into_affine(), d))
    }

    /// Create from the accumulator polynomial. Much more efficient than `Self::from_members_using_trapdoor`
    pub fn from_polynomial_using_trapdoor(
        non_member: &E::ScalarField,
        polynomial: &AccumulatorPolynomial<E>,
        trapdoor: &E::ScalarField,
        P2: &E::G2Affine,
    ) -> Result<Self, DelegationError> {
        let poly = DenseOrSparsePolynomial::from(&polynomial.0);
        Self::from_poly(non_member, poly, trapdoor, P2)
    }

    pub fn verify(
        &self,
        non_member: &E::ScalarField,
        accumulated: &E::G1Affine,
        pk: impl Into<PreparedPublicKey<E>>,
        P1_s: &E::G1Affine,
        P1: &E::G1Affine,
        P2: impl Into<E::G2Prepared>,
    ) -> bool {
        // `e1 = P1*(trapdoor - non_member) = P1*trapdoor - P1*non_member`
        let P1_n = P1.mul_bigint(non_member.into_bigint()).neg();
        let e1 = (P1_n + P1_s).into_affine();
        let P1_d = P1.mul_bigint(self.1.into_bigint()).into_affine();
        // Check e(accumulator, P2) == e(P1*(trapdoor - non_member), witness) * e(P1*d, P2) => e(P1*(trapdoor - non_member), witness) * e(P1*d, P2) * e(-accumulator, P2) == 1
        E::multi_pairing(
            [e1, P1_d, (-accumulated.into_group()).into_affine()],
            [E::G2Prepared::from(self.0), P2.into(), pk.into().0],
        )
        .is_zero()
    }

    /// Divide the given polynomial by another polynomial (x - `non_member`) to get a quotient polynomial
    /// `q` and remainder `d` and then evaluate `q` at `trapdoor`
    fn from_poly(
        non_member: &E::ScalarField,
        polynomial: DenseOrSparsePolynomial<E::ScalarField>,
        trapdoor: &E::ScalarField,
        P2: &E::G2Affine,
    ) -> Result<Self, DelegationError> {
        let divisor = DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_slice(&[
            -*non_member,
            E::ScalarField::one(),
        ]));
        let (q, d) = polynomial.divide_with_q_and_r(&divisor).unwrap();
        // Remainder `d` must be of degree 0 as the divisor polynomial is of degree 1.
        if d.coeffs.len() == 1 {
            Ok(Self(
                P2.mul(q.evaluate(trapdoor)).into_affine(),
                d.coeffs[0],
            ))
        } else {
            // `d` is 0 means `divisor` divides `polynomial`
            Err(DelegationError::AlreadyAMember)
        }
    }
}

impl<E: Pairing> RandomizedNonMembershipWitness<E> {
    pub fn verify(
        &self,
        randomized_accumulated: &E::G1Affine,
        randomized_factor: &E::G1Affine,
        pk: impl Into<PreparedPublicKey<E>>,
        P2: impl Into<E::G2Prepared>,
    ) -> bool {
        E::multi_pairing(
            [
                *randomized_factor,
                self.1,
                (-randomized_accumulated.into_group()).into_affine(),
            ],
            [E::G2Prepared::from(self.0), P2.into(), pk.into().0],
        )
        .is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_commitment::SetCommitmentSRS;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;
    type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;

    #[test]
    fn add_remove() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 100;
        let (srs, trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, max_size, None);

        let sk = SecretKey::<Bls12_381>::new(&mut rng);

        let m1 = (0..6).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let m2 = (0..3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let mut m3 = m1.clone();
        m3.extend_from_slice(&m2);

        let (mut a1, _) = Accumulator::new_using_trapdoor(&m1, &trapdoor, &sk, srs.get_P1());
        let (a2, _) = Accumulator::new_using_trapdoor(&m2, &trapdoor, &sk, srs.get_P1());
        let (mut a3, _) = Accumulator::new_using_trapdoor(&m3, &trapdoor, &sk, srs.get_P1());

        a1.add_using_trapdoor(&m2, &trapdoor);
        assert_eq!(a1, a3);

        a3.remove_using_trapdoor(&m1, &trapdoor);
        assert_eq!(a2, a3);
    }

    #[test]
    fn non_membership_witness() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 100;
        let (srs, trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, max_size, None);

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::<Bls12_381>::new(&sk, srs.get_P2());

        let prep_P2 = G2Prepared::from(*srs.get_P2());
        let prep_pk = PreparedPublicKey::from(pk);

        let m1 = (0..6).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let (mut a1, mut accum_poly) =
            Accumulator::new_using_trapdoor(&m1, &trapdoor, &sk, srs.get_P1());

        let non_member = Fr::rand(&mut rng);
        let wit1 = NonMembershipWitness::from_members_using_trapdoor(
            &non_member,
            &m1,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        assert!(wit1.verify(
            &non_member,
            a1.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        let wit1_from_poly = NonMembershipWitness::from_polynomial_using_trapdoor(
            &non_member,
            &accum_poly,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        assert!(wit1_from_poly.verify(
            &non_member,
            a1.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));
        assert_eq!(wit1, wit1_from_poly);

        // TODO: Fix me
        /*let wit1_from_eval = NonMembershipWitness::<Bls12_381>::from_eval_using_trapdoor(
            &non_member,
            &a1.2,
            &trapdoor,
            srs.get_P2(),
        )
            .unwrap();
        assert_eq!(wit1.0, wit1_from_eval.0);
        assert_eq!(wit1.1, wit1_from_eval.1);
        assert!(wit1_from_eval.verify(
            &non_member,
            a1.accumulated(),
            &pk,
            srs.get_s_P1(),
            srs.get_P1(),
            srs.get_P2()
        ));*/

        let mut a2 = a1.clone();

        let m2 = (0..2).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        a1.add_using_trapdoor(&m2, &trapdoor);

        // Old witness does not verify for new accumulator
        assert!(!wit1.verify(
            &non_member,
            a1.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        // Old witness verifies for old accumulator
        assert!(wit1.verify(
            &non_member,
            a2.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        accum_poly.add_using_trapdoor(&m2, &trapdoor);
        let wit2_from_poly = NonMembershipWitness::from_polynomial_using_trapdoor(
            &non_member,
            &accum_poly,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        assert!(wit2_from_poly.verify(
            &non_member,
            a1.accumulated(),
            prep_pk,
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2
        ));

        // Cannot create non-membership witness for a member
        let mut m3 = m2.clone();
        m3.push(non_member);
        a2.add_using_trapdoor(&[non_member], &trapdoor);
        assert!(
            NonMembershipWitness::<Bls12_381>::from_members_using_trapdoor(
                &non_member,
                &m3,
                &trapdoor,
                srs.get_P2()
            )
            .is_err()
        );
    }

    #[test]
    fn timing_non_membership_witness() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 5000;
        let (srs, trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, max_size, None);

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::<Bls12_381>::new(&sk, srs.get_P2());

        let prep_P2 = G2Prepared::from(*srs.get_P2());
        let prep_pk = PreparedPublicKey::from(pk);

        let mut members = (0..1000).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let (mut accum, mut accum_poly) =
            Accumulator::new_using_trapdoor(&members, &trapdoor, &sk, srs.get_P1());

        let non_member = Fr::rand(&mut rng);

        let start = Instant::now();
        let wit1 = NonMembershipWitness::from_members_using_trapdoor(
            &non_member,
            &members,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        println!(
            "Creating a non-membership witness from an accumulator of {} members takes: {:?}",
            members.len(),
            start.elapsed()
        );

        assert!(wit1.verify(
            &non_member,
            accum.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        let start = Instant::now();
        let wit1_from_poly = NonMembershipWitness::from_polynomial_using_trapdoor(
            &non_member,
            &accum_poly,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        println!("Creating a non-membership witness from an accumulator of {} members using the accumulator polynomial takes: {:?}", members.len(), start.elapsed());

        assert!(wit1_from_poly.verify(
            &non_member,
            accum.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        let mut additions = (0..1000).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let start = Instant::now();
        accum.add_using_trapdoor(&additions, &trapdoor);
        println!(
            "Updating accumulator with {} members takes: {:?}",
            additions.len(),
            start.elapsed()
        );

        let start = Instant::now();
        accum_poly.add_using_trapdoor(&additions, &trapdoor);
        println!(
            "Updating accumulator polynomial with {} members takes: {:?}",
            additions.len(),
            start.elapsed()
        );

        members.append(&mut additions);

        let start = Instant::now();
        let wit2 = NonMembershipWitness::<Bls12_381>::from_members_using_trapdoor(
            &non_member,
            &members,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        println!(
            "Creating a non-membership witness from an accumulator of {} members takes: {:?}",
            members.len(),
            start.elapsed()
        );

        assert!(wit2.verify(
            &non_member,
            accum.accumulated(),
            prep_pk.clone(),
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2.clone()
        ));

        let start = Instant::now();
        let wi2_from_poly = NonMembershipWitness::from_polynomial_using_trapdoor(
            &non_member,
            &accum_poly,
            &trapdoor,
            srs.get_P2(),
        )
        .unwrap();
        println!("Creating a non-membership witness from an accumulator of {} members using the accumulator polynomial takes: {:?}", members.len(), start.elapsed());

        assert!(wi2_from_poly.verify(
            &non_member,
            accum.accumulated(),
            prep_pk,
            srs.get_s_P1(),
            srs.get_P1(),
            prep_P2
        ));
    }
}
