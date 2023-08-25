//! Proof of partial knowledge protocol as described in section 4 of the paper "Compressing Proofs of k-Out-Of-n".
//! Implements both for single witness DLs and DLs involving witness vector

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use ark_poly::{
    polynomial::{univariate::DensePolynomial, DenseUVPolynomial},
    Polynomial,
};
use ark_std::{
    cfg_into_iter, cfg_iter,
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};

use crate::{error::CompSigmaError, transforms::Homomorphism, utils::multiples_with_n_powers_of_i};

use dock_crypto_utils::poly::multiply_many_polys;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Create polynomial referred to p(X) in the paper. p(0) = 1 and p(X) = 0 for all X in given vector `x`,
/// thus its a polynomial of degree `x.len()`. From Lagrange interpolation, the polynomial is
/// \sum_{j in 0..=k}(y_j * l_j(x)). Since all except one y_j is 1 and the non-zero equals 1, the
/// polynomial equals the basis polynomial l_0(x) and l_0(x) = \prod_{j in 1..=k}(x-x_j) / \prod_{j in 1..=k}(0-x_j)
fn create_poly<F: PrimeField>(x: Vec<F>) -> DensePolynomial<F> {
    assert!(x.iter().all(|x_| !x_.is_zero()));

    // Get all -x_j
    let neg_x = x.into_iter().map(|i| -i).collect::<Vec<_>>();
    // Create terms of the form (x - x_j) and multiply them
    let polys = neg_x
        .iter()
        .map(|i| DensePolynomial::from_coefficients_slice(&[*i, F::one()]))
        .collect();
    let poly = multiply_many_polys(polys);

    // Take product of all -x_j and invert the result
    let inv_neg_x_product = neg_x.iter().fold(F::one(), |a, b| a * b).inverse().unwrap();

    &poly * inv_neg_x_product
}

/// Return a new vector `y` whose first `d` elements are coefficients of degree `d` polynomial `poly` and
/// rest of the elements are of `t`, i.e. `y = [a_1, a_2, ..., a_d, t_1, t_2, ..., t_n]`
fn create_y_from_t_and_poly<F: PrimeField>(mut t: Vec<F>, poly: DensePolynomial<F>) -> Vec<F> {
    let mut y = vec![];
    // Skip the constant of the polynomial
    for c in poly.coeffs.iter().skip(1) {
        y.push(*c);
    }
    y.append(&mut t);
    y
}

/// Create a random gamma and then P = gs * y + h * gamma
fn create_P<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    y: &[G::ScalarField],
    gs: &[G],
    h: &G,
) -> (G::ScalarField, G) {
    let gamma = G::ScalarField::rand(rng);
    let P = G::Group::msm_unchecked(gs, &y) + h.mul_bigint(gamma.into_bigint());
    (gamma, P.into_affine())
}

macro_rules! impl_homomorphism {
    ($name: ident, $G: ident) => {
        impl<$G: AffineRepr> Homomorphism<$G::ScalarField> for $name<$G> {
            type Output = $G;
            fn eval(&self, x: &[$G::ScalarField]) -> Result<Self::Output, CompSigmaError> {
                if x.len() < self.size() {
                    return Err(CompSigmaError::VectorTooShort);
                }
                Ok($G::Group::msm_unchecked(&self.0, &x[..self.size()]).into_affine())
            }

            fn scale(&self, scalar: &$G::ScalarField) -> Self {
                let s = scalar.into_bigint();
                let f = cfg_iter!(self.0)
                    .map(|f| f.mul_bigint(s))
                    .collect::<Vec<_>>();
                Self($G::Group::normalize_batch(&f))
            }

            fn add(&self, other: &Self) -> Result<Self, CompSigmaError> {
                if self.0.len() != other.0.len() {
                    return Err(CompSigmaError::VectorLenMismatch);
                }
                Ok(Self(
                    cfg_iter!(self.0)
                        .zip(cfg_iter!(other.0))
                        .map(|(a, b)| (*a + *b).into())
                        .collect::<Vec<_>>(),
                ))
            }

            fn split_in_half(&self) -> (Self, Self) {
                (
                    Self(self.0[..self.0.len() / 2].to_vec()),
                    Self(self.0[self.0.len() / 2..].to_vec()),
                )
            }

            fn size(&self) -> usize {
                self.0.len()
            }

            fn pad(&self, new_size: u32) -> Self {
                let size = self.size();
                let mut f = self.0.clone();
                if new_size as usize > size {
                    f.append(&mut vec![$G::zero(); new_size as usize - size]);
                }
                Self(f)
            }
        }
    };
}

/// This module is when witnesses are single field elements and DLs are of form `P_1 = g^{x_1}`, `P_2 = g^{x_2}`, ...
pub mod single {
    use super::*;

    /// The new witnesses are referred as Y in the paper
    pub fn create_new_witnesses<F: PrimeField>(n: usize, known_x: BTreeMap<usize, &F>) -> Vec<F> {
        let unknown_indices = (0..n)
            .filter(|i| !known_x.contains_key(i))
            .map(|i| F::from((i + 1) as u64))
            .collect::<Vec<_>>();

        let p_x = create_poly(unknown_indices);
        let mut t = vec![];
        for i in 0..n {
            if known_x.contains_key(&i) {
                // t_j = p_x(j) * x_j
                t.push(p_x.evaluate(&F::from((i + 1) as u64)) * *known_x.get(&i).unwrap());
            } else {
                t.push(F::zero());
            }
        }
        create_y_from_t_and_poly(t, p_x)
    }

    /// Create the new witnesses and commit to them in a single commitment from the given witnesses and
    /// their individual commitments
    pub fn create_new_witnesses_and_their_commitment<R: RngCore, G: AffineRepr>(
        rng: &mut R,
        Ps: &[G],
        known_x: BTreeMap<usize, &G::ScalarField>,
        gs: &[G],
        h: &G,
    ) -> Result<(Vec<G::ScalarField>, G::ScalarField, G), CompSigmaError> {
        if Ps.len() <= known_x.len() {
            return Err(CompSigmaError::VectorTooShort);
        }
        let n = Ps.len();
        let k = known_x.len();
        if gs.len() != (2 * n - k) {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let y = create_new_witnesses::<G::ScalarField>(n, known_x);

        let (gamma, P) = create_P(rng, &y, gs, h);
        Ok((y, gamma, P))
    }

    #[derive(Clone)]
    pub struct Hom<G: AffineRepr>(
        /// First `n-k` elements for multiples of `P_i` and next n for `g`. This holds the vector of
        /// bases such that the inner product of this vector and vector `Y` given `P_i`
        pub Vec<G>,
    );

    impl<G: AffineRepr> Hom<G> {
        /// For `k` known openings of `n` total commitments, the homomorphism for the commitment at index `i` is
        /// `g * t_i + P_i * -\sum_{j in 1..n-k}(a_j*i^j)`
        /// For `g * t_i`, the bases will be a vector `[0, 0, ..., g, 0, ..., 0]` of size `n` with `g` at index `i` and rest as 0
        /// For `P_i * \sum_{j in 1..n-k}(a_j*i^j)`, its equal to `P_i * -a_1 * i + P_2 * -a_2 * i^2 + ... + P_i * -a_{n-k} * i^{n-k}`
        /// which is equal to `(P_i * -i) * a_1 + (P_i * -i^2) * a_2 + ... + (P_i * -i^{n-k}) * a_{n-k}`. Thus the bases for it
        /// can be written as vector `[(P_i * -i), (P_i * -i^2), ..., (P_i * -i^{n-k})]` of size `n-k`.
        /// Thus the final bases are `[(P_i * -i), (P_i * -i^2), ..., (P_i * -i^{n-k}), 0, 0, ..., g, 0, ..., 0]` of size `2*n-k`
        pub fn new(g: G, P: G, k: usize, n: usize, i: usize) -> Result<Self, CompSigmaError> {
            if n <= 1 || n <= k || n <= i {
                return Err(CompSigmaError::FaultyParameterSize);
            }
            // `g_vec` will have only 0s except at the position `i`
            let mut g_vec = vec![G::zero(); n];
            g_vec[i] = g;

            let i = G::ScalarField::from((i + 1) as u64);
            let mut P_vec = multiples_with_n_powers_of_i(&P, i, n - k, &-G::ScalarField::one());
            let mut f = vec![];
            f.append(&mut P_vec);
            f.append(&mut g_vec);
            Ok(Self(f))
        }
    }

    impl_homomorphism!(Hom, G);

    /// Create a homomorphism for each commitment
    pub fn create_homomorphisms<G: AffineRepr>(
        g: G,
        Ps: Vec<G>,
        n: usize,
        k: usize,
    ) -> Vec<Hom<G>> {
        assert_eq!(Ps.len(), n);
        cfg_into_iter!(Ps)
            .enumerate()
            .map(|(i, Ps)| Hom::new(g.clone(), Ps, k, n, i).unwrap())
            .collect()
    }
}

/// This module is when witnesses are vectors of field elements and DLs are of for `P_1 = g_1^{x_1}*g_2^{x_2}..`, `P_2 = g_1^{y_1}*g_2^{y_2}..`, ...
pub mod multiple {
    use super::*;

    /// Size of every x_i vector involved in each P_i must be passed. When witness sizes are not known,
    /// choose an upper bound
    pub fn create_new_witnesses<F: PrimeField>(
        n: usize,
        unknown_witness_sizes: BTreeMap<usize, usize>,
        known_x: BTreeMap<usize, &[F]>,
    ) -> Vec<F> {
        assert!(known_x
            .keys()
            .collect::<BTreeSet<_>>()
            .is_disjoint(&unknown_witness_sizes.keys().collect::<BTreeSet<_>>()));
        assert_eq!(unknown_witness_sizes.len() + known_x.len(), n);
        let unknown_indices = unknown_witness_sizes
            .keys()
            .map(|i| F::from((i + 1) as u64))
            .collect::<Vec<_>>();

        let p_x = create_poly(unknown_indices);
        let mut t = vec![];
        for i in 0..n {
            if known_x.contains_key(&i) {
                let p = p_x.evaluate(&F::from((i + 1) as u64));
                let x = *known_x.get(&i).unwrap();
                t.append(&mut x.iter().map(|x| *x * p).collect::<Vec<_>>());
            } else {
                t.append(&mut vec![
                    F::zero();
                    *unknown_witness_sizes.get(&i).unwrap()
                ]);
            }
        }
        create_y_from_t_and_poly(t, p_x)
    }

    /// Size of every x_i vector involved in each P_i must be passed
    pub fn create_new_witnesses_and_their_commitment<R: RngCore, G: AffineRepr>(
        rng: &mut R,
        unknown_witness_sizes: BTreeMap<usize, usize>,
        Ps: &[G],
        known_x: BTreeMap<usize, &[G::ScalarField]>,
        gs: &[G],
        h: &G,
    ) -> Result<(Vec<G::ScalarField>, G::ScalarField, G), CompSigmaError> {
        if Ps.len() <= known_x.len() {
            return Err(CompSigmaError::VectorTooShort);
        }
        let n = Ps.len();
        let k = known_x.len();
        if (unknown_witness_sizes.len() + known_x.len()) != n {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        // `total_witness_count` will be the total known and unknown witnesses that are committed in the
        // final commitment in addition to the polynomial coefficients
        let mut total_witness_count = unknown_witness_sizes
            .values()
            .fold(0, |accum, size| accum + size);
        total_witness_count += known_x
            .values()
            .map(|v| v.len())
            .fold(0, |accum, size| accum + size);
        // n-k for the polynomial coefficient
        if gs.len() != (total_witness_count + n - k) {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let y = create_new_witnesses::<G::ScalarField>(n, unknown_witness_sizes, known_x);

        let (gamma, P) = create_P(rng, &y, gs, h);
        Ok((y, gamma, P))
    }

    #[derive(Clone)]
    pub struct Hom<G: AffineRepr>(
        /// First `n-k` elements for multiples of `P_i` and next `T` for corresponding elements of `g` where `T`
        /// is the total number of witnesses from all `P_i` combined.
        /// This holds the vector of bases such that the inner product of this vector and vector `Y` given `P_i`
        pub Vec<G>,
    );

    impl<G: AffineRepr> Hom<G> {
        /// For `k` known openings of `n` total commitments, the homomorphism for the commitment at index `i` is
        /// `\sum_{l in 1..m}(g_l * t_i_l) + P_i * -\sum_{j in 1..n-k}(a_j*i^j)` where `m` is the size of witness vector `x_i`
        /// For `\sum_{l in 1..m}(g_l * t_i_l)`, the bases will be a vector `[0, 0, ..., g_1, g_2, ..., g_m, 0, ..., 0]` of size `T`
        /// where is the `T` is the sum of sizes of all `x_i`
        /// For `P_i * \sum_{j in 1..n-k}(a_j*i^j)`, its equal to `P_i * -a_1 * i + P_2 * -a_2 * i^2 + ... + P_i * -a_{n-k} * i^{n-k}`
        /// which is equal to `(P_i * -i) * a_1 + (P_i * -i^2) * a_2 + ... + (P_i * -i^{n-k}) * a_{n-k}`. Thus the bases for it
        /// can be written as vector `[(P_i * -i), (P_i * -i^2), ..., (P_i * -i^{n-k})]` of size `n-k`.
        /// Thus the final bases are `[(P_i * -i), (P_i * -i^2), ..., (P_i * -i^{n-k}), 0, 0, ..., g_1, g_2, ..., g_m, 0, ..., 0]`
        /// of size `T+n-k`
        pub fn new(
            g: &[G],
            P: G,
            k: usize,
            n: usize,
            witness_sizes: &[usize],
            i: usize,
        ) -> Result<Self, CompSigmaError> {
            if n <= 1 || n <= k || n <= i {
                return Err(CompSigmaError::FaultyParameterSize);
            }
            if witness_sizes.len() != n {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            if g.len() < *witness_sizes.iter().reduce(|a, b| a.max(b)).unwrap() {
                return Err(CompSigmaError::VectorTooShort);
            }
            let size = n - k;
            let total_witness_count = witness_sizes.iter().sum();
            // `g_vec` will have only 0s except at the positions where its multiplied by the witnesses
            // starting at `i`, thus `g_vec` will have only `witness_sizes[i]`
            // non-0 elements
            let mut g_vec = vec![G::zero(); total_witness_count];
            let g_vec_offset = witness_sizes[0..i].iter().sum::<usize>();
            // Set `g` for the corresponding `x_i`
            for j in 0..witness_sizes[i] {
                g_vec[g_vec_offset + j] = g[j].clone();
            }

            let i = G::ScalarField::from((i + 1) as u64);
            let mut P_vec = multiples_with_n_powers_of_i(&P, i, size, &-G::ScalarField::one());
            let mut f = vec![];
            f.append(&mut P_vec);
            f.append(&mut g_vec);
            Ok(Self(f))
        }
    }

    impl_homomorphism!(Hom, G);

    pub fn create_homomorphisms<G: AffineRepr>(
        g: &[G],
        Ps: Vec<G>,
        n: usize,
        k: usize,
        witness_sizes: &[usize],
    ) -> Result<Vec<Hom<G>>, CompSigmaError> {
        if Ps.len() != n {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        assert_eq!(Ps.len(), n);
        cfg_into_iter!(Ps)
            .enumerate()
            .map(|(i, Ps)| Hom::new(g, Ps, k, n, witness_sizes, i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amortized_homomorphisms::*;
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::{One, Zero};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn polynomial() {
        fn check_poly(x: Vec<Fr>) {
            let p = create_poly(x.clone());
            assert_eq!(p.degree(), x.len());
            assert_eq!(p.evaluate(&Fr::zero()), Fr::one());
            for x in x.iter() {
                assert_eq!(p.evaluate(x), Fr::zero());
            }
        }

        let x1 = vec![Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)];
        let x2 = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(9u64),
        ];
        let x3 = vec![Fr::from(4u64)];
        check_poly(x1);
        check_poly(x2);
        check_poly(x3);
    }

    #[test]
    fn create_homomorphisms() {
        fn check_hom(n: usize, known_indices: BTreeSet<usize>) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();
            let g = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
            let x = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let Ps = x
                .iter()
                .map(|x| g.mul_bigint(x.into_bigint()).into_affine())
                .collect::<Vec<_>>();

            let known_x = known_indices
                .iter()
                .map(|i| (*i, &x[*i]))
                .collect::<BTreeMap<_, _>>();
            let y = single::create_new_witnesses::<Fr>(n, known_x);
            let fs = single::create_homomorphisms(g.clone(), Ps.clone(), n, k);

            assert_eq!(fs.len(), n);
            for i in 0..n {
                if !known_indices.contains(&i) {
                    assert!(y[n - k + i].is_zero());
                }
                assert_eq!(fs[i].eval(&y).unwrap(), Ps[i]);
            }

            let scalars = (0..fs.len())
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let f_rho = AmortizeHomomorphisms::<_, _>::new_homomorphism_from_given_randomness(
                &fs, &scalars,
            );
            assert_eq!(
                f_rho.eval(&y).unwrap(),
                <Bls12_381 as Pairing>::G1::msm_unchecked(&Ps, &scalars).into_affine()
            );
        }

        check_hom(3, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_hom(3, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_hom(3, vec![0, 1].into_iter().collect::<BTreeSet<_>>());
        check_hom(3, vec![1, 2].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![2].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![0, 1].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![0, 1, 2].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![0, 1, 2, 3].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![0, 3].into_iter().collect::<BTreeSet<_>>());
        check_hom(5, vec![1, 4].into_iter().collect::<BTreeSet<_>>());
        check_hom(6, vec![1, 3].into_iter().collect::<BTreeSet<_>>());
        check_hom(6, vec![2, 5].into_iter().collect::<BTreeSet<_>>());
        check_hom(6, vec![2, 4, 5].into_iter().collect::<BTreeSet<_>>());
        check_hom(6, vec![1, 2, 4, 5].into_iter().collect::<BTreeSet<_>>());
        check_hom(6, vec![1, 2, 3, 4, 5].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn partial_knowledge_single() {
        fn check_partial_know_single(n: usize, known_indices: BTreeSet<usize>) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();
            let g = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
            let gs = (0..2 * n - k)
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();

            let xs = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let known_x = known_indices
                .iter()
                .map(|i| (*i, &xs[*i]))
                .collect::<BTreeMap<_, _>>();
            let Ps = xs
                .iter()
                .map(|x| g.mul_bigint(x.into_bigint()).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            let (y, gamma, P) =
                single::create_new_witnesses_and_their_commitment(&mut rng, &Ps, known_x, &gs, &h)
                    .unwrap();
            let fs = single::create_homomorphisms(g.clone(), Ps.clone(), n, k);

            assert_eq!(fs.len(), n);
            for i in 0..n {
                if !known_indices.contains(&i) {
                    assert!(y[n - k + i].is_zero());
                }
                assert_eq!(fs[i].eval(&y).unwrap(), Ps[i]);
            }

            let mut new_gs = gs.clone();
            new_gs.push(h);
            let mut new_y = y.clone();
            new_y.push(gamma);

            let rand_comm =
                RandomCommitment::new::<_, Blake2b512, _>(&mut rng, &new_gs, &Ps, &fs, None)
                    .unwrap();
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(&new_y, &challenge).unwrap();
            response
                .is_valid::<Blake2b512, _>(
                    &new_gs,
                    &P,
                    &Ps,
                    &fs,
                    &rand_comm.A,
                    &rand_comm.t,
                    &challenge,
                )
                .unwrap();
            println!(
                "Proof of partial knowledge of {}-of-{} takes {:?}",
                k,
                n,
                start.elapsed()
            );
        }

        check_partial_know_single(3, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(3, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(3, vec![0, 1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(3, vec![1, 2].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![2].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![0, 1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![0, 1, 2].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![0, 1, 2, 3].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![0, 3].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(5, vec![1, 4].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(6, vec![1, 3].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(6, vec![2, 5].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(6, vec![2, 4, 5].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(6, vec![1, 2, 4, 5].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_single(6, vec![1, 2, 3, 4, 5].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn partial_knowledge_multiple() {
        fn check_partial_know_multiple(
            n: usize,
            witness_sizes: Vec<usize>,
            known_indices: BTreeSet<usize>,
        ) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();

            let g = (0..*witness_sizes.iter().reduce(|a, b| a.max(b)).unwrap())
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let gs = (0..(witness_sizes.iter().sum::<usize>() + n - k))
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();

            let xs = (0..n)
                .map(|i| {
                    (0..witness_sizes[i])
                        .map(|_| Fr::rand(&mut rng))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let known_x = known_indices
                .iter()
                .map(|i| (*i, xs[*i].as_slice()))
                .collect::<BTreeMap<_, _>>();
            let Ps = xs
                .iter()
                .map(|x| <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine())
                .collect::<Vec<_>>();

            let (y, gamma, P) = multiple::create_new_witnesses_and_their_commitment(
                &mut rng,
                witness_sizes
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !known_indices.contains(i))
                    .map(|(i, j)| (i, *j))
                    .collect::<BTreeMap<_, _>>(),
                &Ps,
                known_x,
                &gs,
                &h,
            )
            .unwrap();
            let fs = multiple::create_homomorphisms(&g, Ps.clone(), n, k, &witness_sizes).unwrap();

            assert_eq!(fs.len(), n);
            let mut y_offset = 0;
            for i in 0..n {
                if !known_indices.contains(&i) {
                    for j in 0..witness_sizes[i] {
                        assert!(y[n - k + y_offset + j].is_zero());
                    }
                }
                y_offset += witness_sizes[i];
                assert_eq!(fs[i].eval(&y).unwrap(), Ps[i]);
            }

            let mut new_gs = gs.clone();
            new_gs.push(h);
            let mut new_y = y.clone();
            new_y.push(gamma);

            let rand_comm =
                RandomCommitment::new::<_, Blake2b512, _>(&mut rng, &new_gs, &Ps, &fs, None)
                    .unwrap();
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(&new_y, &challenge).unwrap();
            response
                .is_valid::<Blake2b512, _>(
                    &new_gs,
                    &P,
                    &Ps,
                    &fs,
                    &rand_comm.A,
                    &rand_comm.t,
                    &challenge,
                )
                .unwrap();
        }

        check_partial_know_multiple(
            3,
            vec![3, 4, 2],
            vec![0, 1].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            3,
            vec![3, 4, 2],
            vec![0].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            3,
            vec![3, 4, 2],
            vec![1].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            3,
            vec![7, 2, 9],
            vec![1].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            3,
            vec![10, 20, 30],
            vec![1, 2].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            5,
            vec![3, 4, 5, 9, 1],
            vec![0].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            5,
            vec![1, 2, 2, 2, 2],
            vec![2].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            5,
            vec![2, 2, 2, 2, 2],
            vec![0, 1, 3].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            5,
            vec![3, 5, 6, 20, 5],
            vec![0, 1, 3, 4].into_iter().collect::<BTreeSet<_>>(),
        );
        check_partial_know_multiple(
            8,
            vec![3, 5, 6, 20, 5, 9, 2, 1],
            vec![2, 3, 4].into_iter().collect::<BTreeSet<_>>(),
        );

        check_partial_know_multiple(
            5,
            vec![2, 2, 8, 2, 8],
            vec![0, 1, 3].into_iter().collect::<BTreeSet<_>>(),
        );
    }

    #[test]
    fn partial_knowledge_multiple_compressed() {
        let n = 3;
        let witness_sizes = vec![2, 3, 2];
        let known_indices = vec![0, 1].into_iter().collect::<BTreeSet<_>>();

        let mut rng = StdRng::seed_from_u64(0u64);
        let k = known_indices.len();

        let total_witness_size = witness_sizes.iter().sum::<usize>() + n - k;

        let max_witness_size = *witness_sizes.iter().reduce(|a, b| a.max(b)).unwrap();

        let g = (0..max_witness_size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let gs = (0..total_witness_size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let h = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();

        let xs = (0..n)
            .map(|i| {
                (0..witness_sizes[i])
                    .map(|_| Fr::rand(&mut rng))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let known_x = known_indices
            .iter()
            .map(|i| (*i, xs[*i].as_slice()))
            .collect::<BTreeMap<_, _>>();
        let Ps = xs
            .iter()
            .map(|x| <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine())
            .collect::<Vec<_>>();

        let (y, gamma, P) = multiple::create_new_witnesses_and_their_commitment(
            &mut rng,
            witness_sizes
                .iter()
                .enumerate()
                .filter(|(i, _)| !known_indices.contains(i))
                .map(|(i, j)| (i, *j))
                .collect::<BTreeMap<_, _>>(),
            &Ps,
            known_x,
            &gs,
            &h,
        )
        .unwrap();
        let mut fs = multiple::create_homomorphisms(&g, Ps.clone(), n, k, &witness_sizes).unwrap();

        assert_eq!(fs.len(), n);
        let mut y_offset = 0;
        for i in 0..n {
            if !known_indices.contains(&i) {
                for j in 0..witness_sizes[i] {
                    assert!(y[n - k + y_offset + j].is_zero());
                }
            }
            y_offset += witness_sizes[i];
            assert_eq!(fs[i].eval(&y).unwrap(), Ps[i]);
        }

        let mut new_gs = gs.clone();
        new_gs.push(h);
        let mut new_y = y.clone();
        new_y.push(gamma);

        // Padding to make the new commitment and homomorphisms of same sizes
        for _ in 0..7 {
            new_gs.push(G1Affine::zero());
            new_y.push(Fr::zero());
        }
        for i in 0..fs.len() {
            fs[i] = fs[i].pad(16);
        }

        assert_eq!(fs.len(), n);
        let mut y_offset = 0;
        for i in 0..n {
            if !known_indices.contains(&i) {
                for j in 0..witness_sizes[i] {
                    assert!(new_y[n - k + y_offset + j].is_zero());
                }
            }
            y_offset += witness_sizes[i];
            assert_eq!(fs[i].eval(&new_y).unwrap(), Ps[i]);
        }

        let rand_comm =
            RandomCommitment::new::<_, Blake2b512, _>(&mut rng, &new_gs, &Ps, &fs, None).unwrap();
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(&new_y, &challenge).unwrap();
        response
            .is_valid::<Blake2b512, _>(
                &new_gs,
                &P,
                &Ps,
                &fs,
                &rand_comm.A,
                &rand_comm.t,
                &challenge,
            )
            .unwrap();

        let comp_resp = response.compress::<Blake2b512, _>(&new_gs, &Ps, &fs);
        Response::is_valid_compressed::<Blake2b512, _>(
            &new_gs,
            &fs,
            &P,
            &Ps,
            &rand_comm.A,
            &rand_comm.t,
            &challenge,
            &comp_resp,
        )
        .unwrap();
    }
}
