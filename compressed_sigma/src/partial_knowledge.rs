//! Proof of partial knowledge protocol as described in section 4 of the paper "Compressing Proofs of k-Out-Of-n".
//! Implements both for single witness DLs and DLs involving witness vector

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_poly::{
    polynomial::{univariate::DensePolynomial, UVPolynomial},
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
use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

use crate::error::CompSigmaError;
use crate::transforms::Homomorphism;

use dock_crypto_utils::ec::batch_normalize_projective_into_affine;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn multiply_poly<F: PrimeField>(
    left: &DensePolynomial<F>,
    right: &DensePolynomial<F>,
) -> DensePolynomial<F> {
    let mut product = (0..(left.degree() + right.degree() + 1))
        .map(|_| F::zero())
        .collect::<Vec<_>>();
    for i in 0..=left.degree() {
        for j in 0..=right.degree() {
            product[i + j] += left.coeffs[i] * right.coeffs[j];
        }
    }
    DensePolynomial::from_coefficients_vec(product)
}

fn create_poly<F: PrimeField>(x: Vec<F>) -> DensePolynomial<F> {
    let neg_x = cfg_into_iter!(x).map(|i| -i).collect::<Vec<_>>();
    let poly = cfg_iter!(neg_x)
        .map(|i| DensePolynomial::from_coefficients_slice(&[*i, F::one()]))
        .reduce(
            || DensePolynomial::from_coefficients_vec(vec![F::one()]),
            |a, b| multiply_poly(&a, &b),
        );

    let inv_neg_x_product = cfg_into_iter!(neg_x)
        .reduce(|| F::one(), |a, b| a * b)
        .inverse()
        .unwrap();

    &poly * inv_neg_x_product
}

fn create_y_from_t_and_poly<F: PrimeField>(mut t: Vec<F>, poly: DensePolynomial<F>) -> Vec<F> {
    let mut y = vec![];
    for c in poly.coeffs().iter().skip(1) {
        y.push(*c);
    }
    y.append(&mut t);
    y
}

fn create_P<R: RngCore, G: AffineCurve>(
    rng: &mut R,
    y: &[G::ScalarField],
    gs: &[G],
    h: &G,
) -> (G::ScalarField, G) {
    let gamma = G::ScalarField::rand(rng);
    let P = VariableBaseMSM::multi_scalar_mul(
        gs,
        &cfg_iter!(y).map(|y| y.into_repr()).collect::<Vec<_>>(),
    ) + h.mul(gamma.into_repr());
    (gamma, P.into_affine())
}

macro_rules! impl_homomorphism {
    ($name: ident, $G: ident) => {
        impl<$G: AffineCurve> Homomorphism<$G::ScalarField> for $name<$G> {
            type Output = $G;
            fn eval(&self, x: &[$G::ScalarField]) -> Self::Output {
                let n = self.g.len();
                let n_k = self.P.len();
                assert!(x.len() >= n + n_k);
                let x_repr = cfg_iter!(x).map(|t| t.into_repr()).collect::<Vec<_>>();
                let a = &x_repr[0..n_k];
                let t = &x_repr[n_k..n_k + n];
                let g = VariableBaseMSM::multi_scalar_mul(&self.g, &t);
                let P = VariableBaseMSM::multi_scalar_mul(&self.P, &a);
                (g - P).into_affine()
            }

            fn scale(&self, scalar: &$G::ScalarField) -> Self {
                let s = scalar.into_repr();
                let g = cfg_iter!(self.g).map(|g| g.mul(s)).collect::<Vec<_>>();
                let P = cfg_iter!(self.P).map(|P| P.mul(s)).collect::<Vec<_>>();
                Self {
                    g: batch_normalize_projective_into_affine(g),
                    P: batch_normalize_projective_into_affine(P),
                }
            }

            fn add(&self, other: &Self) -> Self {
                assert_eq!(self.g.len(), other.g.len());
                assert_eq!(self.P.len(), other.P.len());
                Self {
                    g: cfg_iter!(self.g)
                        .zip(cfg_iter!(other.g))
                        .map(|(a, b)| a.add(*b))
                        .collect::<Vec<_>>(),
                    P: cfg_iter!(self.P)
                        .zip(cfg_iter!(other.P))
                        .map(|(a, b)| a.add(*b))
                        .collect::<Vec<_>>(),
                }
            }

            fn split_in_half(&self) -> (Self, Self) {
                unimplemented!()
            }

            fn size(&self) -> usize {
                2
            }

            fn pad(&self, _new_size: usize) -> Self {
                unimplemented!()
            }
        }
    };
}

// TODO: The proof of knowledge of P does not use compression but it should especially when witnesses are vectors

/// This module is when witnesses are single field elements and DLs are of for `P_1 = g^{x_1}`, `P_2 = g^{x_2}`, ...
pub mod single {
    use super::*;

    pub fn create_y<F: PrimeField>(n: usize, known_x: BTreeMap<usize, &F>) -> Vec<F> {
        let unknown_indices = (0..n)
            .filter(|i| !known_x.contains_key(i))
            .map(|i| F::from((i + 1) as u64))
            .collect::<Vec<_>>();

        let p_x = create_poly(unknown_indices);
        let mut t = vec![];
        for i in 0..n {
            if known_x.contains_key(&i) {
                t.push(p_x.evaluate(&F::from((i + 1) as u64)) * *known_x.get(&i).unwrap());
            } else {
                t.push(F::zero());
            }
        }
        create_y_from_t_and_poly(t, p_x)
    }

    pub fn prepare<R: RngCore, G: AffineCurve>(
        rng: &mut R,
        Ps: &[G],
        known_x: BTreeMap<usize, &G::ScalarField>,
        gs: &[G],
        h: &G,
    ) -> (Vec<G::ScalarField>, G::ScalarField, G) {
        assert!(Ps.len() > known_x.len());
        let n = Ps.len();
        let k = known_x.len();
        assert_eq!(gs.len(), 2 * n - k);

        let y = create_y::<G::ScalarField>(n, known_x);

        let (gamma, P) = create_P(rng, &y, gs, h);
        (y, gamma, P)
    }

    #[derive(Clone)]
    pub struct Hom<G: AffineCurve> {
        pub g: Vec<G>,
        pub P: Vec<G>,
    }

    impl<G: AffineCurve> Hom<G> {
        pub fn new(g: G, P: G, k: usize, n: usize, i: usize) -> Self {
            assert!(n > 1);
            assert!(n > k);
            assert!(n > i);
            let size = n - k;
            let mut g_vec = vec![G::zero(); n];
            g_vec[i] = g;
            let i = G::ScalarField::from((i + 1) as u64);
            let mut i_powers = vec![i];
            for j in 1..size {
                i_powers.push(i_powers[j - 1] * i);
            }
            Self {
                g: g_vec,
                P: batch_normalize_projective_into_affine(
                    multiply_field_elems_with_same_group_elem(P.into_projective(), &i_powers),
                ),
            }
        }
    }

    impl_homomorphism!(Hom, G);

    pub fn create_homomorphisms<G: AffineCurve>(
        g: G,
        Ps: Vec<G>,
        n: usize,
        k: usize,
    ) -> Vec<Hom<G>> {
        assert_eq!(Ps.len(), n);
        cfg_into_iter!(Ps)
            .enumerate()
            .map(|(i, Ps)| Hom::new(g.clone(), Ps, k, n, i))
            .collect()
    }
}

/// This module is when witnesses are vectors of field elements and DLs are of for `P_1 = g_1^{x_1}*g_2^{x_2}..`, `P_2 = g_1^{y_1}*g_2^{y_2}..`, ...
pub mod multiple {
    use super::*;

    /// Size of every x_i vector involved in each P_i must be passed
    pub fn create_y<F: PrimeField>(
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
    pub fn prepare<R: RngCore, G: AffineCurve>(
        rng: &mut R,
        unknown_witness_sizes: BTreeMap<usize, usize>,
        Ps: &[G],
        known_x: BTreeMap<usize, &[G::ScalarField]>,
        gs: &[G],
        h: &G,
    ) -> (Vec<G::ScalarField>, G::ScalarField, G) {
        assert!(Ps.len() > known_x.len());
        let n = Ps.len();
        let k = known_x.len();
        assert_eq!(unknown_witness_sizes.len() + known_x.len(), n);

        let mut total_witness_count = unknown_witness_sizes
            .values()
            .fold(0, |accum, size| accum + size);
        total_witness_count += known_x
            .values()
            .map(|v| v.len())
            .fold(0, |accum, size| accum + size);
        assert_eq!(gs.len(), total_witness_count + n - k);

        let y = create_y::<G::ScalarField>(n, unknown_witness_sizes, known_x);

        let (gamma, P) = create_P(rng, &y, gs, h);
        (y, gamma, P)
    }

    /// All values of `known_x` are of same size (after padding)
    pub fn create_y_for_same_size_witnesses<F: PrimeField>(
        n: usize,
        m: usize,
        known_x: BTreeMap<usize, &[F]>,
    ) -> Vec<F> {
        let unknown_indices = (0..n)
            .filter(|i| !known_x.contains_key(i))
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
                t.append(&mut vec![F::zero(); m]);
            }
        }
        create_y_from_t_and_poly(t, p_x)
    }

    /// All values of `known_x` are of same size (after padding)
    pub fn prepare_for_same_size_witnesses<R: RngCore, G: AffineCurve>(
        rng: &mut R,
        m: usize,
        Ps: &[G],
        known_x: BTreeMap<usize, &[G::ScalarField]>,
        gs: &[G],
        h: &G,
    ) -> (Vec<G::ScalarField>, G::ScalarField, G) {
        assert!(Ps.len() > known_x.len());
        let n = Ps.len();
        let k = known_x.len();
        assert_eq!(gs.len(), (m + 1) * n - k);

        let y = create_y_for_same_size_witnesses::<G::ScalarField>(n, m, known_x);

        let (gamma, P) = create_P(rng, &y, gs, h);
        (y, gamma, P)
    }

    // TODO: It might make sense to move the struct outside and have 3 different implementations of
    // `new`, one for single element witness, one for equal length witness vectors and one for unequal
    // length witness vectors

    #[derive(Clone)]
    pub struct Hom<G: AffineCurve> {
        pub g: Vec<G>,
        pub P: Vec<G>,
    }

    impl<G: AffineCurve> Hom<G> {
        pub fn new(g: &[G], P: G, k: usize, n: usize, witness_sizes: &[usize], i: usize) -> Self {
            assert!(n > 1);
            assert!(n > k);
            assert!(n > i);
            assert_eq!(witness_sizes.len(), n);
            let size = n - k;
            let total_witness_count = witness_sizes.iter().sum();
            let mut g_vec = vec![G::zero(); total_witness_count];
            let g_vec_offset = witness_sizes[0..i].iter().sum::<usize>();
            for j in 0..witness_sizes[i] {
                g_vec[g_vec_offset + j] = g[j].clone();
            }

            let i = G::ScalarField::from((i + 1) as u64);
            let mut i_powers = vec![i];
            for j in 1..size {
                i_powers.push(i_powers[j - 1] * i);
            }
            Self {
                g: g_vec,
                P: batch_normalize_projective_into_affine(
                    multiply_field_elems_with_same_group_elem(P.into_projective(), &i_powers),
                ),
            }
        }

        pub fn new_for_same_size_witnesses(
            g: Vec<G>,
            P: G,
            k: usize,
            n: usize,
            m: usize,
            i: usize,
        ) -> Self {
            assert!(n > 1);
            assert!(n > k);
            assert!(n > i);
            let size = n - k;
            let mut g_vec = vec![G::zero(); m * n];
            for (j, g) in g.into_iter().enumerate() {
                g_vec[m * i + j] = g;
            }
            let i = G::ScalarField::from((i + 1) as u64);
            let mut i_powers = vec![i];
            for j in 1..size {
                i_powers.push(i_powers[j - 1] * i);
            }
            Self {
                g: g_vec,
                P: batch_normalize_projective_into_affine(
                    multiply_field_elems_with_same_group_elem(P.into_projective(), &i_powers),
                ),
            }
        }
    }

    impl_homomorphism!(Hom, G);

    pub fn create_homomorphisms<G: AffineCurve>(
        g: &[G],
        Ps: Vec<G>,
        n: usize,
        k: usize,
        witness_sizes: &[usize],
    ) -> Vec<Hom<G>> {
        assert_eq!(Ps.len(), n);
        cfg_into_iter!(Ps)
            .enumerate()
            .map(|(i, Ps)| Hom::new(g, Ps, k, n, witness_sizes, i))
            .collect()
    }

    pub fn create_homomorphisms_for_same_size_witnesses<G: AffineCurve>(
        g: Vec<G>,
        Ps: Vec<G>,
        n: usize,
        k: usize,
        m: usize,
    ) -> Vec<Hom<G>> {
        assert_eq!(Ps.len(), n);
        cfg_into_iter!(Ps)
            .enumerate()
            .map(|(i, Ps)| Hom::new_for_same_size_witnesses(g.clone(), Ps, k, n, m, i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amortized_homomorphisms::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_ff::{One, Zero};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b;
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

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
    fn combine_homomorphisms() {
        fn check_hom(n: usize, known_indices: BTreeSet<usize>) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();
            let g = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let x = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let Ps = x
                .iter()
                .map(|x| g.mul(x.into_repr()).into_affine())
                .collect::<Vec<_>>();

            let known_x = known_indices
                .iter()
                .map(|i| (*i, &x[*i]))
                .collect::<BTreeMap<_, _>>();
            let y = single::create_y::<Fr>(n, known_x);
            let fs = single::create_homomorphisms(g.clone(), Ps.clone(), n, k);

            assert_eq!(fs.len(), n);
            for i in 0..n {
                if !known_indices.contains(&i) {
                    assert!(y[n - k + i].is_zero());
                }
                assert_eq!(fs[i].eval(&y), Ps[i]);
            }

            let scalars = (0..fs.len())
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let f_rho = combine_f(&fs, &scalars);
            assert_eq!(
                f_rho.eval(&y),
                VariableBaseMSM::multi_scalar_mul(
                    &Ps,
                    &scalars.iter().map(|r| r.into_repr()).collect::<Vec<_>>()
                )
                .into_affine()
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
            let g = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let gs = (0..2 * n - k)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

            let xs = (0..n).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let known_x = known_indices
                .iter()
                .map(|i| (*i, &xs[*i]))
                .collect::<BTreeMap<_, _>>();
            let Ps = xs
                .iter()
                .map(|x| g.mul(x.into_repr()).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            let (y, gamma, P) = single::prepare(&mut rng, &Ps, known_x, &gs, &h);
            let fs = single::create_homomorphisms(g.clone(), Ps.clone(), n, k);

            assert_eq!(fs.len(), n);
            for i in 0..n {
                if !known_indices.contains(&i) {
                    assert!(y[n - k + i].is_zero());
                }
                assert_eq!(fs[i].eval(&y), Ps[i]);
            }

            let mut new_gs = gs.clone();
            new_gs.push(h);
            let mut new_y = y.clone();
            new_y.push(gamma);

            let rand_comm =
                RandomCommitment::new::<_, Blake2b, _>(&mut rng, &new_gs, &P, &Ps, &fs, None)
                    .unwrap();
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(&new_y, &challenge).unwrap();
            response
                .is_valid::<Blake2b, _>(
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
    fn partial_knowledge_multiple_for_same_size_witnesses() {
        fn check_partial_know_multiple(n: usize, m: usize, known_indices: BTreeSet<usize>) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();
            let g = (0..m)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let gs = (0..(m + 1) * n - k)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

            let xs = (0..n)
                .map(|_| (0..m).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            let known_x = known_indices
                .iter()
                .map(|i| (*i, xs[*i].as_slice()))
                .collect::<BTreeMap<_, _>>();
            let Ps = xs
                .iter()
                .map(|x| {
                    VariableBaseMSM::multi_scalar_mul(
                        &g,
                        &x.iter().map(|i| i.into_repr()).collect::<Vec<_>>(),
                    )
                    .into_affine()
                })
                .collect::<Vec<_>>();

            let (y, gamma, P) =
                multiple::prepare_for_same_size_witnesses(&mut rng, m, &Ps, known_x, &gs, &h);
            let fs = multiple::create_homomorphisms_for_same_size_witnesses(
                g.clone(),
                Ps.clone(),
                n,
                k,
                m,
            );

            assert_eq!(fs.len(), n);
            for i in 0..n {
                if !known_indices.contains(&i) {
                    for j in 0..m {
                        assert!(y[n - k + m * i + j].is_zero());
                    }
                }
                assert_eq!(fs[i].eval(&y), Ps[i]);
            }

            let mut new_gs = gs.clone();
            new_gs.push(h);
            let mut new_y = y.clone();
            new_y.push(gamma);

            let rand_comm =
                RandomCommitment::new::<_, Blake2b, _>(&mut rng, &new_gs, &P, &Ps, &fs, None)
                    .unwrap();
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(&new_y, &challenge).unwrap();
            response
                .is_valid::<Blake2b, _>(
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

        check_partial_know_multiple(3, 2, vec![0, 1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(3, 2, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(3, 2, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(3, 8, vec![1].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(3, 8, vec![1, 2].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(5, 2, vec![0].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(5, 2, vec![2].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(5, 10, vec![0, 1, 3].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(5, 7, vec![0, 1, 3, 4].into_iter().collect::<BTreeSet<_>>());
        check_partial_know_multiple(8, 6, vec![2, 3, 4].into_iter().collect::<BTreeSet<_>>());
    }

    #[test]
    fn partial_knowledge_multiple_for_different_size_witnesses() {
        fn check_partial_know_multiple(
            n: usize,
            witness_sizes: Vec<usize>,
            known_indices: BTreeSet<usize>,
        ) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let k = known_indices.len();

            let g = (0..*witness_sizes
                .iter()
                .reduce(|max, item| if max >= item { max } else { item })
                .unwrap())
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let gs = (0..(witness_sizes.iter().sum::<usize>() + n - k))
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

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
                .map(|x| {
                    VariableBaseMSM::multi_scalar_mul(
                        &g,
                        &x.iter().map(|i| i.into_repr()).collect::<Vec<_>>(),
                    )
                    .into_affine()
                })
                .collect::<Vec<_>>();

            let (y, gamma, P) = multiple::prepare(
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
            );
            let fs = multiple::create_homomorphisms(&g, Ps.clone(), n, k, &witness_sizes);

            assert_eq!(fs.len(), n);
            let mut y_offset = 0;
            for i in 0..n {
                if !known_indices.contains(&i) {
                    for j in 0..witness_sizes[i] {
                        assert!(y[n - k + y_offset + j].is_zero());
                    }
                }
                y_offset += witness_sizes[i];
                assert_eq!(fs[i].eval(&y), Ps[i]);
            }

            let mut new_gs = gs.clone();
            new_gs.push(h);
            let mut new_y = y.clone();
            new_y.push(gamma);

            let rand_comm =
                RandomCommitment::new::<_, Blake2b, _>(&mut rng, &new_gs, &P, &Ps, &fs, None)
                    .unwrap();
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(&new_y, &challenge).unwrap();
            response
                .is_valid::<Blake2b, _>(
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
    }
}
