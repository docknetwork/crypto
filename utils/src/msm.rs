use ark_ec::{scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, vec::Vec};

use crate::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Use when same elliptic curve point is to be multiplied by several scalars.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct WindowTable<G: CurveGroup> {
    scalar_size: usize,
    window_size: usize,
    outerc: usize,
    #[serde_as(as = "Vec<Vec<ArkObjectBytes>>")]
    table: Vec<Vec<G::Affine>>,
}

impl<G: CurveGroup> WindowTable<G> {
    /// Create new table for `group_elem`. `num_multiplications` is the number of multiplication that
    /// need to be done and it can be an approximation as it does not impact correctness but only performance.
    pub fn new(num_multiplications: usize, group_elem: G) -> Self {
        let scalar_size = G::ScalarField::MODULUS_BIT_SIZE as usize;
        let window_size = FixedBase::get_mul_window_size(num_multiplications);
        let outerc = (scalar_size + window_size - 1) / window_size;
        let table = FixedBase::get_window_table(scalar_size, window_size, group_elem);
        Self {
            scalar_size,
            window_size,
            outerc,
            table,
        }
    }

    /// Multiply with a single scalar
    pub fn multiply(&self, element: &G::ScalarField) -> G {
        FixedBase::windowed_mul(self.outerc, self.window_size, &self.table, element)
    }

    /// Multiply with a many scalars
    pub fn multiply_many(&self, elements: &[G::ScalarField]) -> Vec<G> {
        FixedBase::msm(self.scalar_size, self.window_size, &self.table, elements)
    }

    pub fn window_size(num_multiplications: usize) -> usize {
        FixedBase::get_mul_window_size(num_multiplications)
    }
}

/// The same group element is multiplied by each in `elements` using a window table
pub fn multiply_field_elems_with_same_group_elem<G: CurveGroup>(
    group_elem: G,
    elements: &[G::ScalarField],
) -> Vec<G> {
    let table = WindowTable::new(elements.len(), group_elem);
    table.multiply_many(elements)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use ark_bls12_381::Bls12_381;
    use ark_ec::{
        pairing::Pairing, scalar_mul::wnaf::WnafContext, AffineRepr, CurveGroup, VariableBaseMSM,
    };
    use ark_ff::{PrimeField, Zero};
    use ark_std::{
        cfg_iter,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    type Fr = <Bls12_381 as Pairing>::ScalarField;
    type G1 = <Bls12_381 as Pairing>::G1;
    type G2 = <Bls12_381 as Pairing>::G2;

    #[test]
    fn print_size_of_group_elems() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);
        let gt = <Bls12_381 as Pairing>::pairing(g1, g2);

        macro_rules! get_bytes {
            ($g:expr, $compressed:expr) => {{
                let mut b = vec![];
                if $compressed {
                    $g.serialize_compressed(&mut b).unwrap();
                } else {
                    $g.serialize_uncompressed(&mut b).unwrap();
                }
                b
            }};
        }

        println!("g1 compressed {:?}", get_bytes!(g1, true).len());
        println!("g1 uncompressed {:?}", get_bytes!(g1, false).len());
        println!("g2 compressed {:?}", get_bytes!(g2, true).len());
        println!("g2 uncompressed {:?}", get_bytes!(g2, false).len());
        println!("gt compressed {:?}", get_bytes!(gt, true).len());
        println!("gt uncompressed {:?}", get_bytes!(gt, false).len());
        println!("g1 zero compressed {:?}", get_bytes!(G1::zero(), true));
        println!("g2 zero compressed {:?}", get_bytes!(G2::zero(), true));
    }

    #[test]
    fn timing_ark_ops() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let context = WnafContext::new(4);
        let mut group_elem = G1::rand(&mut rng);
        let group_elem_affine = group_elem.into_affine();
        let table = context.table(group_elem);

        let mut d0 = Duration::default();
        let mut d1 = Duration::default();
        let mut d2 = Duration::default();
        let mut d3 = Duration::default();

        for _ in 0..100 {
            let e = Fr::rand(&mut rng);

            let start = Instant::now();
            let mut temp = group_elem_affine.into_group();
            temp *= e;
            d0 += start.elapsed();

            let start = Instant::now();
            let temp1 = context.mul_with_table(&table, &e).unwrap();
            d1 += start.elapsed();

            assert_eq!(temp, temp1);

            let start = Instant::now();
            group_elem *= e;
            d2 += start.elapsed();

            let start = Instant::now();
            let _ = group_elem_affine.mul_bigint(e.into_bigint());
            d3 += start.elapsed();
        }

        println!("d0={:?}", d0);
        println!("d1={:?}", d1);
        println!("d2={:?}", d2);
        println!("d3={:?}", d3);

        let mut d5 = Duration::default();
        let mut d6 = Duration::default();
        for _ in 0..100 {
            let g1 = G1::rand(&mut rng).into_affine();
            let g2 = G1::rand(&mut rng).into_affine();
            let e1 = Fr::rand(&mut rng);
            let e2 = Fr::rand(&mut rng);

            let start = Instant::now();
            let temp = g1.mul_bigint(e1.into_bigint()) + g2.mul_bigint(e2.into_bigint());
            d5 += start.elapsed();

            let start = Instant::now();
            let temp1 = G1::msm(&[g1, g2], &[e1, e2]).unwrap();
            d6 += start.elapsed();

            assert_eq!(temp, temp1);
        }

        println!("d5={:?}", d5);
        println!("d6={:?}", d6);

        let mut d7 = Duration::default();
        for _ in 0..100 {
            let mut g1 = G1::rand(&mut rng);
            let g2 = G1::rand(&mut rng).into_affine();
            let start = Instant::now();
            g1 += g2.into_group();
            d7 += start.elapsed();
        }

        println!("d7={:?}", d7);

        let mut d9 = Duration::default();
        let mut d10 = Duration::default();

        for _ in 0..100 {
            let scalars = (0..30).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let g = G1::rand(&mut rng);

            let start = Instant::now();
            let temp = multiply_field_elems_with_same_group_elem(g, scalars.as_slice());
            d9 += start.elapsed();

            let start = Instant::now();
            let a = g.into_affine();
            let temp1 = cfg_iter!(scalars)
                .map(|s| a.mul_bigint(s.into_bigint()))
                .collect::<Vec<_>>();
            d10 += start.elapsed();

            assert_eq!(temp, temp1);
        }

        println!("d9={:?}", d9);
        println!("d10={:?}", d10);

        let mut d11 = Duration::default();
        let mut d12 = Duration::default();

        for _ in 0..100 {
            let g1 = G1::rand(&mut rng).into_affine();
            let g2 = G1::rand(&mut rng).into_affine();
            let e1 = Fr::rand(&mut rng);
            let e2 = Fr::rand(&mut rng);

            let start = Instant::now();
            let temp = g1.mul_bigint(e1.into_bigint()) + g2.mul_bigint(e2.into_bigint());
            d11 += start.elapsed();

            let start = Instant::now();
            let temp1 = G1::msm(&[g1, g2], &[e1, e2]).unwrap();
            d12 += start.elapsed();

            assert_eq!(temp, temp1);
        }

        println!("d11={:?}", d11);
        println!("d12={:?}", d12);

        // Pre-Prepared vs not prepared for pairing
        let mut d13 = Duration::default();
        let mut d14 = Duration::default();

        for _ in 0..100 {
            let g1 = G1::rand(&mut rng).into_affine();
            let g2 = <Bls12_381 as Pairing>::G2::rand(&mut rng).into_affine();
            let g3 = <Bls12_381 as Pairing>::G1Prepared::from(g1);
            let g4 = <Bls12_381 as Pairing>::G2Prepared::from(g2);

            let start = Instant::now();
            let temp = <Bls12_381 as Pairing>::pairing(g1, g2);
            d13 += start.elapsed();

            let start = Instant::now();
            let temp1 = <Bls12_381 as Pairing>::pairing(g3, g4);
            d14 += start.elapsed();

            assert_eq!(temp, temp1);
        }

        println!("d13={:?}", d13);
        println!("d14={:?}", d14);

        let mut d15 = Duration::default();
        let mut d16 = Duration::default();

        let g = G1::rand(&mut rng);
        let count = 10;

        let start = Instant::now();
        let scalar_size = Fr::MODULUS_BIT_SIZE as usize;
        let window_size = FixedBase::get_mul_window_size(count);
        let outerc = (scalar_size + window_size - 1) / window_size;
        let table = FixedBase::get_window_table(scalar_size, window_size, g);
        d15 += start.elapsed();

        let g = g.into_affine();
        for _ in 0..count {
            let e = Fr::rand(&mut rng);

            let start = Instant::now();
            let temp = FixedBase::windowed_mul::<G1>(outerc, window_size, &table, &e);
            d15 += start.elapsed();

            let start = Instant::now();
            let temp1 = g.mul_bigint(e.into_bigint());
            d16 += start.elapsed();

            assert_eq!(temp, temp1);
        }

        println!("d15={:?}", d15);
        println!("d16={:?}", d16);
    }
}
