use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    cfg_iter,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};

use crate::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Use when same elliptic curve point is to be multiplied by several scalars.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct WindowTable<G: ProjectiveCurve> {
    scalar_size: usize,
    window_size: usize,
    outerc: usize,
    #[serde_as(as = "Vec<Vec<AffineGroupBytes>>")]
    table: Vec<Vec<G::Affine>>,
}

impl<G: ProjectiveCurve> WindowTable<G> {
    /// Create new table for `group_elem`. `scalar_size` is the size in bits of the scalar.
    /// num_multiplications is the number of multiplication that need to be done and it can be an
    /// approximation as it does not impact correctness but only performance.
    pub fn new(scalar_size: usize, num_multiplications: usize, group_elem: G) -> Self {
        let window_size = FixedBaseMSM::get_mul_window_size(num_multiplications);
        let outerc = (scalar_size + window_size - 1) / window_size;
        let table = FixedBaseMSM::get_window_table(scalar_size, window_size, group_elem);
        Self {
            scalar_size,
            window_size,
            outerc,
            table,
        }
    }

    /// Multiply with a single scalar
    pub fn multiply(&self, element: &G::ScalarField) -> G {
        FixedBaseMSM::windowed_mul(self.outerc, self.window_size, &self.table, element)
    }

    /// Multiply with a many scalars
    pub fn multiply_many(&self, elements: &[G::ScalarField]) -> Vec<G> {
        FixedBaseMSM::multi_scalar_mul(self.scalar_size, self.window_size, &self.table, elements)
    }

    pub fn window_size(num_multiplications: usize) -> usize {
        FixedBaseMSM::get_mul_window_size(num_multiplications)
    }
}

/// The same group element is multiplied by each in `elements` using a window table
pub fn multiply_field_elems_with_same_group_elem<G: ProjectiveCurve>(
    group_elem: G,
    elements: &[G::ScalarField],
) -> Vec<G> {
    let scalar_size = G::ScalarField::size_in_bits();
    let table = WindowTable::new(scalar_size, elements.len(), group_elem);
    table.multiply_many(elements)
}

pub fn variable_base_msm<G: AffineCurve>(bases: &[G], scalars: &[G::ScalarField]) -> G::Projective {
    let s = cfg_iter!(scalars)
        .map(|b| b.into_repr())
        .collect::<Vec<_>>();
    VariableBaseMSM::multi_scalar_mul(bases, &s)
}

pub fn variable_base_msm_with_bigint<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Projective {
    VariableBaseMSM::multi_scalar_mul(bases, &scalars)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use ark_bls12_381::Bls12_381;
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::wnaf::WnafContext;
    use ark_ec::{group::Group, AffineCurve, PairingEngine};
    use ark_ff::PrimeField;
    use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn timing_ark_ops() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let context = WnafContext::new(4);
        let mut group_elem = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng);
        let group_elem_affine = group_elem.into_affine();
        let table = context.table(group_elem);

        let mut d0 = Duration::default();
        let mut d1 = Duration::default();
        let mut d2 = Duration::default();
        let mut d3 = Duration::default();
        let mut d4 = Duration::default();

        for _ in 0..100 {
            let e = Fr::rand(&mut rng);

            let start = Instant::now();
            let mut temp = group_elem_affine.into_projective();
            temp *= e;
            d0 += start.elapsed();

            let start = Instant::now();
            let _ = context.mul_with_table(&table, &e).unwrap();
            d1 += start.elapsed();

            let start = Instant::now();
            group_elem *= e;
            d2 += start.elapsed();

            let start = Instant::now();
            let _ = group_elem_affine.mul(e.into_repr());
            d3 += start.elapsed();

            let start = Instant::now();
            let _ = <<Bls12_381 as PairingEngine>::G1Projective as Group>::mul(&group_elem, &e);
            d4 += start.elapsed();
        }

        println!("d0={:?}", d0);
        println!("d1={:?}", d1);
        println!("d2={:?}", d2);
        println!("d3={:?}", d3);
        println!("d4={:?}", d4);

        let mut d5 = Duration::default();
        let mut d6 = Duration::default();
        for _ in 0..100 {
            let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let g2 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let e1 = Fr::rand(&mut rng);
            let e2 = Fr::rand(&mut rng);

            let start = Instant::now();
            let _ = g1.mul(e1.into_repr()) + g2.mul(e2.into_repr());
            d5 += start.elapsed();

            let start = Instant::now();
            let _ = VariableBaseMSM::multi_scalar_mul(&[g1, g2], &[e1.into_repr(), e2.into_repr()]);
            d6 += start.elapsed();
        }

        println!("d5={:?}", d5);
        println!("d6={:?}", d6);

        let mut d7 = Duration::default();
        let mut d8 = Duration::default();
        for _ in 0..100 {
            let mut g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng);
            let g2 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

            let mut g3 = g1.clone();
            let g4 = g2.clone();

            let start = Instant::now();
            g1 += g2.into_projective();
            d7 += start.elapsed();

            let start = Instant::now();
            g3.add_assign_mixed(&g4);
            d8 += start.elapsed();
        }

        println!("d7={:?}", d7);
        println!("d8={:?}", d8);

        let mut d9 = Duration::default();
        let mut d10 = Duration::default();

        for _ in 0..100 {
            let scalars = (0..30).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let g = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng);

            let start = Instant::now();
            multiply_field_elems_with_same_group_elem(g, scalars.as_slice());
            d9 += start.elapsed();

            let start = Instant::now();
            let a = g.into_affine();
            let _ = scalars
                .iter()
                .map(|s| a.mul(s.into_repr()))
                .collect::<Vec<_>>();
            d10 += start.elapsed();
        }

        println!("d9={:?}", d9);
        println!("d10={:?}", d10);

        let mut d11 = Duration::default();
        let mut d12 = Duration::default();

        for _ in 0..100 {
            let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let g2 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let e1 = Fr::rand(&mut rng);
            let e2 = Fr::rand(&mut rng);

            let start = Instant::now();
            let _ = g1.mul(e1.into_repr()) + g2.mul(e2.into_repr());
            d11 += start.elapsed();

            let start = Instant::now();
            let _ = VariableBaseMSM::multi_scalar_mul(&[g1, g2], &[e1.into_repr(), e2.into_repr()]);
            d12 += start.elapsed();
        }

        println!("d11={:?}", d11);
        println!("d12={:?}", d12);

        // Pre-Prepared vs not prepared for pairing
        let mut d13 = Duration::default();
        let mut d14 = Duration::default();

        for _ in 0..100 {
            let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
            let g2 = <Bls12_381 as PairingEngine>::G2Projective::rand(&mut rng).into_affine();
            let g3 = <Bls12_381 as PairingEngine>::G1Prepared::from(g1.clone());
            let g4 = <Bls12_381 as PairingEngine>::G2Prepared::from(g2.clone());

            let start = Instant::now();
            let _ = <Bls12_381 as PairingEngine>::pairing(g1, g2);
            d13 += start.elapsed();

            let start = Instant::now();
            let _ = <Bls12_381 as PairingEngine>::product_of_pairings(&[(g3, g4)]);
            d14 += start.elapsed();
        }

        println!("d13={:?}", d13);
        println!("d14={:?}", d14);

        let mut d15 = Duration::default();
        let mut d16 = Duration::default();

        let g = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng);
        let count = 10;

        let start = Instant::now();
        let scalar_size = Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(count);
        let outerc = (scalar_size + window_size - 1) / window_size;
        let table = FixedBaseMSM::get_window_table(scalar_size, window_size, g);
        d15 += start.elapsed();

        let g = g.into_affine();
        for _ in 0..count {
            let e = Fr::rand(&mut rng);

            let start = Instant::now();
            let _ = FixedBaseMSM::windowed_mul::<<Bls12_381 as PairingEngine>::G1Projective>(
                outerc,
                window_size,
                &table,
                &e,
            );
            d15 += start.elapsed();

            let start = Instant::now();
            let _ = g.mul(e.into_repr());
            d16 += start.elapsed();
        }

        println!("d15={:?}", d15);
        println!("d16={:?}", d16);
    }
}
