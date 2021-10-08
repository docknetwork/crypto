use ark_ec::wnaf::WnafContext;
use ark_ec::ProjectiveCurve;
use ark_std::{
    iter::{IntoIterator, Iterator},
    vec::Vec,
};

// TODO: Window size should not be hardcoded. It can be inferred from `group_elem`

/// The same group element is multiplied by each in `elements` using a window table
pub(crate) fn multiply_field_elems_refs_with_same_group_elem<'a, G: ProjectiveCurve>(
    window_size: usize,
    group_elem: G,
    elements: impl Iterator<Item = &'a G::ScalarField>,
) -> Vec<G> {
    let context = WnafContext::new(window_size);
    let table = context.table(group_elem);
    elements
        .into_iter()
        .map(|e| context.mul_with_table(&table, e).unwrap())
        .collect()
}

/// The same group element is multiplied by each in `elements` using a window table
pub(crate) fn multiply_field_elems_with_same_group_elem<G: ProjectiveCurve>(
    window_size: usize,
    group_elem: G,
    elements: impl Iterator<Item = G::ScalarField>,
) -> Vec<G> {
    let context = WnafContext::new(window_size);
    let table = context.table(group_elem);
    elements
        .into_iter()
        .map(|e| context.mul_with_table(&table, &e).unwrap())
        .collect()
}

/// Return `par_iter` or `iter` depending on whether feature `parallel` is enabled
#[macro_export]
macro_rules! iter {
    ($val:expr) => {{
        #[cfg(feature = "parallel")]
        let it = $val.par_iter();
        #[cfg(not(feature = "parallel"))]
        let it = $val.iter();
        it
    }};
}

/// Return `into_par_iter` or `into_iter` depending on whether feature `parallel` is enabled
#[macro_export]
macro_rules! into_iter {
    ($val:expr) => {{
        #[cfg(feature = "parallel")]
        let it = $val.into_par_iter();
        #[cfg(not(feature = "parallel"))]
        let it = $val.into_iter();
        it
    }};
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use ark_bls12_381::Bls12_381;
    use ark_ec::msm::VariableBaseMSM;
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
            multiply_field_elems_refs_with_same_group_elem(4, g, scalars.iter());
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
    }
}
