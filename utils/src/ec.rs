use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_std::{cfg_into_iter, cfg_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn batch_normalize_projective_into_affine<G: ProjectiveCurve>(mut v: Vec<G>) -> Vec<G::Affine> {
    G::batch_normalization(&mut v);
    cfg_into_iter!(v).map(|v| v.into()).collect()
}

pub fn pairing_product<E: PairingEngine>(a: &[E::G1Affine], b: &[E::G2Affine]) -> E::Fqk {
    let pairs: Vec<(E::G1Prepared, E::G2Prepared)> = cfg_iter!(a)
        .map(|e| E::G1Prepared::from(*e))
        .zip(cfg_iter!(b).map(|e| E::G2Prepared::from(*e)))
        .collect();
    E::product_of_pairings(pairs.iter())
}

pub fn pairing_product_with_g2_prepared<E: PairingEngine>(
    a: &[E::G1Affine],
    b: Vec<E::G2Prepared>,
) -> E::Fqk {
    let pairs: Vec<(E::G1Prepared, E::G2Prepared)> = cfg_iter!(a)
        .map(|e| E::G1Prepared::from(*e))
        .zip(cfg_into_iter!(b))
        .collect();
    E::product_of_pairings(pairs.iter())
}
