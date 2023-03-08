#![allow(non_snake_case)]

use crate::concat_slices;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use digest::Digest;

/// Hash bytes to a point on the curve. Returns as Projective coordinates. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters.
pub fn projective_group_elem_from_try_and_incr<G: AffineRepr, D: Digest>(bytes: &[u8]) -> G::Group {
    let mut hash = D::digest(bytes);
    let mut g = G::from_random_bytes(&hash);
    let mut j = 1u64;
    while g.is_none() {
        hash = D::digest(&concat_slices!(bytes, b"-attempt-", j.to_le_bytes()));
        g = G::from_random_bytes(&hash);
        j += 1;
    }
    g.unwrap().mul_by_cofactor_to_group()
}

/// Hash bytes to a point on the curve. Returns as Affine coordinates. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters.
pub fn affine_group_elem_from_try_and_incr<G: AffineRepr, D: Digest>(bytes: &[u8]) -> G {
    projective_group_elem_from_try_and_incr::<G, D>(bytes).into_affine()
}

/// Hash bytes to a field element. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters or challenge
pub fn field_elem_from_try_and_incr<F: PrimeField, D: Digest>(bytes: &[u8]) -> F {
    let mut hash = D::digest(bytes);
    let mut f = F::from_random_bytes(&hash);
    let mut j = 1u64;
    while f.is_none() {
        hash = D::digest(&concat_slices!(bytes, b"-attempt-", j.to_le_bytes()));
        f = F::from_random_bytes(&hash);
        j += 1;
    }
    f.unwrap()
}
