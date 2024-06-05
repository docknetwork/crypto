#![allow(non_snake_case)]

use crate::{
    aliases::{FullDigest, SyncIfParallel},
    concat_slices,
    misc::le_bytes_iter,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField,
};
use ark_std::vec::Vec;
use digest::Digest;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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

/// Hash given bytes `seed` to a field element using constant time operations where `dst` is the domain
/// separation tag.
pub fn hash_to_field<F: PrimeField, D: FullDigest>(dst: &[u8], seed: &[u8]) -> F {
    let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(dst);
    hasher.hash_to_field(seed, 1).pop().unwrap()
}

/// Hash given bytes `seed` to `count` number of field element using constant time operations where `dst` is the domain
/// separation tag. It's different from `HashToField::hash_to_field` in that the first `n` elements of
/// `hash_to_field_many(n)` and `hash_to_field_many(n + x)` for any `x` >= 0 are the same.
pub fn hash_to_field_many<F: PrimeField, D: FullDigest + SyncIfParallel>(
    dst: &[u8],
    seed: &[u8],
    count: u32,
) -> Vec<F> {
    let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(dst);
    le_bytes_iter(count)
        .map(|ctr| concat_slices!(seed, ctr))
        .map(|seed| hasher.hash_to_field(&seed, 1).pop().unwrap())
        .collect()
}
