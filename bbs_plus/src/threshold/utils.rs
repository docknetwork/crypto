use crate::threshold::multiplication_phase::Phase2Output;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{cfg_into_iter, ops::Mul, vec::Vec};
use itertools::Itertools;
use oblivious_transfer::ParticipantId;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn compute_masked_arguments_to_multiply<F: PrimeField>(
    signing_key: &F,
    r: Vec<F>,
    mut zero_shares: Vec<F>,
    self_id: ParticipantId,
    others: &[ParticipantId],
) -> (Vec<F>, Vec<F>) {
    let batch_size = r.len();
    debug_assert_eq!(zero_shares.len(), 2 * batch_size);
    let alphas = zero_shares.drain(0..batch_size).collect::<Vec<_>>();
    let betas = zero_shares;
    let lambda = secret_sharing_and_dkg::common::lagrange_basis_at_0::<F>(&others, self_id);
    let (masked_signing_key_shares, masked_rs) = cfg_into_iter!(r)
        .zip(cfg_into_iter!(alphas).zip(cfg_into_iter!(betas)))
        .map(|(r, (alpha, beta))| {
            let masked_signing_key_share = alpha + (lambda * signing_key);
            let masked_r = beta + r;
            (masked_signing_key_share, masked_r)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .multiunzip::<(Vec<F>, Vec<F>)>();
    (masked_signing_key_shares, masked_rs)
}

pub fn compute_R_and_u<G: AffineRepr>(
    base: G::Group,
    r: &G::ScalarField,
    e: &G::ScalarField,
    masked_r: &G::ScalarField,
    masked_signing_key_share: &G::ScalarField,
    index_in_output: usize,
    phase2: &Phase2Output<G::ScalarField>,
) -> (G, G::ScalarField) {
    let R = base.mul(r).into_affine();
    let mut u = *masked_r * (*e + masked_signing_key_share);
    for (_, (a, b)) in &phase2.z_A {
        u += a[index_in_output];
        u += b[index_in_output];
    }
    for (_, (a, b)) in &phase2.z_B {
        u += a[index_in_output];
        u += b[index_in_output];
    }
    (R, u)
}
