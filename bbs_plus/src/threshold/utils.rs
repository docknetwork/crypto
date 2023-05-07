use crate::threshold::multiplication_phase::Phase2Output;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{ops::Mul, vec::Vec};
use oblivious_transfer::ParticipantId;

pub fn compute_masked_arguments_to_multiply<F: PrimeField>(
    unmasked_signing_key: &F,
    unmasked_r: &F,
    mut zero_shares: Vec<F>,
    self_id: ParticipantId,
    others: &[ParticipantId],
) -> (F, F) {
    debug_assert_eq!(zero_shares.len(), 2);
    let alpha = zero_shares.pop().unwrap();
    let beta = zero_shares.pop().unwrap();
    let lambda = secret_sharing_and_dkg::common::lagrange_basis_at_0::<F>(&others, self_id);
    let masked_signing_key_share = alpha + (lambda * unmasked_signing_key);
    let masked_r = beta + unmasked_r;
    (masked_signing_key_share, masked_r)
}

pub fn compute_R_and_u<G: AffineRepr>(
    base: G::Group,
    r: G::ScalarField,
    e: G::ScalarField,
    masked_r: G::ScalarField,
    masked_signing_key_share: G::ScalarField,
    phase2: Phase2Output<G::ScalarField>,
) -> (G, G::ScalarField) {
    let R = base.mul(r).into_affine();
    let mut u = masked_r * (e + masked_signing_key_share);
    for (_, (a, b)) in phase2.z_A {
        u += a;
        u += b;
    }
    for (_, (a, b)) in phase2.z_B {
        u += a;
        u += b;
    }
    (R, u)
}
