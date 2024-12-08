use crate::{common::MemberCommitmentKey, error::SmcRangeProofError};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::ops::Neg;
use dock_crypto_utils::ff::powers;

pub(super) fn check_commitment_for_arbitrary_range<G: AffineRepr>(
    base: u16,
    z_sigma_min: &[G::ScalarField],
    z_sigma_max: &[G::ScalarField],
    z_r_min: &G::ScalarField,
    z_r_max: &G::ScalarField,
    D_min: &G,
    D_max: &G,
    min: u64,
    max: u64,
    commitment: &G,
    challenge: &G::ScalarField,
    comm_key: &MemberCommitmentKey<G>,
) -> Result<(), SmcRangeProofError> {
    let l = find_l_for_arbitrary_range(max, min, base) as u32;

    let comm_c = *commitment * challenge;
    // Calculate powers of base once to avoid recomputing them again during commitment

    let base_powers = powers(&G::ScalarField::from(base), z_sigma_min.len() as u32);

    // Following 2 checks are different from the paper. The paper has typos where the exponent
    // of `g` is not multiplied by the challenge. Also, the paper uses only a single `D` which can leak
    // some information to the verifier in some cases. See the module docs for more info
    if (-comm_c
        + comm_key.g * (G::ScalarField::from(min) * challenge)
        + comm_key.commit_decomposed_given_base_powers(&base_powers, z_sigma_min, z_r_min))
    .into_affine()
        != *D_min
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    // x = base^l - max
    let mut x = G::ScalarField::from((base as u64).pow(l));
    x -= G::ScalarField::from(max);
    if (-comm_c - comm_key.g * (x * challenge)
        + comm_key.commit_decomposed_given_base_powers(&base_powers, z_sigma_max, z_r_max))
    .into_affine()
        != *D_max
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

pub(super) fn check_commitment_for_prefect_range<G: AffineRepr>(
    base: u16,
    z_sigma: &[G::ScalarField],
    z_r: &G::ScalarField,
    D: &G,
    commitment: &G,
    challenge: &G::ScalarField,
    comm_key: &MemberCommitmentKey<G>,
) -> Result<(), SmcRangeProofError> {
    if (comm_key.commit_decomposed(base, z_sigma, z_r) + commitment.into_group().neg() * challenge)
        .into_affine()
        != *D
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

/// Returns the number of digits, `l`, needed to represent `max - min` in base `base` and satisfy `max - min < base^l`
pub fn find_l_for_arbitrary_range(max: u64, min: u64, base: u16) -> u16 {
    let diff = max - min;
    let l = diff.ilog(base as u64);
    if (base as u64).pow(l) > diff {
        l as u16
    } else {
        l as u16 + 1
    }
}

/// Returns the number of digits, `l`, needed to represent `max` in base `base`, i.e. `l = log_{base} max`. `l` should satisfy `base^l = max`
pub fn find_l_for_perfect_range(max: u64, base: u16) -> Result<u16, SmcRangeProofError> {
    let l = max.ilog(base as u64) as u16;
    if (base as u64).pow(l as u32) != max {
        return Err(SmcRangeProofError::NotAPerfectRange(max, base));
    }
    Ok(l)
}
