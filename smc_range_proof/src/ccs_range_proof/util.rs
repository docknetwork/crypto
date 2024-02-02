use crate::{common::MemberCommitmentKey, error::SmcRangeProofError};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::ops::Neg;
use dock_crypto_utils::ff::powers;

pub(super) fn check_commitment_for_arbitrary_range<E: Pairing>(
    base: u16,
    z_sigma_min: &[E::ScalarField],
    z_sigma_max: &[E::ScalarField],
    z_r_min: &E::ScalarField,
    z_r_max: &E::ScalarField,
    D_min: &E::G1Affine,
    D_max: &E::G1Affine,
    min: u64,
    max: u64,
    commitment: &E::G1Affine,
    challenge: &E::ScalarField,
    comm_key: &MemberCommitmentKey<E::G1Affine>,
) -> Result<(), SmcRangeProofError> {
    let l = find_l_greater_than(max, base) as u32;

    let comm_c = *commitment * challenge;
    // Calculate powers of base once to avoid recomputing them again during commitment

    let base_powers = powers(&E::ScalarField::from(base), z_sigma_min.len() as u32);

    // Following 2 checks are different from the paper. The paper has typos where the exponent
    // of `g` is not multiplied by the challenge. Also the paper uses only a single `D` which can leak
    // some information to the verifier in some cases. See the module docs for more info
    if (-comm_c
        + comm_key.g * (E::ScalarField::from(min) * challenge)
        + comm_key.commit_decomposed_given_base_powers(&base_powers, z_sigma_min, z_r_min))
    .into_affine()
        != *D_min
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    if (-comm_c - comm_key.g * (E::ScalarField::from((base as u64).pow(l) - max) * challenge)
        + comm_key.commit_decomposed_given_base_powers(&base_powers, z_sigma_max, z_r_max))
    .into_affine()
        != *D_max
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

pub(super) fn check_commitment_for_prefect_range<E: Pairing>(
    base: u16,
    z_sigma: &[E::ScalarField],
    z_r: &E::ScalarField,
    D: &E::G1Affine,
    commitment: &E::G1Affine,
    challenge: &E::ScalarField,
    comm_key: &MemberCommitmentKey<E::G1Affine>,
) -> Result<(), SmcRangeProofError> {
    if (comm_key.commit_decomposed(base, z_sigma, z_r) + commitment.into_group().neg() * challenge)
        .into_affine()
        != *D
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

pub fn find_l_greater_than(max: u64, base: u16) -> u16 {
    let l = max.ilog(base as u64);
    if (base as u64).pow(l) > max {
        l as u16
    } else {
        l as u16 + 1
    }
}

pub fn find_l(max: u64, base: u16) -> u16 {
    let l = max.ilog(base as u64);
    let power = (base as u64).pow(l);
    assert_eq!(power, max);
    l as u16
}

#[macro_export]
macro_rules! gen_proof_perfect_range {
    ($self: ident, $challenge: ident, $proof: ident) => {{
        // Following is different from the paper, the paper has `-` but here its `+`
        let z_v = cfg_into_iter!(0..$self.V.len())
            .map(|i| $self.t[i] + ($self.v[i] * $challenge))
            .collect::<Vec<_>>();
        let z_sigma = cfg_into_iter!(0..$self.V.len())
            .map(|i| $self.s[i] + ($self.digits[i] * $challenge))
            .collect::<Vec<_>>();
        let z_r = $self.m + ($self.r * $challenge);
        $proof {
            base: $self.base,
            V: $self.V,
            a: $self.a,
            D: $self.D,
            z_v,
            z_sigma,
            z_r,
        }
    }};
}

#[macro_export]
macro_rules! gen_proof_arbitrary_range {
    ($self: ident, $challenge: ident, $proof: ident) => {{
        let z_v_min = cfg_into_iter!(0..$self.V_min.len())
            .map(|i| $self.t_min[i] + ($self.v_min[i] * $challenge))
            .collect::<Vec<_>>();
        let z_v_max = cfg_into_iter!(0..$self.V_max.len())
            .map(|i| $self.t_max[i] + ($self.v_max[i] * $challenge))
            .collect::<Vec<_>>();
        let z_sigma_min = cfg_into_iter!(0..$self.V_min.len())
            .map(|i| $self.s_min[i] + ($self.digits_min[i] * $challenge))
            .collect::<Vec<_>>();
        let z_sigma_max = cfg_into_iter!(0..$self.V_max.len())
            .map(|i| $self.s_max[i] + ($self.digits_max[i] * $challenge))
            .collect::<Vec<_>>();
        let z_r_min = $self.m_min + ($self.r * $challenge);
        let z_r_max = $self.m_max + ($self.r * $challenge);
        $proof {
            base: $self.base,
            V_min: $self.V_min,
            V_max: $self.V_max,
            a_min: $self.a_min,
            a_max: $self.a_max,
            D_min: $self.D_min,
            D_max: $self.D_max,
            z_v_min,
            z_v_max,
            z_sigma_min,
            z_sigma_max,
            z_r_min,
            z_r_max,
        }
    }};
}
