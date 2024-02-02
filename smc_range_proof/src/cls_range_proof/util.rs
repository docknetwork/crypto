use crate::common::{base_n_digits, MemberCommitmentKey};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_std::{cfg_into_iter, collections::BTreeMap, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::error::SmcRangeProofError;
use dock_crypto_utils::ff::inner_product;

#[macro_export]
macro_rules! gen_proof {
    ($self: ident, $challenge: ident, $proof: ident) => {{
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

pub(super) fn get_range_and_randomness_multiple(base: u16, min: u64, max: u64) -> (u64, u16) {
    let mut range = max - min;
    let mut randomness_multiple = 1;
    let b_1 = (base - 1) as u64;
    if range % b_1 != 0 {
        range = range * b_1;
        randomness_multiple = randomness_multiple * (base - 1);
    }
    (range, randomness_multiple)
}

pub(super) fn check_commitment<E: Pairing>(
    base: u16,
    z_sigma: &[E::ScalarField],
    z_r: &E::ScalarField,
    D: &E::G1Affine,
    min: u64,
    max: u64,
    commitment: &E::G1Affine,
    challenge: &E::ScalarField,
    comm_key: &MemberCommitmentKey<E::G1Affine>,
) -> Result<(), SmcRangeProofError> {
    let (range, randomness_multiple) = get_range_and_randomness_multiple(base, min, max);

    let l = find_number_of_digits(range, base);
    let G = find_sumset_boundaries(range, base, l);

    if (-(*commitment * (E::ScalarField::from(randomness_multiple) * challenge))
        + comm_key.g * (E::ScalarField::from(min * randomness_multiple as u64) * challenge)
        + comm_key.commit(
            &inner_product(
                z_sigma,
                &cfg_into_iter!(G)
                    .map(|G_i| E::ScalarField::from(G_i))
                    .collect::<Vec<_>>(),
            ),
            &(E::ScalarField::from(randomness_multiple) * z_r),
        ))
    .into_affine()
        != *D
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

/// Returns what the paper calls l. Here we assume that `base - 1` divides `max`.
pub fn find_number_of_digits(max: u64, base: u16) -> u16 {
    // (((max + 1) as f64).log(base as f64)).ceil() as u16
    // Above can cause overflow with large u64 values as f64 can't contain the same amount of
    // integers as u64 so using the below loop instead
    let mut power = 1;
    let mut l = 0;
    while power < max {
        power *= base as u64;
        l += 1;
    }
    l
}

/// Returns what the paper calls `G_i`, `max` is called `H` and `num` is called `l` in the paper
pub fn find_sumset_boundaries(max: u64, base: u16, num: u16) -> Vec<u64> {
    if base == 2 {
        cfg_into_iter!(0..num)
            .map(|i| (max + (1 << i)) >> (i + 1))
            .collect()
    } else {
        let h = base_n_digits(max, base);
        let mut g = vec![];
        for i in 0..num as usize {
            let h_hat = max / (base as u64).pow(i as u32 + 1);
            let sum = h[..i].iter().map(|h_i| *h_i as u64).sum::<u64>() as u64;
            g.push(h_hat + ((1 + h[i] as u64 + (sum % (base as u64 - 1))) / base as u64))
        }
        g
    }
}

pub fn solve_linear_equations(y: u64, coefficients: &[u64], u: u16) -> Option<Vec<u16>> {
    let n = coefficients.len();
    let mut solutions = vec![0; n];

    fn find_value_for_index(
        index: usize,
        remaining_y: i64,
        solutions: &mut Vec<u16>,
        coefficients: &[u64],
        u: u16,
        memo: &mut BTreeMap<(usize, i64), bool>,
    ) -> bool {
        if index == coefficients.len() {
            if remaining_y == 0 {
                return true;
            }
            return false;
        }

        if let Some(&result) = memo.get(&(index, remaining_y)) {
            return result;
        }

        for x in 0..u {
            solutions[index] = x;
            let new_remaining_y = remaining_y - coefficients[index] as i64 * x as i64;
            if new_remaining_y >= 0
                && find_value_for_index(
                    index + 1,
                    new_remaining_y,
                    solutions,
                    coefficients,
                    u,
                    memo,
                )
            {
                memo.insert((index, remaining_y), true);
                return true;
            }
        }

        memo.insert((index, remaining_y), false);
        false
    }

    let mut memo: BTreeMap<(usize, i64), bool> = BTreeMap::new();

    if find_value_for_index(0, y as i64, &mut solutions, coefficients, u, &mut memo) {
        Some(solutions)
    } else {
        None
    }
}
