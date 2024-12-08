use crate::{
    common::{base_n_digits_for_u128, MemberCommitmentKey},
    error::SmcRangeProofError,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{cfg_into_iter, vec, vec::Vec};
use dock_crypto_utils::ff::inner_product;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Return range, i.e. `max - min`, such that it's a multiple of `base-1`. If `base-1` does not divide `max - min`,
/// the new range is `(max - min)*(base-1)`. This will require the randomness in the commitment to be multiplied by
/// `base-1` as well.
pub(super) fn get_range_and_randomness_multiple(base: u16, min: u64, max: u64) -> (u128, u16) {
    // If the range, i.e. max - min is not a multiple of base-1, it has to be made, by multiplying it with base-1
    // which might not fit within a u64 so make it a wider type u128
    let mut range = (max - min) as u128;
    let mut randomness_multiple = 1;
    let b_1 = (base - 1) as u128;
    if range % b_1 != 0 {
        // This can't fail since the original value of max-min fits in a u64
        range = range * b_1;
        randomness_multiple = randomness_multiple * (base - 1);
    }
    (range, randomness_multiple)
}

pub(super) fn check_commitment<G: AffineRepr>(
    base: u16,
    z_sigma: &[G::ScalarField],
    z_r: &G::ScalarField,
    D: &G,
    min: u64,
    max: u64,
    commitment: &G,
    challenge: &G::ScalarField,
    comm_key: &MemberCommitmentKey<G>,
) -> Result<(), SmcRangeProofError> {
    // -1 because range in sumset is inclusive but in the protocol, upper bound is exclusive
    let (range, randomness_multiple) = get_range_and_randomness_multiple(base, min, max - 1);

    let l = find_number_of_digits(range, base);
    let G = find_sumset_boundaries(range, base, l);

    if (-(*commitment * (G::ScalarField::from(randomness_multiple) * challenge))
        + comm_key.g
            * (G::ScalarField::from(min as u128 * randomness_multiple as u128) * challenge)
        + comm_key.commit(
            &inner_product(
                z_sigma,
                &cfg_into_iter!(G)
                    .map(|G_i| G::ScalarField::from(G_i))
                    .collect::<Vec<_>>(),
            ),
            &(G::ScalarField::from(randomness_multiple) * z_r),
        ))
    .into_affine()
        != *D
    {
        return Err(SmcRangeProofError::InvalidRangeProof);
    }
    Ok(())
}

/// Returns what the paper calls l and calculated as `ceil(log_u(range+1))`. Here we assume that `base - 1` divides `range`.
pub fn find_number_of_digits(range: u128, base: u16) -> u32 {
    let mut l = (range + 1).ilog(base as u128);
    if (base as u128).pow(l) < (range + 1) {
        l += 1;
    }
    l
}

/// Returns what the paper calls `G_i`, `range` is called `H` and `num` is called `l` in the paper. Calculates as
/// per Theorem 2 in the paper
pub fn find_sumset_boundaries(range: u128, base: u16, num: u32) -> Vec<u128> {
    if base == 2 {
        cfg_into_iter!(0..num)
            .map(|i| (range + (1 << i)) >> (i + 1))
            .collect()
    } else {
        let h = base_n_digits_for_u128(range, base);
        let mut g = vec![];
        for i in 0..num as usize {
            // h_hat = floor(range / base^{i+1})
            let h_hat = range / (base as u128).pow(i as u32 + 1);
            let sum = h[..i].iter().map(|h_i| *h_i as u128).sum::<u128>();
            g.push(h_hat + ((1 + h[i] as u128 + (sum % (base as u128 - 1))) / base as u128))
        }
        g
    }
}

/// Returns digits of `value` when expressed in sumset notation give sumset boundaries, i.e. `G`
pub fn decompose_for_sumset(value: u128, G: &[u128], base: u16) -> Vec<u16> {
    let mut deomposition = vec![0; G.len()];
    let mut target = value;
    for (i, g_i) in G.iter().enumerate() {
        // For each g_i, check if target >= (base-1) * g_i. If it is then digit corresponding to g_i is (base-1) and new
        // target is target - (base-1) * g_i. Else check if target >= (base-2) * g_i and so on.
        for u_i in (1..base).rev() {
            let g_u = *g_i * u_i as u128;
            if target >= g_u {
                deomposition[i] = u_i;
                target -= g_u;
                break;
            }
        }
    }
    debug_assert_eq!(target, 0);
    deomposition
}

/// Pre-requisites of applying sumset protocol
/// Returns number of digits, sumset boundaries (G), randomness multiple and digits of the adapted value.
pub fn get_sumset_parameters(
    value: u64,
    min: u64,
    max: u64,
    base: u16,
) -> (u32, Vec<u128>, u16, Vec<u16>) {
    // The protocol works for the range [0, H], so change `value` and set range accordingly.
    // New value becomes value - min
    // New max becomes max-1 because the implemented protocol is asking for the proof in range [min, max) and
    // sumset protocol in the paper is described for range [0, max], i.e. upper bound is inclusive in the paper,
    // but it's not in the implementation
    let (range, randomness_multiple) = get_range_and_randomness_multiple(base, min, max - 1);
    let mut value = (value - min) as u128;
    if randomness_multiple != 1 {
        // range had to be artificially increased so increase the value accordingly. This won't overflow as original value is a u64
        value = value * (base - 1) as u128;
    }

    let l = find_number_of_digits(range, base);
    let G = find_sumset_boundaries(range, base, l);
    let digits = decompose_for_sumset(value, &G, base);
    // Following is only for debugging
    // let mut expected = 0_u64;
    // for j in 0..digits.len() {
    //     assert!(digits[j] < base);
    //     expected += digits[j] as u64 * G[j];
    // }
    // assert_eq!(expected, value);
    (l, G, randomness_multiple, digits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{
        rand::{prelude::StdRng, Rng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    #[test]
    fn sumsets_check() {
        // Test that sumsets are correctly created and elements are correctly decomposed
        let mut rng = StdRng::seed_from_u64(0u64);

        let iters_per_base = 50;
        let iters_per_max = 100;
        for base in [3, 4, 5, 8, 10, 11, 14, 16] {
            for _ in 0..iters_per_base {
                let max = u64::rand(&mut rng) as u128 * (base as u128 - 1);
                let l = find_number_of_digits(max, base);
                let G = find_sumset_boundaries(max, base, l);
                let start = Instant::now();
                let mut test_vec = vec![0, 1, max, max - 1];
                for _ in 0..iters_per_max {
                    test_vec.push(rng.gen_range(2..max - 1));
                }
                for i in test_vec {
                    let sigma = decompose_for_sumset(i, &G, base);
                    assert_eq!(sigma.len(), G.len());
                    let mut expected = 0_u128;
                    for j in 0..sigma.len() {
                        assert!(sigma[j] < base);
                        expected += sigma[j] as u128 * G[j];
                    }
                    assert_eq!(
                        expected, i,
                        "Failed for value={} with base={} and max={}. G={:?}, sigma={:?}",
                        i, base, max, G, sigma
                    );
                }
                println!(
                    "Check for base={} and max={} finished in {:?}",
                    base,
                    max,
                    start.elapsed()
                );
            }
        }
    }
}
