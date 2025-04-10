use alloc::string::ToString;
use ark_ec::Group;
use ark_std::collections::BTreeMap;

/// Solve discrete log using brute force.
/// `max` is the maximum value of the discrete log and this returns `x` such that `1 <= x <= max` and `base * x = target`
/// if such `x` exists, else return None.
pub fn solve_discrete_log_brute_force<G: Group>(max: u64, base: G, target: G) -> Option<u64> {
    if target == base {
        return Some(1);
    }
    let mut cur = base;
    for j in 2..=max {
        cur += base;
        if cur == target {
            return Some(j);
        }
    }
    None
}

/// Solve discrete log using Baby Step Giant Step as described in section 2 of <https://eprint.iacr.org/2015/605>
/// `max` is the maximum value of the discrete log and this returns `x` such that `1 <= x <= max` and `base * x = target`
/// if such `x` exists, else return None.
/// `max` is of type u64 but only accurate till a 52 bit value since 12 bit precision is lost while taking square root.
pub fn solve_discrete_log_bsgs<G: Group>(max: u64, base: G, target: G) -> Option<u64> {
    // Will lose 12 bits of precision
    let m = (max as f64).sqrt().ceil() as u64;
    solve_discrete_log_bsgs_inner(m, m, base, target)
}

/// Solve discrete log using Baby Step Giant Step with worse worst-case performance but better average case performance as described in section 2 of <https://eprint.iacr.org/2015/605>.
/// `max` is the maximum value of the discrete log and this returns `x` such that `1 <= x <= max` and `base * x = target`
/// if such `x` exists, else return None.
/// `max` is of type u64 but only accurate till a 52 bit value since 12 bit precision is lost while taking square root.
pub fn solve_discrete_log_bsgs_alt<G: Group>(max: u64, base: G, target: G) -> Option<u64> {
    // Will lose 12 bits of precision
    let m = (max as f64 / 2.0).sqrt().ceil() as u64;
    solve_discrete_log_bsgs_inner(m, 2 * m, base, target)
}

fn solve_discrete_log_bsgs_inner<G: Group>(
    num_baby_steps: u64,
    num_giant_steps: u64,
    base: G,
    target: G,
) -> Option<u64> {
    if base == target {
        return Some(1);
    }
    if target.is_zero() {
        return Some(0);
    }
    // Create a map of `base * i -> i` for `i` in `[1, num_baby_steps]`
    let mut baby_steps = BTreeMap::new();
    baby_steps.insert(base.to_string(), 1);
    let mut cur = base;
    for i in 2..=num_baby_steps {
        cur = cur + base;
        if cur == target {
            return Some(i);
        }
        baby_steps.insert(cur.to_string(), i);
    }
    let base_m = cur;
    let mut cur = target;
    for i in 0..num_giant_steps {
        if let Some(b) = baby_steps.get(&cur.to_string()) {
            return Some(i * num_baby_steps + b);
        }
        cur = cur - base_m;
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::{
        ops::Mul,
        time::{Duration, Instant},
    };

    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ec::pairing::{Pairing, PairingOutput};
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn solving_discrete_log() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: Group + Mul<Fr, Output = G>>(
            rng: &mut StdRng,
            base: G,
            check_large_value: bool,
        ) {
            let checks_per_max = 10;
            let mut total_checks = 0;
            let mut duration_naive = Duration::default();
            let mut duration_bsgs = Duration::default();
            let mut duration_bsgs_alt = Duration::default();

            for max in [1, 2, 3, 4, 5, 6, 8, 15, 16, 31, 32, 255, 256, 65535] {
                for _ in 0..checks_per_max {
                    let dl = (u16::rand(rng) as u64 % max) + 1;
                    let target = base * Fr::from(dl);

                    // println!("For max={} and discrete log={}", max, dl);
                    let start = Instant::now();
                    let dl_naive = solve_discrete_log_brute_force(max, base, target);
                    let time = start.elapsed();
                    assert_eq!(dl, dl_naive.unwrap());
                    // println!("Time for naive approach: {:?}", time);
                    duration_naive += time;

                    let start = Instant::now();
                    let dl_bsgs = solve_discrete_log_bsgs(max, base, target);
                    let time = start.elapsed();
                    assert_eq!(dl, dl_bsgs.unwrap());
                    // println!("Time for BSGS approach: {:?}", time);
                    duration_bsgs += time;

                    let start = Instant::now();
                    let dl_bsgs_alt = solve_discrete_log_bsgs_alt(max, base, target);
                    let time = start.elapsed();
                    assert_eq!(dl, dl_bsgs_alt.unwrap());
                    // println!("Time for alt. BSGS approach: {:?}", time);
                    duration_bsgs_alt += time;

                    total_checks += 1;
                }
            }

            if check_large_value {
                for dl in [
                    u32::MAX as u64,                  // 32-bit value
                    u32::MAX as u64 * u8::MAX as u64, // 40-bit value
                ] {
                    let target = base * Fr::from(dl);
                    println!("For discrete log={}", dl);

                    let start = Instant::now();
                    let dl_bsgs = solve_discrete_log_bsgs(dl, base, target);
                    let time = start.elapsed();
                    assert_eq!(dl, dl_bsgs.unwrap());
                    println!("Time for BSGS approach: {:?}", time);

                    let start = Instant::now();
                    let dl_bsgs_alt = solve_discrete_log_bsgs_alt(dl, base, target);
                    let time = start.elapsed();
                    assert_eq!(dl, dl_bsgs_alt.unwrap());
                    println!("Time for alt. BSGS approach: {:?}", time);
                }
            }

            let target = base * Fr::from(10);
            assert!(solve_discrete_log_brute_force(8, base, target).is_none());
            assert!(solve_discrete_log_bsgs(8, base, target).is_none());

            println!("For total {} checks, brute force took {:?} and baby step giant step took {:?} and alt. baby step giant step took {:?}", total_checks, duration_naive, duration_bsgs, duration_bsgs_alt);
        }

        println!("\n\nTesting for group G1");
        let g1 = G1Projective::rand(&mut rng);
        check::<G1Projective>(&mut rng, g1, true);

        println!("\n\nTesting for group G2");
        let g2 = G2Projective::rand(&mut rng);
        check::<G2Projective>(&mut rng, g2, true);

        println!("\n\nTesting for group GT");
        let gt = <Bls12_381 as Pairing>::pairing(g1, g2);
        check::<PairingOutput<Bls12_381>>(&mut rng, gt, false);
    }
}
