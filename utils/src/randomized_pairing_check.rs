use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_std::rand::Rng;
use ark_std::{cfg_into_iter, cfg_iter, vec, vec::Vec, UniformRand};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Inspired from Snarkpack implementation - https://github.com/nikkolasg/snarkpack/blob/main/src/pairing_check.rs
/// RandomizedPairingChecker represents a check of the form e(A,B)e(C,D)... = T. Checks can
/// be aggregated together using random linear combination. The efficiency comes
/// from keeping the results from the miller loop output before proceeding to a final
/// exponentiation when verifying if all checks are verified.
/// For each pairing equation, multiply by a power of a random element created during initialization
#[derive(Debug, Clone)]
pub struct RandomizedPairingChecker<E: PairingEngine> {
    /// a miller loop result that is to be multiplied by other miller loop results
    /// before going into a final exponentiation result
    left: E::Fqk,
    /// a right side result which is already in the right subgroup Gt which is to
    /// be compared to the left side when "final_exponentiatiat"-ed
    right: E::Fqk,
    /// If true, delays the computation of miller loops till the end (unless overridden) trading off memory for CPU time.
    lazy: bool,
    /// Keeps the pairs of G1, G2 elements that need to be used in miller loops when running lazily
    pending: Vec<(E::G1Prepared, E::G2Prepared)>,
    random: E::Fr,
    /// For each pairing equation, its multiplied by `self.random`
    current_random: E::Fr,
}

impl<E> RandomizedPairingChecker<E>
where
    E: PairingEngine,
{
    pub fn new_using_rng<R: Rng>(rng: &mut R, lazy: bool) -> Self {
        Self::new(E::Fr::rand(rng), lazy)
    }

    pub fn new(random: E::Fr, lazy: bool) -> Self {
        Self {
            left: E::Fqk::one(),
            right: E::Fqk::one(),
            lazy,
            pending: vec![],
            random,
            current_random: E::Fr::one(),
        }
    }

    pub fn add_multiple_sources_and_target(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        out: &E::Fqk,
    ) {
        self.add_multiple_sources_and_target_with_laziness_choice(a, b, out, self.lazy)
    }

    pub fn add_multiple_sources(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        d: &[E::G2Affine],
    ) {
        self.add_multiple_sources_with_laziness_choice(a, b, c, d, self.lazy)
    }

    pub fn add_sources(&mut self, a: E::G1Affine, b: E::G2Affine, c: E::G1Affine, d: E::G2Affine) {
        self.add_sources_with_laziness_choice(a, b, c, d, self.lazy)
    }

    pub fn add_prepared_sources_and_target(
        &mut self,
        a: &[E::G1Affine],
        b: Vec<E::G2Prepared>,
        out: &E::Fqk,
    ) {
        self.add_prepared_sources_and_target_with_laziness_choice(a, b, out, self.lazy)
    }

    pub fn add_multiple_sources_and_target_with_laziness_choice(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        out: &E::Fqk,
        lazy: bool,
    ) {
        assert_eq!(a.len(), b.len());

        let m = self.current_random.into_repr();
        let mut it = cfg_iter!(a)
            .zip(cfg_iter!(b))
            .map(|(a, b)| {
                (
                    E::G1Prepared::from(a.mul(m).into_affine()),
                    E::G2Prepared::from(*b),
                )
            })
            .collect::<Vec<_>>();
        if lazy {
            self.pending.append(&mut it);
        } else {
            self.left *= E::miller_loop(it.iter());
        }
        self.right *= out.pow(m);
        self.current_random *= self.random;
    }

    pub fn add_multiple_sources_with_laziness_choice(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        d: &[E::G2Affine],
        lazy: bool,
    ) {
        assert_eq!(a.len(), b.len());
        assert_eq!(c.len(), d.len());
        let m = self.current_random.into_repr();
        let mut it = cfg_iter!(a)
            .zip(cfg_iter!(b))
            .map(|(a, b)| {
                (
                    E::G1Prepared::from(a.mul(m).into_affine()),
                    E::G2Prepared::from(*b),
                )
            })
            .collect::<Vec<_>>();
        let mut it1 = cfg_iter!(c)
            .zip(cfg_iter!(d))
            .map(|(c, d)| {
                (
                    E::G1Prepared::from(-c.mul(m).into_affine()),
                    E::G2Prepared::from(*d),
                )
            })
            .collect::<Vec<_>>();
        if lazy {
            self.pending.append(&mut it);
            self.pending.append(&mut it1);
        } else {
            self.left *= E::miller_loop(it.iter().chain(it1.iter()));
        }
        self.current_random *= self.random;
    }

    pub fn add_sources_with_laziness_choice(
        &mut self,
        a: E::G1Affine,
        b: E::G2Affine,
        c: E::G1Affine,
        d: E::G2Affine,
        lazy: bool,
    ) {
        let m = self.current_random.into_repr();
        let mut it = vec![
            (
                E::G1Prepared::from(a.mul(m).into_affine()),
                E::G2Prepared::from(b),
            ),
            (
                E::G1Prepared::from(-c.mul(m).into_affine()),
                E::G2Prepared::from(d),
            ),
        ];
        if lazy {
            self.pending.append(&mut it);
        } else {
            self.left *= E::miller_loop(it.iter());
        }
        self.current_random *= self.random;
    }

    pub fn add_prepared_sources_and_target_with_laziness_choice(
        &mut self,
        a: &[E::G1Affine],
        b: Vec<E::G2Prepared>,
        out: &E::Fqk,
        lazy: bool,
    ) {
        assert_eq!(a.len(), b.len());
        let m = self.current_random.into_repr();
        let mut it = cfg_iter!(a)
            .map(|a| E::G1Prepared::from(a.mul(m).into_affine()))
            .zip(cfg_into_iter!(b))
            .collect::<Vec<_>>();
        if lazy {
            self.pending.append(&mut it);
        } else {
            self.left *= E::miller_loop(it.iter());
        }
        self.right *= out.pow(m);
        self.current_random *= self.random;
    }

    pub fn verify(&self) -> bool {
        let mut p = E::Fqk::one();
        if self.pending.len() > 0 {
            p = E::miller_loop(self.pending.iter());
        }
        let left = self.left * p;
        E::final_exponentiation(&left).unwrap() == self.right
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
    use ark_ec::bls12::{G1Prepared, G2Prepared};
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use std::time::Instant;

    fn rev_vec<T: Clone>(v: &[T]) -> Vec<T> {
        let mut x = v.to_vec();
        x.reverse();
        x
    }

    #[test]
    fn test_pairing_randomize() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let n = 10;
        let mut t1 = 0;

        let a1 = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let b1 = (0..n)
            .map(|_| G2Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let a2 = (0..n + 5)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let b2 = (0..n + 5)
            .map(|_| G2Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let a3 = (0..n - 2)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let b3 = (0..n - 2)
            .map(|_| G2Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let start = Instant::now();
        let out1 = Bls12_381::product_of_pairings(
            &a1.iter()
                .zip(b1.iter())
                .map(|(a, b)| (G1Prepared::from(*a), G2Prepared::from(*b)))
                .collect::<Vec<_>>(),
        );
        t1 += start.elapsed().as_micros();

        let start = Instant::now();
        let out2 = Bls12_381::product_of_pairings(
            &a2.iter()
                .zip(b2.iter())
                .map(|(a, b)| (G1Prepared::from(*a), G2Prepared::from(*b)))
                .collect::<Vec<_>>(),
        );
        t1 += start.elapsed().as_micros();

        let start = Instant::now();
        let out3 = Bls12_381::product_of_pairings(
            &a3.iter()
                .zip(b3.iter())
                .map(|(a, b)| (G1Prepared::from(*a), G2Prepared::from(*b)))
                .collect::<Vec<_>>(),
        );
        t1 += start.elapsed().as_micros();

        for lazy in [true, false] {
            let start = Instant::now();
            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_multiple_sources_and_target(&a1, &b1, &out1);
            checker.add_multiple_sources_and_target(&a2, &b2, &out2);
            checker.add_multiple_sources_and_target(&a3, &b3, &out3);
            assert!(checker.verify());
            let l_str = if lazy { "lazy-" } else { "" };
            println!(
                "Time taken with {}checker {} us",
                l_str,
                start.elapsed().as_micros()
            );
        }
        println!("Time taken without checker {} us", t1);

        for lazy in [true, false] {
            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
            assert!(checker.verify());
        }

        for lazy in [true, false] {
            let start = Instant::now();
            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
            checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
            checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
            assert!(checker.verify());
            let l_str = if lazy { "lazy-" } else { "" };
            println!(
                "Time taken with {}checker {} us",
                l_str,
                start.elapsed().as_micros()
            );
        }

        for lazy in [true, false] {
            let start = Instant::now();
            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_multiple_sources_and_target(&a1, &b1, &out1);
            checker.add_multiple_sources_and_target(&a2, &b2, &out2);
            checker.add_multiple_sources_and_target(&a3, &b3, &out3);
            checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
            checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
            checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
            assert!(checker.verify());
            let l_str = if lazy { "lazy-" } else { "" };
            println!(
                "Time taken with {}checker {} us",
                l_str,
                start.elapsed().as_micros()
            );
        }

        for lazy in [true, false] {
            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_sources(a1[0].clone(), b1[0].clone(), a1[0].clone(), b1[0].clone());
            assert!(checker.verify());

            let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
            checker.add_sources(a1[0].clone(), b1[0].clone(), a1[0].clone(), b1[0].clone());
            checker.add_sources(a1[1].clone(), b1[1].clone(), a1[1].clone(), b1[1].clone());
            checker.add_sources(a1[2].clone(), b1[2].clone(), a1[2].clone(), b1[2].clone());
            assert!(checker.verify());
        }
    }
}
