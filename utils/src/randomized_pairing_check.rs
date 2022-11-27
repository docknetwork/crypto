use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_std::rand::Rng;
use ark_std::{cfg_into_iter, cfg_iter, UniformRand, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Debug, Copy, Clone)]
pub struct RandomizedPairingChecker<E: PairingEngine> {
    left: E::Fqk,
    right: E::Fqk,
    r: E::Fr,
    current_r: E::Fr,
}

#[derive(Debug, Clone)]
pub struct RandomizedPairingCheckerLazy<E: PairingEngine> {
    left: Vec<(E::G1Prepared, E::G2Prepared)>,
    right: E::Fqk,
    r: E::Fr,
    current_r: E::Fr,
}

impl<E> RandomizedPairingChecker<E>
    where
        E: PairingEngine,
{
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            left: E::Fqk::one(),
            right: E::Fqk::one(),
            r: E::Fr::rand(rng),
            current_r: E::Fr::one(),
        }
    }

    pub fn add_multiple_sources_and_target(&mut self, a: &[E::G1Affine], b: &[E::G2Affine], out: &E::Fqk) {
        assert_eq!(a.len(), b.len());

        let m = self.current_r.into_repr();
        let it = cfg_iter!(a)
            .zip(cfg_iter!(b))
            .map(|(a, b)| {
                (
                    E::G1Prepared::from(a.mul(m).into_affine()),
                    E::G2Prepared::from(*b),
                )
            })
            .collect::<Vec<_>>();
        self.left *= E::miller_loop(it.iter());
        self.right *= out.pow(m);
        self.current_r *= self.r;
    }

    pub fn add_multiple_sources(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        d: &[E::G2Affine],
    ) {
        assert_eq!(a.len(), b.len());
        assert_eq!(c.len(), d.len());
        let m = self.current_r.into_repr();
        let it = cfg_iter!(a)
            .zip(cfg_iter!(b))
            .map(|(a, b)| {
                (
                    E::G1Prepared::from(a.mul(m).into_affine()),
                    E::G2Prepared::from(*b),
                )
            })
            .collect::<Vec<_>>();
        let it1 = cfg_iter!(c)
            .zip(cfg_iter!(d))
            .map(|(c, d)| {
                (
                    E::G1Prepared::from(-c.mul(m).into_affine()),
                    E::G2Prepared::from(*d),
                )
            })
            .collect::<Vec<_>>();
        self.left *= E::miller_loop(it.iter().chain(it1.iter()));
        self.current_r *= self.r;
    }

    pub fn add_sources(
        &mut self,
        a: E::G1Affine,
        b: E::G2Affine,
        c: E::G1Affine,
        d: E::G2Affine,
    ) {
        let m = self.current_r.into_repr();
        let it = [(E::G1Prepared::from(a.mul(m).into_affine()), E::G2Prepared::from(b)), (E::G1Prepared::from(-c.mul(m).into_affine()), E::G2Prepared::from(d))];
        self.left *= E::miller_loop(it.iter());
        self.current_r *= self.r;
    }

    pub fn add_prepared_sources_and_target(
        &mut self,
        a: &[E::G1Affine],
        b: Vec<E::G2Prepared>,
        out: &E::Fqk,
    ) {
        assert_eq!(a.len(), b.len());
        let m = self.current_r.into_repr();
        let it = cfg_iter!(a)
            .map(|a| E::G1Prepared::from(a.mul(m).into_affine()))
            .zip(cfg_into_iter!(b))
            .collect::<Vec<_>>();
        self.left *= E::miller_loop(it.iter());
        self.right *= out.pow(m);
        self.current_r *= self.r;
    }

    pub fn verify(&self) -> bool {
        E::final_exponentiation(&self.left).unwrap() == self.right
    }
}

impl<E> RandomizedPairingCheckerLazy<E>
    where
        E: PairingEngine,
{
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            left: vec![],
            right: E::Fqk::one(),
            r: E::Fr::rand(rng),
            current_r: E::Fr::one(),
        }
    }

    pub fn add_multiple_sources_and_target(&mut self, a: &[E::G1Affine], b: &[E::G2Affine], out: &E::Fqk) {
        assert_eq!(a.len(), b.len());

        let m = self.current_r.into_repr();
        let mut it = cfg_iter!(a)
            .zip(cfg_iter!(b))
            .map(|(a, b)| {
                (
                    E::G1Prepared::from(a.mul(m).into_affine()),
                    E::G2Prepared::from(*b),
                )
            })
            .collect::<Vec<_>>();
        self.left.append(&mut it);
        self.right *= out.pow(m);
        self.current_r *= self.r;
    }

    pub fn add_multiple_sources(
        &mut self,
        a: &[E::G1Affine],
        b: &[E::G2Affine],
        c: &[E::G1Affine],
        d: &[E::G2Affine],
    ) {
        assert_eq!(a.len(), b.len());
        assert_eq!(c.len(), d.len());
        let m = self.current_r.into_repr();
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
        self.left.append(&mut it);
        self.left.append(&mut it1);
        self.current_r *= self.r;
    }

    pub fn add_sources(
        &mut self,
        a: E::G1Affine,
        b: E::G2Affine,
        c: E::G1Affine,
        d: E::G2Affine,
    ) {
        let m = self.current_r.into_repr();
        self.left.push((E::G1Prepared::from(a.mul(m).into_affine()), E::G2Prepared::from(b)));
        self.left.push((E::G1Prepared::from(-c.mul(m).into_affine()), E::G2Prepared::from(d)));
        self.current_r *= self.r;
    }

    pub fn add_prepared_sources_and_target(
        &mut self,
        a: &[E::G1Affine],
        b: Vec<E::G2Prepared>,
        out: &E::Fqk,
    ) {
        assert_eq!(a.len(), b.len());
        let m = self.current_r.into_repr();
        let mut it = cfg_iter!(a)
            .map(|a| E::G1Prepared::from(a.mul(m).into_affine()))
            .zip(cfg_into_iter!(b))
            .collect::<Vec<_>>();
        self.left.append(&mut it);
        self.right *= out.pow(m);
        self.current_r *= self.r;
    }

    pub fn verify(&self) -> bool {
        let left = E::miller_loop(self.left.iter());
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
    use ark_std::{rand::Rng, UniformRand};
    use std::time::{Duration, Instant};

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

        let start = Instant::now();
        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources_and_target(&a1, &b1, &out1);
        checker.add_multiple_sources_and_target(&a2, &b2, &out2);
        checker.add_multiple_sources_and_target(&a3, &b3, &out3);
        assert!(checker.verify());
        println!("Time taken with checker {} us", start.elapsed().as_micros());
        println!("Time taken without checker {} us", t1);

        let start = Instant::now();
        let mut checker = RandomizedPairingCheckerLazy::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources_and_target(&a1, &b1, &out1);
        checker.add_multiple_sources_and_target(&a2, &b2, &out2);
        checker.add_multiple_sources_and_target(&a3, &b3, &out3);
        assert!(checker.verify());
        println!("Time taken with lazy checker {} us", start.elapsed().as_micros());

        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
        assert!(checker.verify());

        let start = Instant::now();
        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
        checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
        checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
        assert!(checker.verify());
        println!("Time taken with checker {} us", start.elapsed().as_micros());

        let start = Instant::now();
        let mut checker = RandomizedPairingCheckerLazy::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
        checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
        checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
        assert!(checker.verify());
        println!("Time taken with lazy checker {} us", start.elapsed().as_micros());

        let start = Instant::now();
        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources_and_target(&a1, &b1, &out1);
        checker.add_multiple_sources_and_target(&a2, &b2, &out2);
        checker.add_multiple_sources_and_target(&a3, &b3, &out3);
        checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
        checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
        checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
        assert!(checker.verify());
        println!("Time taken with checker {} us", start.elapsed().as_micros());

        let start = Instant::now();
        let mut checker = RandomizedPairingCheckerLazy::<Bls12_381>::new(&mut rng);
        checker.add_multiple_sources_and_target(&a1, &b1, &out1);
        checker.add_multiple_sources_and_target(&a2, &b2, &out2);
        checker.add_multiple_sources_and_target(&a3, &b3, &out3);
        checker.add_multiple_sources(&a1, &b1, &rev_vec(&a1), &rev_vec(&b1));
        checker.add_multiple_sources(&a2, &b2, &rev_vec(&a2), &rev_vec(&b2));
        checker.add_multiple_sources(&a3, &b3, &rev_vec(&a3), &rev_vec(&b3));
        assert!(checker.verify());
        println!("Time taken with lazy checker {} us", start.elapsed().as_micros());

        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_sources(a1[0].clone(), b1[0].clone(), a1[0].clone(), b1[0].clone());
        assert!(checker.verify());

        let mut checker = RandomizedPairingChecker::<Bls12_381>::new(&mut rng);
        checker.add_sources(a1[0].clone(), b1[0].clone(), a1[0].clone(), b1[0].clone());
        checker.add_sources(a1[1].clone(), b1[1].clone(), a1[1].clone(), b1[1].clone());
        checker.add_sources(a1[2].clone(), b1[2].clone(), a1[2].clone(), b1[2].clone());
        assert!(checker.verify());
    }
}
