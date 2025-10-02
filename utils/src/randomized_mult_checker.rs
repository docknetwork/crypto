use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{One, Zero};
use ark_std::{
    iter::{IntoIterator, Iterator},
    rand::Rng,
    vec::Vec,
    UniformRand,
    collections::BTreeMap,
};

/// Represents a scalar multiplication check of the form `G1 * a1 + G2 * a2 + G3 * a3 + ... = T`.
/// Several checks can be added of forms either `G1 * a1 = T1` or `G1 * a1 + H1 * b1 = T2` or `G1 * a1 + H1 * b1 + J1 * c1 = T3`
/// These checks can be aggregated together using random linear combination. The efficiency comes from converting all these
/// scalar multiplications in a single multi-scalar multiplication.
/// For each check, multiply the check by a power of a random element created during initialization.
/// eg. for these 4 checks `G1 * a1 = T1, G1 * a2 + H1 * b2 = T2` and `G1 * a3 + H2 * b3 + J1 * c3 = T3`, `G1 * a4 + H2 * b4 + J2 * c4 = T4`,
/// a single check is created as `G1 * a1 - T1 + G1 * a2 * r + H1 * b2 * r - T2 * r + G1 * a3 * r^2 + H2 * b3 * r^2 + J1 * c3 * r^2 - T3 * r^2 + G1 * a4 * r^3 + H2 * b4 * r^3 + J2 * c4 * r^3 - T4 * r^3 = 0`
/// where `r` is a random value and so are`r^2`, `r^3`
/// The single check above is simplified by combining terms of `G1`, `H1`, etc to reduce the size of the multi-scalar multiplication
#[derive(Debug, Clone)]
pub struct RandomizedMultChecker<G: AffineRepr> {
    /// Verification will expect the multi-scalar multiplication of key-value pairs to be one.
    /// x-coordinate -> (scalar, point)
    // This trick is taken from halo2 code (MSM) but keeping the point rather than y coordinate in value since there is no way to convert back from x, y coordinates for AffineRepr
    args: BTreeMap<G::BaseField, (G::ScalarField, G)>,
    /// The random value chosen during creation
    random: G::ScalarField,
    /// The random value to be used for current check. After each check, set `current_random = current_random * random`
    current_random: G::ScalarField,
}

impl<G: AffineRepr> RandomizedMultChecker<G> {
    pub fn new(random: G::ScalarField) -> Self {
        Self {
            args: BTreeMap::new(),
            random,
            current_random: G::ScalarField::one(),
        }
    }

    pub fn new_using_rng<R: Rng>(rng: &mut R) -> Self {
        Self::new(G::ScalarField::rand(rng))
    }

    /// Add a check of the form `p * s = t`. Converts it to `p * s * r - t * r = 0` where `r` is the current randomness.
    pub fn add_1(&mut self, p: G, s: &G::ScalarField, t: G) {
        self.add(p, self.current_random * s);
        self.add(t, -self.current_random);
        self.current_random *= self.random;
    }

    /// Add a check of the form `p1 * s1 + p2 * s2 = t`. Converts it to `p1 * s1 * r + p2 * s2 * r - t * r = 0` where `r` is the current randomness.
    pub fn add_2(&mut self, p1: G, s1: &G::ScalarField, p2: G, s2: &G::ScalarField, t: G) {
        self.add(p1, self.current_random * s1);
        self.add(p2, self.current_random * s2);
        self.add(t, -self.current_random);
        self.current_random *= self.random;
    }

    /// Add a check of the form `p1 * s1 + p2 * s2 + p3 * s3 = t`. Converts it to `p1 * s1 * r + p2 * s2 * r + p3 * s3 * r - t * r = 0` where `r` is the current randomness.
    pub fn add_3(
        &mut self,
        p1: G,
        s1: &G::ScalarField,
        p2: G,
        s2: &G::ScalarField,
        p3: G,
        s3: &G::ScalarField,
        t: G,
    ) {
        self.add(p1, self.current_random * s1);
        self.add(p2, self.current_random * s2);
        self.add(p3, self.current_random * s3);
        self.add(t, -self.current_random);
        self.current_random *= self.random;
    }

    /// Add a check of the form `<a, b> = t`. Expects `a` and `b` to be of the same length
    pub fn add_many<'a>(
        &mut self,
        a: impl IntoIterator<Item = G>,
        b: impl IntoIterator<Item = &'a G::ScalarField>,
        t: G,
    ) {
        for (a_i, b_i) in a.into_iter().zip(b) {
            self.add(a_i, self.current_random * b_i);
        }
        self.add(t, -self.current_random);
        self.current_random *= self.random;
    }

    /// Combine all the checks into a multi-scalar multiplication and return true if the result is 0.
    pub fn verify(&self) -> bool {
        let mut points = Vec::with_capacity(self.len());
        let mut scalars = Vec::with_capacity(self.len());
        for (_, (s, point)) in self.args.iter() {
            points.push(*point);
            scalars.push(*s);
        }
        G::Group::msm_unchecked(&points, &scalars).is_zero()
    }

    pub fn len(&self) -> usize {
        self.args.len()
    }

    fn add(&mut self, p: G, s: G::ScalarField) {
        if let Some(x) = p.x() {
            self.args
                .entry(*x)
                .and_modify(|(old_scalar, point)| {
                    // If the point or its negative already exists, update the scalar accordingly
                    if *point == p {
                        *old_scalar += s;
                    } else {
                        *old_scalar -= s;
                        debug_assert_eq!(point.into_group(), -p.into_group());
                    }
                })
                .or_insert((s, p));
        } else {
            // If p is a point at infinity, then it doesn't impact the result
            debug_assert!(p.is_zero());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ec::CurveGroup;
    use ark_std::{rand::rngs::OsRng, UniformRand};
    use std::time::Instant;

    #[test]
    fn basic() {
        let mut rng = OsRng::default();
        let g1 = G1Affine::rand(&mut rng);
        let g2 = G1Affine::rand(&mut rng);
        let g3 = G1Affine::rand(&mut rng);
        let h1 = G1Affine::rand(&mut rng);
        let h2 = G1Affine::rand(&mut rng);
        let h3 = G1Affine::rand(&mut rng);

        let a1 = Fr::rand(&mut rng);
        let a2 = Fr::rand(&mut rng);
        let a3 = Fr::rand(&mut rng);
        let a4 = Fr::rand(&mut rng);
        let a5 = Fr::rand(&mut rng);
        let a6 = Fr::rand(&mut rng);

        let c1 = (g1 * a1).into_affine();
        let c2 = (g1 * a2).into_affine();
        let c3 = (g1 * a3).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g1, &a2, c2);
        checker.add_1(g1, &a3, c3);
        assert!(checker.verify());

        // Checking if g1 * a2 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g1, &a2, c2); // this is invalid
        checker.add_1(g1, &a2, c3);
        assert!(!checker.verify());

        let c1 = (g1 * a1).into_affine();
        let c2 = (g2 * a2).into_affine();
        let c3 = (g3 * a3).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g2, &a2, c2);
        checker.add_1(g3, &a3, c3);
        assert!(checker.verify());

        // Checking if g2 * a3 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g2, &a2, c2); // this is invalid
        checker.add_1(g2, &a3, c3);
        assert!(!checker.verify());

        let c1 = (g1 * a1 + h1 * a4).into_affine();
        let c2 = (g1 * a2 + h1 * a5).into_affine();
        let c3 = (g1 * a3 + h1 * a6).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g1, &a2, h1, &a5, c2);
        checker.add_2(g1, &a3, h1, &a6, c3);
        assert!(checker.verify());

        // Checking if g1 * a3 + h1 * a3 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g1, &a2, h1, &a5, c2);
        checker.add_2(g1, &a3, h1, &a3, c3); // this is invalid
        assert!(!checker.verify());

        let c1 = (g1 * a1 + h1 * a4).into_affine();
        let c2 = (g2 * a2 + h2 * a5).into_affine();
        let c3 = (g3 * a3 + h3 * a6).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g2, &a2, h2, &a5, c2);
        checker.add_2(g3, &a3, h3, &a6, c3);
        assert!(checker.verify());

        let c1 = (g1 * a1 + g2 * a2 + g3 * a3).into_affine();
        let c2 = (h1 * a4 + h2 * a5 + h3 * a6).into_affine();
        let c3 = (g2 * a3 + h1 * a1 + h2 * a2).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_3(g1, &a1, g2, &a2, g3, &a3, c1);
        checker.add_3(h1, &a4, h2, &a5, h3, &a6, c2);
        checker.add_3(g2, &a3, h1, &a1, h2, &a2, c3);
        assert!(checker.verify());

        // Checking if g2 * a3 + h1 * a1 + h2 * a1 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_3(g1, &a1, g2, &a2, g3, &a3, c1);
        checker.add_3(h1, &a4, h2, &a5, h3, &a6, c2);
        checker.add_3(g2, &a3, h1, &a1, h2, &a1, c3); // this is invalid
        assert!(!checker.verify());

        let c1 = (g1 * a1).into_affine();
        let c2 = (g2 * a2).into_affine();
        let c3 = (g1 * a1 + h1 * a4).into_affine();
        let c4 = (g1 * a2 + h1 * a5).into_affine();
        let c5 = (g1 * a3 + h1 * a6).into_affine();
        let c6 = (g1 * a1 + h1 * a4).into_affine();
        let c7 = (g2 * a2 + h2 * a5).into_affine();
        let c8 = (g3 * a3 + h3 * a6).into_affine();
        let c9 = (g1 * a1 + g2 * a2 + g3 * a3).into_affine();
        let c10 = (h1 * a4 + h2 * a5 + h3 * a6).into_affine();
        let c11 = (h1 * a2 + h2 * a3 + h3 * a4).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g2, &a2, c2);
        checker.add_2(g1, &a1, h1, &a4, c3);
        checker.add_2(g1, &a2, h1, &a5, c4);
        checker.add_2(g1, &a3, h1, &a6, c5);
        checker.add_2(g1, &a1, h1, &a4, c6);
        checker.add_2(g2, &a2, h2, &a5, c7);
        checker.add_2(g3, &a3, h3, &a6, c8);
        checker.add_3(g1, &a1, g2, &a2, g3, &a3, c9);
        checker.add_3(h1, &a4, h2, &a5, h3, &a6, c10);
        checker.add_3(h1, &a2, h2, &a3, h3, &a4, c11);
        assert!(checker.verify());

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_many([g3, h3], [&a3, &a6], c8);
        checker.add_many([g1, g2, g3], [&a1, &a2, &a3], c9);
        assert!(checker.verify());

        let minus_g1 = -g1;
        let minus_g2 = -g2;
        let c1 = (g1 * a1).into_affine();
        let c2 = (minus_g1 * a2).into_affine();
        let c3 = (g2 * a3).into_affine();
        let c4 = (minus_g2 * a4).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(minus_g1, &a2, c2);
        checker.add_1(g2, &a3, c3);
        checker.add_1(minus_g2, &a4, c4);
        assert!(checker.verify());
    }

    #[test]
    fn timing_comparison() {
        let mut rng = OsRng::default();

        for i in [40, 60, 80, 100] {
            let g = (0..i).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
            let h = (0..i).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
            let k = (0..i).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
            let a = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let b = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let c = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let r = (0..i)
                .map(|j| (g[0] * a[j] + h[0] * b[j]).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            for j in 0..i {
                assert_eq!((g[0] * a[j] + h[0] * b[j]).into_affine(), r[j]);
            }
            println!("For {} items, naive check took {:?}", i, start.elapsed());

            let start = Instant::now();
            let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
            for j in 0..i {
                checker.add_2(g[0], &a[j], h[0], &b[j], r[j]);
            }
            assert!(checker.verify());
            println!(
                "For {} items, RandomizedMultChecker took {:?}",
                i,
                start.elapsed()
            );

            let r = (0..i)
                .map(|j| (g[j] * a[j] + h[j] * b[j]).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            for j in 0..i {
                assert_eq!((g[j] * a[j] + h[j] * b[j]).into_affine(), r[j]);
            }
            println!("For {} items, naive check took {:?}", i, start.elapsed());

            let start = Instant::now();
            let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
            for j in 0..i {
                checker.add_2(g[j], &a[j], h[j], &b[j], r[j]);
            }
            assert!(checker.verify());
            println!(
                "For {} items, RandomizedMultChecker took {:?}",
                i,
                start.elapsed()
            );

            let r = (0..i)
                .map(|j| (g[0] * a[j] + h[0] * b[j] + k[0] * c[j]).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            for j in 0..i {
                assert_eq!(
                    (g[0] * a[j] + h[0] * b[j] + k[0] * c[j]).into_affine(),
                    r[j]
                );
            }
            println!("For {} items, naive check took {:?}", i, start.elapsed());

            let start = Instant::now();
            let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
            for j in 0..i {
                checker.add_3(g[0], &a[j], h[0], &b[j], k[0], &c[j], r[j]);
            }
            assert!(checker.verify());
            println!(
                "For {} items, RandomizedMultChecker took {:?}",
                i,
                start.elapsed()
            );

            let r = (0..i)
                .map(|j| (g[j] * a[j] + h[j] * b[j] + k[j] * c[j]).into_affine())
                .collect::<Vec<_>>();

            let start = Instant::now();
            for j in 0..i {
                assert_eq!(
                    (g[j] * a[j] + h[j] * b[j] + k[j] * c[j]).into_affine(),
                    r[j]
                );
            }
            println!("For {} items, naive check took {:?}", i, start.elapsed());

            let start = Instant::now();
            let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
            for j in 0..i {
                checker.add_3(g[j], &a[j], h[j], &b[j], k[j], &c[j], r[j]);
            }
            assert!(checker.verify());
            println!(
                "For {} items, RandomizedMultChecker took {:?}",
                i,
                start.elapsed()
            );
        }
    }
}
