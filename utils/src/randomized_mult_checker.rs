use ahash::RandomState;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{One, Zero};
use ark_std::{
    iter::{IntoIterator, Iterator},
    rand::Rng,
    vec::Vec,
    UniformRand,
};
use hashbrown::{hash_map::Entry, HashMap};

use crate::error::UtilsError;

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
    /// x-coordinate -> (scalar, point, y-coordinate)
    // This trick is taken from halo2 code (MSM) but keeping both the point and y coordinate in value since there is no way to convert back from x, y coordinates for AffineRepr
    pub args: HashMap<G::BaseField, (G::ScalarField, G, G::BaseField), RandomState>,
    /// The random value chosen during creation
    pub random: G::ScalarField,
    /// The random value to be used for current check. After each check, set `current_random = current_random * random`
    pub current_random: G::ScalarField,
    /// Flag to detect forgotten `verify()`.
    verified: bool,
    /// Flag to detect a canceled checker.
    cancelled: bool,
}

impl<G: AffineRepr> RandomizedMultChecker<G> {
    pub fn new(random: G::ScalarField) -> Self {
        Self {
            args: HashMap::with_hasher(RandomState::new()),
            random,
            current_random: G::ScalarField::one(),
            verified: false,
            cancelled: false,
        }
    }

    pub fn new_using_rng<R: Rng>(rng: &mut R) -> Self {
        Self::new(G::ScalarField::rand(rng))
    }

    /// Add a check of the form `p * s = t`. Converts it to `p * s * r - t * r = 0` where `r` is the current randomness.
    pub fn add_1(&mut self, p: G, s: &G::ScalarField, t: G) {
        self.add(p, self.current_random * s);
        self.add(t, -self.current_random);
        self.update_random();
    }

    /// Add a check of the form `p1 * s1 + p2 * s2 = t`. Converts it to `p1 * s1 * r + p2 * s2 * r - t * r = 0` where `r` is the current randomness.
    pub fn add_2(&mut self, p1: G, s1: &G::ScalarField, p2: G, s2: &G::ScalarField, t: G) {
        self.add(p1, self.current_random * s1);
        self.add(p2, self.current_random * s2);
        self.add(t, -self.current_random);
        self.update_random();
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
        self.update_random();
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
        self.update_random();
    }

    /// Combine all the checks into a multi-scalar multiplication and return `Ok` if the result is 0.
    pub fn verify(mut self) -> Result<(), UtilsError> {
        self.verified = true;
        let (points, scalars) = self.points_and_scalars_for_msm();
        if G::Group::msm_unchecked(&points, &scalars).is_zero() {
            Ok(())
        } else {
            Err(UtilsError::MultCheckFailed)
        }
    }

    /// Cancel the checker. This is useful when the verifier wants to cancel the checker if it is not needed anymore,
    /// say a different check failed which fails verification anyway
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn len(&self) -> usize {
        self.args.len()
    }

    pub fn points_and_scalars_for_msm(&self) -> (Vec<G>, Vec<G::ScalarField>) {
        let mut points = Vec::with_capacity(self.len());
        let mut scalars = Vec::with_capacity(self.len());
        for (_, (s, point, _)) in self.args.iter() {
            points.push(*point);
            scalars.push(*s);
        }
        (points, scalars)
    }

    pub fn update_random(&mut self) {
        self.current_random *= self.random;
    }

    #[inline(always)]
    pub fn add(&mut self, p: G, s: G::ScalarField) {
        if p.is_zero() {
            return;
        }

        // unwrap is fine as point is not at infinity
        let (p_x, p_y) = p.xy().unwrap();

        match self.args.entry(*p_x) {
            Entry::Occupied(mut entry) => {
                let (old_scalar, point, y) = entry.get_mut();
                if y == p_y {
                    *old_scalar += s;
                } else {
                    *old_scalar -= s;
                    debug_assert_eq!(point.into_group(), -p.into_group());
                }
            }
            Entry::Vacant(entry) => {
                entry.insert((s, p, *p_y));
            }
        }
    }
}

impl<G: AffineRepr> Drop for RandomizedMultChecker<G> {
    fn drop(&mut self) {
        if !self.verified && !self.cancelled && !self.args.is_empty() {
            panic!(
                "RandomizedMultChecker was dropped without calling `verify()`. \
                This means all accumulated scalar multiplications were never performed. \
                This indicates a bug in caller's verifier code"
            );
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
        checker.verify().unwrap();

        // Checking if g1 * a2 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g1, &a2, c2); // this is invalid
        checker.add_1(g1, &a2, c3);
        assert!(checker.verify().is_err());

        let c1 = (g1 * a1).into_affine();
        let c2 = (g2 * a2).into_affine();
        let c3 = (g3 * a3).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g2, &a2, c2);
        checker.add_1(g3, &a3, c3);
        checker.verify().unwrap();

        // Checking if g2 * a3 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_1(g1, &a1, c1);
        checker.add_1(g2, &a2, c2); // this is invalid
        checker.add_1(g2, &a3, c3);
        assert!(checker.verify().is_err());

        let c1 = (g1 * a1 + h1 * a4).into_affine();
        let c2 = (g1 * a2 + h1 * a5).into_affine();
        let c3 = (g1 * a3 + h1 * a6).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g1, &a2, h1, &a5, c2);
        checker.add_2(g1, &a3, h1, &a6, c3);
        checker.verify().unwrap();

        // Checking if g1 * a3 + h1 * a3 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g1, &a2, h1, &a5, c2);
        checker.add_2(g1, &a3, h1, &a3, c3); // this is invalid
        assert!(checker.verify().is_err());

        let c1 = (g1 * a1 + h1 * a4).into_affine();
        let c2 = (g2 * a2 + h2 * a5).into_affine();
        let c3 = (g3 * a3 + h3 * a6).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_2(g1, &a1, h1, &a4, c1);
        checker.add_2(g2, &a2, h2, &a5, c2);
        checker.add_2(g3, &a3, h3, &a6, c3);
        checker.verify().unwrap();

        let c1 = (g1 * a1 + g2 * a2 + g3 * a3).into_affine();
        let c2 = (h1 * a4 + h2 * a5 + h3 * a6).into_affine();
        let c3 = (g2 * a3 + h1 * a1 + h2 * a2).into_affine();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_3(g1, &a1, g2, &a2, g3, &a3, c1);
        checker.add_3(h1, &a4, h2, &a5, h3, &a6, c2);
        checker.add_3(g2, &a3, h1, &a1, h2, &a2, c3);
        checker.verify().unwrap();

        // Checking if g2 * a3 + h1 * a1 + h2 * a1 == c3 fails
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_3(g1, &a1, g2, &a2, g3, &a3, c1);
        checker.add_3(h1, &a4, h2, &a5, h3, &a6, c2);
        checker.add_3(g2, &a3, h1, &a1, h2, &a1, c3); // this is invalid
        assert!(checker.verify().is_err());

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
        checker.verify().unwrap();

        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        checker.add_many([g3, h3], [&a3, &a6], c8);
        checker.add_many([g1, g2, g3], [&a1, &a2, &a3], c9);
        checker.verify().unwrap();

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
        checker.verify().unwrap();
    }

    #[test]
    fn add_function() {
        let mut rng = OsRng::default();
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);

        // Adding the same point twice should result in 1 entry with combined scalar
        let point1 = G1Affine::rand(&mut rng);
        let scalar1 = Fr::from(5u64);
        let scalar2 = Fr::from(3u64);

        checker.add(point1, scalar1);
        assert_eq!(
            checker.len(),
            1,
            "Should have 1 entry after adding first point"
        );

        // Check the entry
        let (p_x, p_y) = point1.xy().unwrap();
        let entry = checker.args.get(p_x).unwrap();
        assert_eq!(entry.0, scalar1, "Scalar should match the first addition");
        assert_eq!(entry.1, point1, "Point should match");
        assert_eq!(entry.2, *p_y, "Y-coordinate should match");

        // Add the same point again with different scalar
        checker.add(point1, scalar2);
        assert_eq!(
            checker.len(),
            1,
            "Should still have 1 entry after adding same point twice"
        );

        let entry = checker.args.get(p_x).unwrap();
        assert_eq!(
            entry.0,
            scalar1 + scalar2,
            "Scalar should be sum of both additions"
        );
        assert_eq!(entry.1, point1, "Point should still match");
        assert_eq!(entry.2, *p_y, "Y-coordinate should still match");
        checker.cancel();

        // Adding a point and its negative should result in 1 entry with scalar difference
        let mut checker2 = RandomizedMultChecker::new_using_rng(&mut rng);
        let point2 = G1Affine::rand(&mut rng);
        let neg_point2 = -point2;
        let scalar3 = Fr::from(7u64);
        let scalar4 = Fr::from(2u64);

        checker2.add(point2, scalar3);
        assert_eq!(checker2.len(), 1, "Should have 1 entry after adding point");

        let (p2_x, p2_y) = point2.xy().unwrap();

        // Add the negative point
        checker2.add(neg_point2, scalar4);
        assert_eq!(
            checker2.len(),
            1,
            "Should still have 1 entry after adding negative point"
        );

        let entry = checker2.args.get(p2_x).unwrap();
        assert_eq!(
            entry.0,
            scalar3 - scalar4,
            "Scalar should be difference (positive - negative)"
        );
        // The point stored should still be the original point
        assert_eq!(entry.1, point2, "Point should still be the original point");
        assert_eq!(entry.2, *p2_y, "Y-coordinate should still match original");
        checker2.cancel();

        // Adding point at infinity should not update args
        let mut checker3 = RandomizedMultChecker::new_using_rng(&mut rng);
        let infinity = G1Affine::zero();
        let scalar5 = Fr::from(10u64);

        assert_eq!(checker3.len(), 0, "Should start with 0 entries");

        checker3.add(infinity, scalar5);
        assert_eq!(
            checker3.len(),
            0,
            "Should still have 0 entries after adding infinity"
        );
        assert!(checker3.args.is_empty(), "Args map should remain empty");

        // Add a regular point first, then infinity - should not affect the count
        let point3 = G1Affine::rand(&mut rng);
        checker3.add(point3, scalar5);
        assert_eq!(
            checker3.len(),
            1,
            "Should have 1 entry after adding regular point"
        );

        checker3.add(infinity, scalar5);
        assert_eq!(
            checker3.len(),
            1,
            "Should still have 1 entry after adding infinity"
        );

        // Verify the regular point entry is unchanged
        let (p3_x, p3_y) = point3.xy().unwrap();
        let entry = checker3.args.get(p3_x).unwrap();
        assert_eq!(
            entry.0, scalar5,
            "Regular point's scalar should be unchanged"
        );
        assert_eq!(entry.1, point3, "Regular point should be unchanged");
        assert_eq!(
            entry.2, *p3_y,
            "Regular point's y-coordinate should be unchanged"
        );
        checker3.cancel();
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
            checker.verify().unwrap();
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
            checker.verify().unwrap();
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
            checker.verify().unwrap();
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
            checker.verify().unwrap();
            println!(
                "For {} items, RandomizedMultChecker took {:?}",
                i,
                start.elapsed()
            );
        }
    }
}
