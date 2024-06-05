/// Concatenates supplied slices into one continuous vector.
#[macro_export]
macro_rules! concat_slices {
    ($($slice: expr),+) => {
        [$(&$slice[..]),+].concat()
    }
}

/// Concatenates provided byte slices and hashes result to a point on the curve. Returns as Affine coordinates.
#[macro_export]
macro_rules! affine_group_element_from_byte_slices {
    ($($arg: expr),+) => {
        $crate::hashing_utils::affine_group_elem_from_try_and_incr::<_, D>(&$crate::concat_slices!($($arg),+))
    };
}

/// Implements `Deref`/`DeferMut` traits for the supplied wrapper and type.
#[macro_export]
macro_rules! impl_deref {
    ($wrapper: ident$(<$($gen: ident: $($bound: path),+),*>)?($inner: ty)) => {
        impl$(<$($gen: $($bound)++),+>)* core::ops::Deref for $wrapper$(<$($gen),+>)* {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl$(<$($gen: $($bound)++),+>)* core::ops::DerefMut for $wrapper$(<$($gen),+>)* {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

/// Calculates the product of pairing for supplied pairs.
/// ```compile_fail
/// multi_pairing! {
///     a, c,
///     b, d
/// }
/// ```
/// Will be transformed to:
/// ```compile_fail
/// E::multi_pairing([a, b], [c, d])
/// ```
#[macro_export]
macro_rules! multi_pairing {
    ($($g1: expr, $g2: expr);+) => {
        $crate::multi_pairing! { using E: $($g1, $g2);+ }
    };
    (using $pairing_engine: path: $($g1: expr, $g2: expr);+) => {
        <$pairing_engine>::multi_pairing(
            [
                $($g1.into()),+
            ],
            [
                $($g2.into()),+
            ]
        )
    }
}

/// Flattened `rayon::join(|| expr1, || rayon::join(|| expr2, || ...))`
#[cfg(feature = "parallel")]
#[macro_export]
macro_rules! join {
    (@ $a: expr) => { $a };
    (@ $a: expr, $b: expr) => {
        rayon::join(|| $a, || $b)
    };
    (@ $a: expr, $b: expr, $($c: expr),+) => {{
        join!(@ $a, join!(@ $b, $($c),+))
    }};
    ($($e: expr),+) => {{
        $crate::unnest_tuple!(
            $($e),+
            =>
            join!(@ $($e),+)
        )
    }}
}

/// `(expr1, expr2, expr3...)`
#[cfg(not(feature = "parallel"))]
#[macro_export]
macro_rules! join {
    ($($e: expr),+) => {
        ($($e),+)
    };
}

/// `(a, (b, c)) => (a, b, c)`
#[macro_export]
macro_rules! unnest_tuple {
    ($a: expr => $v: expr) => {{
        $v
    }};
    ($a: expr, $b: expr => $v: expr) => {{
        let (_a, _b) = $v;

        (_a, _b)
    }};
    ($a: expr, $b: expr, $c: expr => $v: expr) => {{
        let (_a, (_b, _c)) = $v;

        (_a, _b, _c)
    }};
    ($a: expr, $b: expr, $c: expr, $d: expr => $v: expr) => {{
        let (_a, (_b, (_c, _d))) = $v;

        (_a, _b, _c, _d)
    }};
    ($a: expr, $b: expr, $c: expr, $d: expr, $e: expr => $v: expr) => {{
        let (_a, (_b, (_c, (_d, _e)))) = $v;

        (_a, _b, _c, _d, _e)
    }};
    ($a: expr, $b: expr, $c: expr, $d: expr, $e: expr, $f: expr => $v: expr) => {{
        let (_a, (_b, (_c, (_d, (_e, _f))))) = $v;

        (_a, _b, _c, _d, _e, _f)
    }};
}

/// `impl Iterator` or `impl ParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(feature = "parallel")]
macro_rules! impl_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl rayon::prelude::ParallelIterator<Item = $item> $($tt)* }
}

/// `impl Iterator` or `impl ParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(not(feature = "parallel"))]
macro_rules! impl_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl core::iter::Iterator<Item = $item> $($tt)* }
}

/// `impl IntoIterator` or `impl IntoParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(feature = "parallel")]
macro_rules! impl_into_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl rayon::prelude::IntoParallelIterator<Item = $item> $($tt)* }
}

/// `impl IntoIterator` or `impl IntoParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(not(feature = "parallel"))]
macro_rules! impl_into_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl core::iter::IntoIterator<Item = $item> $($tt)* }
}

/// `impl DoubleEndedIterator + ExactSizeIterator` or `impl IndexedParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(feature = "parallel")]
macro_rules! impl_indexed_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl rayon::prelude::IndexedParallelIterator<Item = $item> $($tt)* }
}

/// `impl DoubleEndedIterator + ExactSizeIterator` or `impl IndexedParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(not(feature = "parallel"))]
macro_rules! impl_indexed_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl $crate::aliases::DoubleEndedExactSizeIterator<Item = $item> $($tt)* }
}

/// `impl IntoIterator` where `IntoIter: DoubleEndedIterator + ExactSizeIterator`  or `impl IntoParallelIterator` where `Iter: IndexedParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(feature = "parallel")]
macro_rules! impl_into_indexed_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl rayon::prelude::IntoParallelIterator<Item = $item, Iter = impl rayon::prelude::IndexedParallelIterator<Item = $item> $($tt)*> $($tt)* }
}

/// `impl IntoIterator` where `IntoIter: DoubleEndedIterator + ExactSizeIterator`  or `impl IntoParallelIterator` where `Iter: IndexedParallelIterator` depending on the `parallel` feature.
#[macro_export]
#[cfg(not(feature = "parallel"))]
macro_rules! impl_into_indexed_iter {
    (<Item = $item: ty> $($tt: tt)*) => { impl core::iter::IntoIterator<Item = $item, IntoIter = impl $crate::aliases::DoubleEndedExactSizeIterator<Item = $item> $($tt)*> $($tt)* }
}

/// Converts given vectors to `OwnedPairs`, panics in case of error.
#[macro_export]
macro_rules! owned_pairs {
    ($left: expr, $right: expr) => {
        $crate::try_owned_pairs!($left, $right).unwrap_or_else(|(left, right)| {
            panic!("Lengths are not equal: left = {}, right = {}", left, right)
        })
    };
}

/// Attempts to build `OwnedPairs` from the given vectors, returning `(left length, right length)` in case of error.
#[macro_export]
macro_rules! try_owned_pairs {
    ($left: expr, $right: expr) => {
        $crate::owned_pairs::OwnedPairs::try_from(($left, $right))
    };
}

/// Builds `Pairs` from the given slices, panics in case of error.
#[macro_export]
macro_rules! pairs {
    ($left: expr, $right: expr) => {
        $crate::try_pairs!($left, $right).unwrap_or_else(|(left, right)| {
            panic!("Lengths are not equal: left = {}, right = {}", left, right)
        })
    };
}

/// Attempts to convert given slices to `Pairs`, returning `(left length, right length)` in case of error.
#[macro_export]
macro_rules! try_pairs {
    ($left: expr, $right: expr) => {
        $crate::pairs::Pairs::try_from((&$left[..], &$right[..]))
    };
}

/// Return `$error` if `$left` not equals `$right`
#[macro_export]
macro_rules! expect_equality {
    ($left: expr, $right: expr, $error: expr) => {
        if $left != $right {
            return Err($error($left, $right));
        }
    };
}

/// Return pairing where `$pairing_func` is the pairing function, `$g1` is/are group G1 elements and `$g2` is/are group G2 elements
#[macro_export]
macro_rules! pair_g1_g2 {
    ($pairing_func: path, $g1: expr, $g2: expr) => {
        $pairing_func($g1, $g2)
    };
}

/// Return pairing where `$pairing_func` is the pairing function, `$g1` is/are group G1 elements and `$g2` is/are group G2 elements
#[macro_export]
macro_rules! pair_g2_g1 {
    ($pairing_func: path, $g2: expr, $g1: expr) => {
        $pairing_func($g1, $g2)
    };
}

#[macro_export]
macro_rules! randomized_pairing_checker_g1_g2 {
    ($randomized_pairing_checker: ident, $func_name: ident, $g1: expr, $g2: expr, $out: expr) => {
        $randomized_pairing_checker.$func_name($g1, $g2, $out)
    };
}

#[macro_export]
macro_rules! randomized_pairing_checker_g2_g1 {
    ($randomized_pairing_checker: ident, $func_name: ident, $g2: expr, $g1: expr, $out: expr) => {
        $randomized_pairing_checker.$func_name($g1, $g2, $out)
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn unnest_tuple() {
        let a = unnest_tuple!(1 => 1);
        assert_eq!([a], [1]);
        let (a, b) = unnest_tuple!(_a, _b => (1, 2));
        assert_eq!([a, b], [1, 2]);
        let (a, b, c) = unnest_tuple!(_a, _b, _c => (1, (2, 3)));
        assert_eq!([a, b, c], [1, 2, 3]);
        let (a, b, c, d) = unnest_tuple!(_a, _b, _c, _d => (1, (2, (3, 4))));
        assert_eq!([a, b, c, d], [1, 2, 3, 4]);
        let (a, b, c, d, e) = unnest_tuple!(_a, _b, _c, _d, _e => (1, (2, (3, (4, 5)))));
        assert_eq!([a, b, c, d, e], [1, 2, 3, 4, 5]);
        let (a, b, c, d, e, f) =
            unnest_tuple!(_a, _b, _c, _d, _e, _f => (1, (2, (3, (4, (5, 6))))));
        assert_eq!([a, b, c, d, e, f], [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn join() {
        let a = join!(1);
        assert_eq!([a], [1]);
        let (a, b) = join!(1, 2);
        assert_eq!([a, b], [1, 2]);
        let (a, b, c) = join!(1, 2, 3);
        assert_eq!([a, b, c], [1, 2, 3]);
        let (a, b, c, d) = join!(1, 2, 3, 4);
        assert_eq!([a, b, c, d], [1, 2, 3, 4]);
        let (a, b, c, d, e) = join!(1, 2, 3, 4, 5);
        assert_eq!([a, b, c, d, e], [1, 2, 3, 4, 5]);
        let (a, b, c, d, e, f) = join!(1, 2, 3, 4, 5, 6);
        assert_eq!([a, b, c, d, e, f], [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn equality() {
        enum Errr {
            #[allow(dead_code)]
            Unequal(usize, usize),
        }

        fn test_fn(s: usize) -> Result<usize, Errr> {
            let v = vec![1, 2, 4];
            expect_equality!(v.len(), s, Errr::Unequal);
            Ok(s)
        }

        assert!(test_fn(3).is_ok());
        assert!(test_fn(2).is_err());
    }
}
