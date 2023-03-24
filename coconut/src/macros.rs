/// Convert given slices to `OwnedPairs`, panics in case of error.
#[macro_export]
macro_rules! owned_pairs {
    ($left: expr, $right: expr) => {
        $crate::try_owned_pairs!($left, $right).unwrap_or_else(|(left, right)| {
            panic!("Lengths are not equal: left = {}, right = {}", left, right)
        })
    };
}

/// Convert given slices to `OwnedPairs`, panics in case of error.
#[macro_export]
macro_rules! try_owned_pairs {
    ($left: expr, $right: expr) => {
        $crate::helpers::OwnedPairs::try_from(($left, $right))
    };
}

/// Convert given slices to `Pairs`, panics in case of error.
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
        $crate::helpers::Pairs::try_from((&$left[..], &$right[..]))
    };
}
