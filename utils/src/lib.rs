#![cfg_attr(not(feature = "std"), no_std)]

// TODO: Feature gate this
#[macro_use]
pub mod serde_utils;
pub mod ff;
pub mod hashing_utils;
pub mod msm;
pub mod poly;
pub mod randomized_pairing_check;
pub mod transcript;

#[macro_export]
macro_rules! concat_slices {
    ($($slice: expr),+) => {
        [$(&$slice[..]),+].concat()
    }
}
