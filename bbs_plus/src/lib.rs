#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! BBS+ signature according to the paper: "Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited" <https://eprint.iacr.org/2016/663>
//! Provides signature creation and verification in both groups G1 and G2.
//! Provides proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub mod error;
pub mod proof;
pub mod setup;
pub mod signature;

#[cfg(test)]
#[macro_use]
pub mod tests {
    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ident, $obj: ident) => {
            let mut serz = vec![];
            $obj.serialize(&mut serz).unwrap();
            assert_eq!($obj_type::deserialize(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_unchecked(&mut serz).unwrap();
            assert_eq!($obj_type::deserialize_unchecked(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_uncompressed(&mut serz).unwrap();
            assert_eq!(
                $obj_type::deserialize_uncompressed(&serz[..]).unwrap(),
                $obj
            );
        };
    }
}
