#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! BBS+ signature according to the paper: [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663).
//! Provides
//! - signature creation and verification in both groups G1 and G2.
//! - proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
//!
//! ## Modules
//!
//! 1. Signature parameters and key generation module - [`setup`]
//! 2. Signature module - [`signature`]
//! 3. Proof of knowledge of signature module - [`proof`]
//!
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.
//!
//! [`setup`]: crate::setup
//! [`signature`]: crate::signature
//! [`proof`]: crate::proof

pub mod error;
pub mod proof;
pub mod setup;
pub mod signature;

pub mod prelude {
    pub use crate::error::BBSPlusError;
    pub use crate::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
    pub use crate::setup::*;
    pub use crate::signature::{SignatureG1, SignatureG2};
}

#[cfg(test)]
#[macro_use]
pub mod tests {
    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ty, $obj: ident) => {
            // Test ark serialization
            let mut serz = vec![];
            CanonicalSerialize::serialize(&$obj, &mut serz).unwrap();
            let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            let mut serz = vec![];
            $obj.serialize_unchecked(&mut serz).unwrap();
            let deserz: $obj_type = CanonicalDeserialize::deserialize_unchecked(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            let mut serz = vec![];
            $obj.serialize_uncompressed(&mut serz).unwrap();
            let deserz: $obj_type =
                CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            // Test JSON serialization
            let ser = serde_json::to_string(&$obj).unwrap();
            let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
            assert_eq!($obj, deser);

            // Test Message Pack serialization
            let ser = rmp_serde::to_vec_named(&$obj).unwrap();
            let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
            assert_eq!($obj, deser);
        };
    }
}
