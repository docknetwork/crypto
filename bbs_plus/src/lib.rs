#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Implements BBS and BBS+.
//!
//! BBS+ signature according to the paper: [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663).
//! Provides
//! - signature creation and verification with signature in group G1 and public key in group G2 and vice-versa.
//! - proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
//!
//! BBS signature according to the paper: [Revisiting BBS Signatures](https://eprint.iacr.org/2023/275).
//! Provides
//! - signature creation and verification with signature in group G1 and public key in group G2.
//! - proof of knowledge of signature and corresponding messages.
//!
//! ## Modules
//!
//! 1. BBS and BBS+ signature parameters and key generation module - [`setup`]. The signature params for BBS are slightly
//! different from BBS+ but public key is same.
//! 2. BBS+ signature module - [`signature`]
//! 3. BBS+ proof of knowledge of signature module - [`proof`]
//! 4. BBS signature module - [`signature_23`]
//! 5. BBS proof of knowledge of signature module - [`proof_23`]
//!
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.
//!
//! [`setup`]: crate::setup
//! [`signature`]: crate::signature
//! [`proof`]: crate::proof
//! [`signature_23`]: crate::signature_23
//! [`proof_23`]: crate::proof_23

pub mod error;
pub mod proof;
pub mod proof_23;
pub mod setup;
pub mod signature;
pub mod signature_23;

pub mod prelude {
    pub use crate::{
        error::BBSPlusError,
        proof::{MessageOrBlinding, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
        proof_23::{PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol},
        setup::*,
        signature::{SignatureG1, SignatureG2},
        signature_23::Signature23G1,
    };
}

#[cfg(test)]
#[macro_use]
pub mod tests {
    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ty, $obj: ident) => {
            // Test ark serialization
            let mut serz = vec![];
            CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
            let deserz: $obj_type =
                CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
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
