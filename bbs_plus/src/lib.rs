#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! BBS+ signature according to the paper: "Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited" <https://eprint.iacr.org/2016/663>
//! Provides signature creation and verification in both groups G1 and G2.
//! Provides proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

pub mod error;
pub mod proof;
pub mod setup;
pub mod signature;
// pub mod serde_utils;

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
            let mut serz = vec![];
            // $obj.serialize(&mut serz).unwrap();
            CanonicalSerialize::serialize(&$obj, &mut serz).unwrap();
            let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);
            // assert_eq!($obj_type::deserialize(&serz[..]).unwrap(), $obj);
            // assert_eq!(ark_serialize::CanonicalDeserialize::deserialize::<$obj_type>(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_unchecked(&mut serz).unwrap();
            let deserz: $obj_type = CanonicalDeserialize::deserialize_unchecked(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);
            // assert_eq!($obj_type::deserialize_unchecked(&serz[..]).unwrap(), $obj);

            let mut serz = vec![];
            $obj.serialize_uncompressed(&mut serz).unwrap();
            let deserz: $obj_type = CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);
            /*assert_eq!(
                $obj_type::deserialize_uncompressed(&serz[..]).unwrap(),
                $obj
            );*/
        };
    }
}
