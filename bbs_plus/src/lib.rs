#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

//! Implements BBS and BBS+ signatures.
//!
//! BBS+ signature according to the paper: [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663).
//! Provides
//! - signature creation and verification with signature in group G1 and public key in group G2 and vice-versa.
//! - proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
//!
//! BBS signature according to the paper: [Revisiting BBS Signatures](https://eprint.iacr.org/2023/275).
//! Provides
//! - signature creation and verification with signature in group G1 and public key in group G2.
//! - proof of knowledge of signature and corresponding messages. The implemented protocols are a bit
//! different from whats mentioned in the paper. The modifications are made in the Schnorr proof part
//! to allow for use-cases like proving equality (in zero-knowledge) of messages among same/different signatures
//! or proving predicates (in zero-knowledge) about messages. Check the documentation of corresponding modules
//! for more details.
//!
//! Threshold BBS and BBS+ signatures based on the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)
//! The threshold signing protocol has 3 phases (not communication rounds)
//!     1. This is the randomness generation phase
//!     2. This is the phase where multiplications happen
//!     3. Here the outputs of phases 1 and 2 and the messages to be signed are used to generate the signature. This phase
//!     is non-interactive from signers' point of view as they don't just interact among themselves
//!
//! Note that only 3rd phase requires the messages to be known so the first 2 phases can be treated as pre-computation
//! and can be done proactively and thus only phase 1 and 2 are online phases of the MPC protocol and phase 3 is the offline
//! phase.
//! Secondly since the communication time among signers is most likely to be the bottleneck
//! in threshold signing, phase 1 and 2 support batching meaning that to generate `n` signatures only a single execution
//! of phase 1 and 2 needs to done, although with larger inputs. Then `n` executions of phase 3 are done to generate
//! the signature.
//! Also, its assumed that parties have done the DKG as well as the base OT and stored their results before starting phase 1.
//! Both BBS and BBS+ implementations share the same multiplication phase and the base OT phase but their phase 1 is slightly
//! less expensive as BBS+ needs 2 random fields elements but BBS needs only 1.
//!
//! ## Modules
//!
//! 1. BBS and BBS+ signature parameters and key generation module - [`setup`]. The signature params for BBS are slightly
//! different from BBS+ but public key is same.
//! 2. BBS+ signature module - [`signature`]
//! 3. BBS+ proof of knowledge of signature module - [`proof`]
//! 4. BBS signature module - [`signature_23`]
//! 5. BBS proof of knowledge of signature module - [`proof_23`]
//! 6. BBS proof of knowledge of signature module, implementation as in appendix B - [`proof_23_cdl`]
//! 7. BBS proof of knowledge of signature module, implementation as in appendix A - [`proof_23_ietf`]
//! 8. Threshold BBS and BBS+ signatures - [`threshold`]
//!
//! The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.
//!
//!
//! [`setup`]: crate::setup
//! [`signature`]: crate::signature
//! [`proof`]: crate::proof
//! [`signature_23`]: crate::signature_23
//! [`proof_23`]: crate::proof_23
//! [`proof_23_cdl`]: crate::proof_23_cdl
//! [`proof_23_ietf`]: crate::proof_23_ietf
//! [`threshold`]: crate::threshold

pub mod error;
pub mod proof;
pub mod proof_23;
pub mod proof_23_cdl;
pub mod proof_23_ietf;
pub mod setup;
pub mod signature;
pub mod signature_23;
pub mod threshold;

pub mod prelude {
    pub use crate::{
        error::BBSPlusError,
        proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
        proof_23_cdl::{PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol},
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
