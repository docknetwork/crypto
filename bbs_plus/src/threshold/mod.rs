//! Implementation of threshold BBS and BBS+ based on the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)
//! Both implementations share the same multiplication phase and the base OT phase but their round 1 is slightly different.

pub mod base_ot_phase;
pub mod commitment;
pub mod multiplication_phase;
pub mod threshold_bbs;
pub mod threshold_bbs_plus;
pub mod utils;
pub mod zero_sharing;
