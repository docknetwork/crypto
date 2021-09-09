# bbs_plus

BBS+ signature according to the paper: "Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited" <https://eprint.iacr.org/2016/663>
Provides signature creation and verification in both groups G1 and G2.
Provides proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.
The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

License: Apache-2.0
