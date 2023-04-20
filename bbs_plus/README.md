# BBS and BBS+ signatures

<!-- cargo-rdme start -->

Implements BBS and BBS+ signatures.

BBS+ signature according to the paper: [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663).
Provides
- signature creation and verification with signature in group G1 and public key in group G2 and vice-versa.
- proof of knowledge of signature and corresponding messages in group G1 as that is more efficient.

BBS signature according to the paper: [Revisiting BBS Signatures](https://eprint.iacr.org/2023/275).
Provides
- signature creation and verification with signature in group G1 and public key in group G2.
- proof of knowledge of signature and corresponding messages. The implemented protocols are a bit
different from whats mentioned in the paper. The modifications are made in the Schnorr proof part
to allow for use-cases like proving equality (in zero-knowledge) of messages among same/different signatures
or proving predicates (in zero-knowledge) about messages. Check the documentation of corresponding modules
for more details.

### Modules

1. BBS and BBS+ signature parameters and key generation module - [`setup`]. The signature params for BBS are slightly
different from BBS+ but public key is same.
2. BBS+ signature module - [`signature`]
3. BBS+ proof of knowledge of signature module - [`proof`]
4. BBS signature module - [`signature_23`]
5. BBS proof of knowledge of signature module - [`proof_23`]
6. BBS proof of knowledge of signature module, alternate implementation - [`proof_23_alternate`]

The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

[`setup`]: https://docs.rs/bbs_plus/latest/bbs_plus/setup/
[`signature`]: https://docs.rs/bbs_plus/latest/bbs_plus/signature/
[`proof`]: https://docs.rs/bbs_plus/latest/bbs_plus/proof/
[`signature_23`]: https://docs.rs/bbs_plus/latest/bbs_plus/signature_23/
[`proof_23`]: https://docs.rs/bbs_plus/latest/bbs_plus/proof_23/
[`proof_23_alternate`]: https://docs.rs/bbs_plus/latest/bbs_plus/proof_23_alternate/

<!-- cargo-rdme end -->

License: Apache-2.0
