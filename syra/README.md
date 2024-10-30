<!-- cargo-rdme start -->

Implements the protocol from the paper [SyRA: Sybil-Resilient Anonymous Signatures with Applications to Decentralized Identity](https://eprint.iacr.org/2024/379)

This will be used to generate pseudonym for low-entropy user attributes. The issuer will create "signature" for a
unique user attribute and user uses this "signature" to create the pseudonym.

Also implements the threshold issuance of SyRA signatures

A more efficient protocol generating pseudonym and corresponding proof of knowledge is implemented in the module [pseudonym_alt](./src/pseudonym_alt.rs)

<!-- cargo-rdme end -->
