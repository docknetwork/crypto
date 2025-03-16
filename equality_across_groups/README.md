<!-- cargo-rdme start -->

Protocols for proving equality of committed values across groups.

- Implements the sigma protocol for proving that two values committed in different groups are equal. As described in Figure 1 and its
extension in section 5 of the paper [Proofs of discrete logarithm equality across groups](https://eprint.iacr.org/2022/1593). Check the [module](./src/eq_across_groups.rs) for more docs
- Implements the protocol to prove short Weierstrass elliptic curve point addition and scalar multiplication from the paper [CDLS: Proving Knowledge of Committed Discrete Logarithms with Soundness](https://eprint.iacr.org/2023/1595). Check the [point addition module](./src/ec/sw_point_addition.rs) and [scalar multiplication module](./src/ec/sw_scalar_mult.rs) for more docs
- Use the above protocols to prove knowledge of a committed ECDSA public key on Tom-256 curve as described in the paper [ZKAttest Ring and Group Signatures for Existing ECDSA Keys](https://eprint.iacr.org/2021/1183). Check the [module](./src/pok_ecdsa_pubkey.rs) for more docs
- Use the above protocols to prove knowledge of a committed ECDSA public key on BLS12-381 curve. Check the test `pok_ecdsa_pubkey_committed_in_bls12_381_commitment` in [module](./src/pok_ecdsa_pubkey.rs).

**CREDIT**

This idea of using these 2 protocols to prove knowledge of ECDSA public key committed on the BLS12-381 curve came from Patrick Amrein from [Ubique](https://ubique.ch/)
and their work [here](https://github.com/UbiqueInnovation/zkattest-rs) is prior art.

<!-- cargo-rdme end -->
