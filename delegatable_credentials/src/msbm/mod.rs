//! Based on the paper [Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680)

pub mod issuance;
pub mod keys;
pub mod show;
pub mod sps_eq_uc_sig;

/*
TODO: Revocation. A failed approach (similar to how its done with Protego) was:
1. Extend the issuer public key to have `X_Q = x_0 * Q`, `X_s = x_0 * P1 * s` and `{X_s}_hat = x_0 * P2 * s`
where `s` is the accumulator trapdoor and thus `P1 * s` & `P2 * s` are available in accumulator SRS.
2. Extend the user secret key to have 1 more optional element usk2 like with Protego, and public key
contains `upk2 = P1 * usk2` and `upk2_hat = P2 * usk2`
3. The SPSEQ-UC signature will have 2 more elements `T_Q = x_1 * y * P1 + x_0 * usk2 * Q` and
`T_nym = x_1 * y * P1 + x_0 * usk2 * P1 * (s - nym) = x_1 * y * P1 + x_0 * usk2 * (P1 * s - P1 * nym)) = x_1 * y * P1 + x_0 * (P1 * s * usk2 - upk2 * nym)`.
Since `P1 * s` is publicly available from the accumulator SRS, the user will send a proof of knowledge of `usk2` in `P1 * s * usk2` in its signature request and
now the signer can calculate `T_nym`. The user will also send a proof of knowledge of `usk2` in `usk2 * Q` and thus the signer can create `T_Q`.
4. For verifying the signature, verification of `T_Q` and `T_nym` is as follows:
    a. `e(T_Q, P2) = e(Y, {X_1}hat) * e(X_Q, upk2_hat = usk2*P2)`
    b. `e(T_nym, P2) = e(Y, {X_1}hat) * e(upk2, {X_s}_hat = x_0 * P2 * s) * e(-nym * upk2, {X_0}_hat)`
5. For randomizing the signature during `ChangeRep`, randomize `T_Q` and `T_nym` to `{T_Q}'` and `{T_nym}'` respectively as:
    a. `{T_Q}' = (T_Q + X_0 * chi) * psi`
    b. `{T_nym}' = (T_nym + (X_s - X_0)*nym * chi) * psi`
6. The public keys are randomized as `upk2' = (upk2 + P1*chi)*psi`

The challenge is getting the accumulator non-membership witness verification work.
*/
