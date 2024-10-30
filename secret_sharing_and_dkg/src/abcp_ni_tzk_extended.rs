//! Generalization of the protocol for NI-TZK for discrete logarithms described in Fig 3 of the paper [VSS from Distributed ZK Proofs and Applications](https://eprint.iacr.org/2023/992.pdf)
//! Fig 3. describes a protocol for the prover sharing its witness `x` for the relation `h = g^x` among `n` parties such
//! that a threshold number, `t`, of them can reconstruct `x`.
//!
//! Following describes a protocol where the prover shares its witnesses `(x, y, z, ...)` for the relation `h = g_1^x.g_2^y.g_3^z...` where
//! party `i` has shares `(x_i, y_i, z_i, ..)` and any threshold number of them can reconstruct `(x, y, z, ...)`. It uses the
//! approach used when using the Schnorr proof of knowledge protocol to prove knowledge of the opening of a Pedersen commitment.
//! Note: I use multiplicative notation below.
//!
//! I describe the protocol for the relation `h = g_1^x.g_2^y` with 2 witnesses `x, y` below, but it can be extended to more witnesses easily.
//!
//! `HC` is a hash function used to commit to shares and the commitment is opened by revealing the shares.
//! `HC(x_i, .., salt) -> {0, 1}^*` where `x_i ...` can be field elements or group elements and `salt ∈ {0, 1}^*`
//!
//! 1. Prover samples polynomials of degree `t` (such `t+1` parties can reconstruct) `f_x(X), f_y(X)` such that `f_x(0) = x, f_y(0) = y`.
//! 2. Prover samples random blinding polynomials of degree `t` as `b_x(X), b_y(X)`.
//! 3. Prover commits to `b_x(0), b_y(0)` as `C_0 = HC(g_1^b_x(0).g_2^b_y(0), k_0)` where `k_0` is a random salt.
//! 4. For shareholder `i`, the prover
//!    4.1 picks random salts `k_i <- {0, 1}^*, k'_i <- {0, 1}^*`
//!    4.2 commits to `b_x(i), b_y(i)` as `C_i = HC(g_1^b_x(i).g_2^b_y(i), k_i)`
//!    4.3 commits to `x_i=f_x(i), y_i=f_y(i)` as `C'_i = HC(x_i, y_i, k'_i)`.
//! 5. Prover hashes all `C_i`, `C'_i` for `i` = 0 to `n` and instance variables like `h, g_1, g_2`, etc to create challenge `d`.
//! 6. Prover creates response polynomials `r_x(X) = b_x(X) - d.f_x(X), r_y(X) = b_y(X) - d.f_y(X)`.
//! 7. Prover broadcasts all `C_i`, `C'_i` for `i` = 0 to `n`, `k_0` and polynomials `r_x, r_y` and sends `(x_i, y_i, k_i, k'_i)` to shareholder `i` on a private channel.
//! 8. Each shareholder constructs challenge `d` in the same way as prover in step 5.
//! 9. Shareholder `i` verifies
//!    9.1 `C'_i = HC(x_i, y_i, k'_i)`
//!    9.2 `C_i == HC(g_1^{r_x(i) + d.x_i}.g_2^{r_y(i) + d.y_i}, k_i)` (his own share is correct)
//!    9.3 `C_0 == HC(g_1^r_x(0).g_2^r_y(0).h^d, k_0)`  (share is part of the original witness)
//!
//! Note that I omit commitment `C'_0` created in the paper as all the instance variables are anyway hashed into the challenge `d`
//!
//! Following is modification of the above protocol where prover only wants to share the witness `x` of the Pedersen commitment `h = g_1^x.g_2^y`.
//!
//! 1. Prover samples polynomial of degree `t` (such `t+1` parties can reconstruct) `f_x(X)` such that `f_x(0) = x`.
//! 2. Prover samples random blinding polynomial of degree `t` as `b_x(X)` and a random `j <- Z_p`
//! 3. Prover commits to `b_x(0)` as `C_0 = HC(g_1^b_x(0).g_2^j, k_0)` where `k_0` is a random salt.
//! 4. For shareholder `i`, the prover
//!    4.1 picks random salts `k_i <- {0, 1}^*, k'_i <- {0, 1}^*`
//!    4.2 commits to `b_x(i)` as `C_i = HC(g_1^b_x(i), k_i)`
//!    4.3 commits to `x_i=f_x(i)` as `C'_i = HC(x_i, k'_i)`.
//! 5. Prover hashes all `C_i`, `C'_i` for `i` = 0 to `n` and instance variables like `h, g_1, g_2`, etc to create challenge `d`.
//! 6. Prover creates response polynomial `r_x(X) = b_x(X) - d.f_x(X)` and `s = j - d.y`.
//! 7. Prover broadcasts all `C_i`, `C'_i` for `i` = 0 to `n`, `k_0`, `s` and polynomial `r_x` and sends `(x_i, k_i, k'_i)` to shareholder `i` on a private channel.
//! 8. Each shareholder constructs challenge `d` in the same way as prover in step 5.
//! 9. Shareholder `i` verifies
//!    9.1 `C'_i = HC(x_i, k'_i)`
//!    9.2 `C_i == HC(g_1^{r_x(i) + d.x_i}, k_i)` (his own share is correct)
//!    9.3 `C_0 == HC(g_1^r_x(0).g_2^s.h^d, k_0)`  (share is part of the original witness)
//!

// TODO: Implement these
