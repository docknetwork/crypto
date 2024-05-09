//! # Distributed discrete log (DLOG) check
//!
//! This implements a multi-party protocol to check discrete log (DLOG), i.e. given public (`A`, `B`), check that `B = k * A`
//! where no single party knows `k` but each party has a "share" of `k`. The objective is for a threshold of
//! the participants to be able to check if `B = k * A` without needing to (ideally, being able to) learn `k`.
//! The multi-party system is denoted by `UC` (Untrusted Checker) and the `i`th party is denoted by `UC_i`.
//! `k_1`, `k_2`, ..., `k_n` are the additive shares of `k` such that `k = \sum_{i=1 to t}{l_i*k_i}`, i.e. a threshold `t`
//! of `k_i`s can reconstruct `k`. Here `l_i` is the `i`th Lagrange coefficient and `k_i` "belongs" to `UC_i.`.
//! The secret sharing is done by a dealer `S` who knows `k`. These protocols are thus used by the dealer to
//! delegate the responsibility of discrete log check to the multi-party system `UC`. An example is KVAC verification.
//!
//! Two variations of this protocol are implemented:
//!
//! ## Semi honest protocol
//!
//! ### Doing the computation
//!
//! Here the parties have an additive share of the discrete log `k` created by schemes like
//! Shamir secret sharing, i.e. each `UC_i` has `k_i` directly. When requested to check if `B = A * k`, given (`A`, `B`),
//! any `t` participants of `UC` can jointly compute `A * k` by first computing intermediate result `R_i = A * k_i` and
//! combining all `R_i`s using Lagrange coefficients to compute `R = \sum_i{l_i * R_i} = \sum_i{l_i * A * k_i} = A * \sum_i{l_i* k_i} = A * k`
//! where `l_i` is the ith Lagrange coefficient.
//!
//! ### Verifying the secret share
//!
//! Here the dealer can use Feldman secret sharing to prove to each `UC_i` that its share `k_i` is a valid share of `k`.
//!
//! ### Verifying the computation share
//!
//! If an assurance is needed that each `UC_i` is proving a correct response `R_i` and not some gibberish, `UC_i` can provide a proof of
//! correctness of computation, i.e. indeed `R_i = A * k_i`. For this we assume the existence of a commitment to `k_i`, `C_m_i = J * k_i`.
//! This commitment needs to be published only once and can be done by either the dealer `S` or `UC_i`. Now when submitting
//! the response `R_i`, `UC_i` also submits a proof `pi_i` that `k_i` is the same in `C_{m_i}` and in `R_i`. This proof is created using
//! a Sigma protocol (Schnorr's proof of knowledge) and the proofs `pi_i` can be verified either one-by-one or in a batch by
//! using a multi-scalar multiplication and Schwartz–Zippel lemma. In case of failure with batch verification, each proof `pi_i` has
//! to be individually verified to identify the misbehaving `UC_i`
//!
//! A limitation of this protocol is that a threshold of `UC` can reconstruct `k` by deviating from the protocol, i.e.
//! by doing `k = \sum_{i=1 to t}{l_i*k_i}`. This is why this protocol is called semi-honest and to fix this, we have
//! the maliciously secure variant below.
//!
//!
//! ## Maliciously secure protocol
//!
//! ### Doing the computation
//!
//! Rather than the dealer distributing `k`'s shares `k_1`, `k_2`, ... `k_n` among `UC`, it distributes points
//! `P*k_1`, `P*k_2`, ... `P*k_n` among `n` participants `UC_1`, `UC_2`, ... `UC_n` such that any `t` (the threshold)
//! of `UC_1`, `UC_2`, ... `UC_n` can reconstruct `P*k`. Here `P` is a random generator of a group and can be transparently
//! created (hashing a public string to the group). When requested to check if `B = A * k`, given (`A`, `B`), any `t` participants
//! of `UC` can jointly compute the pairing `e(A, P*k)` by first computing intermediate result `R_i = e(A, P*k_i)` and combining
//! all `R_i`s using Lagrange coefficients to compute `R = \sum_i{l_i * R_i} = \sum_i{l_i * e(A, P * k_i)} = e(A, \sum_i{l_i * P * k_i}) = e(A, P * \sum_i{l_i * k_i}) = e(A, P * k)`
//! where `l_i` is the `i`th Lagrange coefficient. Now it can be checked if `R = e(B, P)`
//!
//! ### Verifying the secret share
//!
//! However here the usual Feldman secret sharing does not work as it is and has to be modified. The commitment to
//! polynomial stays the same but verification requires pairings. The sharing polynomial is `F(x) = a_0 + a_1*x + a_2*x^2 + … + a_{n-1}*x^n-1`
//! where `F(0) = k` and share `i` is `s_i = P*k_i` where `k_i = F(i)` thus share `s_i =  P*F(i)`. The commitment to
//! polynomial `F` is `C = g, g*a_0, g*a_1, …, g*a_n-1` where `g` is the commitment key. On receiving the share `s_i`,
//! each participant checks `e(g, s_i) = e(\sum{\prod_j{C_j, i^j}}, P)`. This works because
//! `e(\sum{\prod_j{C_j, i^j}}, P) = e(g + g*a_0*i + g*a_1*i^2 + … + g*{a_n-1}*{i^n-1}, P) = e(g * (1 + a_0*i + a_1*i^2 + … + {a_n-1}*{i^n-1}), P) = e(g * F(i), P) = e(g, P * F(i)) = e(g, s_i)`.
//!
//! ### Verifying the computation share
//!
//! If an assurance is needed that each `UC_i` is proving a correct response `R_i` and not some gibberish, `UC_i` can provide a proof of
//! correctness of computation, i.e. indeed `R_i = e(A, P*k_i)`. For this we assume the existence of a commitment to share `P * k_i`, `C_m_i = e(J, P*k_i)`.
//! This commitment needs to be published only once and can be done by either the dealer `S` or `UC_i`. Now when submitting
//! the response `R_i`, `UC_i` also submits a proof `pi_i` that `P*k_i` is the same in `C_{m_i}` and in `R_i`. This proof is created using
//! a Sigma protocol (Schnorr's proof of knowledge, adapted to pairings) and the proofs `pi_i` can be verified either one-by-one or in a batch
//! by using a multi-pairings and Schwartz–Zippel lemma. In case of failure with batch verification, each proof `pi_i` has to be
//! individually verified to identify the misbehaving `UC_i`.
//!
//! Above description assumes that (`A`, `B`) are in group G1 and thus shares `P*k_i` have to be in group G2 but
//! above protocol can be modified without much effort to work for (`A`, `B`) in group G2 and shares `P*k_i` to be
//! in group G1. The implementation supports both.
//!
//! This protocol is more expensive in terms of computation and bandwidth than the semi-honest protocol.
//!
//! If we wanted the shares to be a hiding commitment like Pedersen commitment such that share `s_i = P * k_i + T * r_i`
//! where `r_i` is some randomness, the dealer can choose `r_i` to be shares of 0, i.e. `\sum(l_i*r_i) = r = 0`
//! where `l_i` are Lagrange coefficients. The aforementioned protocols for verifying the secret share, joint computation
//! and proving the computation can be modified accordingly.
//!
//! The share is `s_i = P*k_i + T*r_i`  and share verification works by signer committing to coefficients of 2 polynomials,
//! polynomial `F` for sharing `k` and polynomial `G` for sharing `r` . `F(x) = a_0 + a_1*x + a_2*x^2 + … + a_{n-1}*x^n-1`
//! where `F(0) = k` , `F(i) = k_i` and `G(x) = b_0 + b_1*x + b_2*x^2 + … + b_{n-1}*x^n-1` where `G(0) = r = 0` , `G(i) = r_i`.
//! Now signer shares commitments to coefficients of both polynomials as `C = g, g*a_0, g*a_1, …, g*a_n-1` and `D = g, g*b*_0, g*b*_1, …, g*b_n-1`.
//! On receiving the share `s_i`, each participant checks `e(g, s_i) = e(\sum{\prod_j{C_j, i^j}}, P) + e(\sum{\prod_j{D_j, i^j}}, T)`. This works because
//! `e(\sum{\prod_j{C_j, i^j}}, P) + e(\sum{\prod_j{D_j, i^j}}, T) = e(g + g**a_0**i + g**a_1**i^2 + … + g*{a_n-1}**{i^n-1}, P) +* e(g + g*b*_0**i + g*b*_1**i^2 + … + g*{b_n-1}**{i^n-1}, T) = e(g * (1 + a_0**i + a_1**i^2 + … + {a_n-1}**{i^n-1}), P) + *e(g * (1 + b_0**i + b_1**i^2 + … + {b_n-1}**{i^n-1}), T) = e(g * F(i), P) + e(g * G(i), T) = e(g, P * F(i)) + e(g, T * G(i)) = e(g, P * F(i) + T * G(i))= e(g, s_i)`.
//
//! When requested to check if `B = A * k`, given `(A, B)`, any `t` participants of `UC` can jointly compute the pairing `e(A, P**k)` by first
//! computing intermediate result `R_i = e(A, P*k_i + T*r_i)` and combining all `R_i`s using Lagrange coefficients to compute
//! `R = \sum_i{l_i * R_i} = \sum_i{l_i * e(A, P * k_i + T * r_i)} = e(A, \sum_i{l_i * P * k_i}) + e(A, \sum_i{l_i * T * r_i}) = e(A, P * k) + e(A, T * r) = e(A, P * k)`,
//! since `r` = 0 where `l_i` is the `i`th Lagrange coefficient. Now it can be checked if `R = e(B, P)`. To prove that `R_i` is
//! properly created, `UC_i` needs to prove using the similar protocol as above but modify `C_m_i` . Rather than `C_m_i = e(J, P*k_i)`,
//! `C_m_i = e(J, P * k_i + T * r_i)`.
//!
//! This method of creating share as Pedersen commitment is not implemented yet.
//!
//!
//! **CREDIT**: Using pairings for maliciously secure protocol was suggested by [Massimiliano Sala](https://www.science.unitn.it/~sala/)
//!

pub mod maliciously_secure;
pub mod semi_honest;
