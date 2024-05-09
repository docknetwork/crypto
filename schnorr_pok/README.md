# Schnorr's proof of knowledge

<!-- cargo-rdme start -->

Schnorr protocol to prove knowledge of 1 or more discrete logs in zero knowledge.
Refer [this](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) for more details of Schnorr protocol.

Also implements the proof of knowledge of discrete log in pairing groups, i.e. given prover and verifier
both know (`A1`, `Y1`), and prover additionally knows `B1`, prove that `e(A1, B1) = Y1`. Similarly,
proving `e(A2, B2) = Y2` when only prover knows `A2` but both know (`B2`, `Y2`). See [`discrete_log_pairing`]

Also implements the proof of **inequality of discrete log** (a value committed in a Pedersen commitment),
either with a public value or with another discrete log in [`Inequality`]. eg. Given a message `m`,
its commitment `C = g * m + h * r` and a public value `v`, proving that `m` ≠ `v`. Or given 2 messages
`m1` and `m2` and their commitments `C1 = g * m1 + h * r1` and `C2 = g * m2 + h * r2`, proving `m1` ≠ `m2`

Also implements the proof of **inequality of discrete log** when only one of the discrete log is known to
the prover. i.e. given `y = g * x` and `z = h * k`, prover and verifier know `g`, `h`, `y` and `z` and prover additionally 
knows `x` but not `k`.

We outline the steps of Schnorr protocol.
Prover wants to prove knowledge of `x` in `y = g * x` (`y` and `g` are public knowledge)  
**Step 1**: Prover generates randomness `r`, and sends `t = g * r` to Verifier.  
**Step 2**: Verifier generates random challenge `c` and send to Prover.  
**Step 3**: Prover produces `s = r + x*c`, and sends s to Verifier.  
**Step 4**: Verifier checks that `g * s = (y * c) + t`.  

For proving knowledge of multiple messages like `x_1` and `x_2` in `y = g_1*x_1 + g_2*x_2`:  
**Step 1**: Prover generates randomness `r_1` and `r_2`, and sends `t = g_1*r_1 + g_2*r_2` to Verifier  
**Step 2**: Verifier generates random challenge `c` and send to Prover  
**Step 3**: Prover produces `s_1 = r_1 + x_1*c` and `s_2 = r_2 + x_2*c`, and sends `s_1` and `s_2` to Verifier  
**Step 4**: Verifier checks that `g_1*s_1 + g_2*s_2 = y*c + t`  

Above can be generalized to more than 2 `x`s

There is another variant of Schnorr which gives shorter proof but is not implemented:
1. Prover creates `r` and then `T = r * G`.
2. Prover computes challenge as `c = Hash(G||Y||T)`.
3. Prover creates response `s = r + c*x` and sends `c` and `s` to the Verifier as proof.
4. Verifier creates `T'` as `T' = s * G - c * Y` and computes `c'` as `c' = Hash(G||Y||T')`
5. Proof if valid if `c == c'`

The problem with this variant is that it leads to poorer failure reporting as in case of failure, it can't be
pointed out which relation failed to verify. Eg. say there are 2 relations being proven which leads to 2
`T`s `T1` and `T2` and 2 responses `s1` and `s2`. If only the responses and challenge are sent then
in case of failure, the verifier will only know that its computed challenge `c'` doesn't match prover's given
challenge `c` but won't know which response `s1` or `s2` or both were incorrect. This is not the case
with the implemented variant as verifier checks 2 equations `s1 = r1 + x1*c` and `s2 = r2 + x2*c`


[`Inequality`]: https://docs.rs/schnorr_pok/latest/schnorr_pok/inequality/
[`discrete_log_pairing`]: https://docs.rs/schnorr_pok/latest/schnorr_pok/discrete_log_pairing/

<!-- cargo-rdme end -->
