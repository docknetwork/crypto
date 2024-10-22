<!-- cargo-rdme start -->

Implements the protocol from the paper [SyRA: Sybil-Resilient Anonymous Signatures with Applications to Decentralized Identity](https://eprint.iacr.org/2024/379)

This will be used to generate pseudonym for low-entropy user attributes. The issuer will create "signature" for a
unique user attribute and user uses this "signature" to create the pseudonym.

Also implements the threshold issuance of SyRA signatures

### A more efficient protocol generating pseudonym and corresponding proof of knowledge

This significantly reduces the number of pairings done by both the user and verifier as well as reducing the
storage and computation cost of user and issuer as the "user secret key" (issuer's signature) is a single group
element in group G1. _But this doesn't have a security proof yet and thus isn't implemented._

- Setup parameters: `g ∈ G1, g_hat ∈ G2`
- Issuer keys: secret `sk ∈ Z_p`, public `ivk_hat ∈ G2, ivk_hat = g_hat*sk`
- User gets from issuer a signature `usk ∈ G1, usk = g*{1/(sk+s)}` where `s ∈ Z_p` is the user's identity
- User and verifier hash context to `Z ∈ G2`.

For the user's signature generation, the objective is that given usk, the user wants to prove 2 relations
1. `T = e(usk, Z)` where `T, Z` are public but usk is only known to the user.
2. User knows a valid `usk` and the `s` in `usk` without revealing `usk` and `usk` satisfies `e(usk, g_hat*s.ivk_hat) == e(g, g_hat)`.
And the user should prove that usk used in relation 1 and 2 are the same.

Relation 1 can be proved by applying the folklore Schnorr protocol for discrete log to the pairing setting. Eg. i.e. given the prover and verifier both know `(Z, T)` and the prover additionally knows `usk`, prove that `e(usk, Z) = T`.
1. Prover chooses a random `R ∈ G1` and computes `K = e(R, Z)`
2. Verifier gives a challenge `c ∈ Z_p`.
3. Computes response `S ∈ G1, S = R + usk*c` and sends `(K, S)` to the verifier.
4. Verifier checks if `e(S, Z) = K + T*c`. This works because `e(S, Z) = e(R + usk*c, Z) = e(R, Z) + e(usk*c, Z) = K + c*e(usk, Z) = K + c*T`.

`usk` is essentially a weak-BB signature so we can create a proof for relation 2 using the proof of knowledge of weak-BB signature protocol described
in section 2.4 of [this paper](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf). Note that there is no pairing computation for prover and
only 1 for verifier (considering a pairing product).

To prove `usk` is the same in both relations, the user chooses a random `r ∈ Z_p` and creates `V ∈ G1, V = usk*r` and `T' = e(V, Z) = T*r` and
proves knowledge of `r` in `T' = T*r`. Note that `V, r` are the same as the ones created in the proof of relation 2 and the user can prove that
`r` is the same. Also, the prover doesn't send `T'`, the verifier creates using `V` and `Z` as `T' = e(V, Z)`.

Following is the detailed protocol for user's signature generation
1. User follows the above protocol for Relation 1 (verifier's challenge is generated through Fiat Shamir) and gets `T = e(usk, Z)` and proof `pi_1 = (K, S)`.
2. User picks a random `r  ∈ Z_p`, creates `V, V' ∈ G1` as `V = usk*r, V' = V*-s * g*r, T' = T*r`.
3. User creates a proof `pi_2 = SPK{(s, r) : V' = V*-s * g*r ∧ T' = T*r}`.
4. User sends proof `pi_1, T, pi_2, V, V'` to the verifier.
5. Verifier creates `T' = e(V, Z)`, checks pi_1, pi_2 and `e(V', g_hat) == e(V, ivk_hat)`.

<!-- cargo-rdme end -->
