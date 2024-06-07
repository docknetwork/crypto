# Publicly verifiable secret sharing protocols

These allow a dealer to share commitments to the secret shares (`commitment_key * secret_share`) with a group such that a threshold number of group
members can get commitment to the secret. This sharing can happen on a public bulletin board as the dealer's
shares are encrypted for the corresponding party and anyone can verify that the shares are created correctly because the dealer
also outputs a proof. This primitive is useful for sharing secrets on a blockchain as the blockchain can verify the proof.

Based on Fig. 7 of the paper [A Unified Framework for Verifiable Secret Sharing](https://eprint.iacr.org/2023/1669).
Implements the protocol in the paper and a variation.

The dealer in the protocol in Fig 7. wants to share commitments to the shares of secrets of `k` - (`k_1`, `k_2`, ..., `k_n`) as (`g * k_1`, `g * k_2`, ..., `g * k_n`)
to `n` parties with secret and public keys (`s_i`, `h_i = g * s_i`) such that any `t` parties can reconstruct commitment to the secret `g * k`.
Notice the base `g` is the same in the public keys, the share commitments and the reconstructed commitment to the secret. This is implemented in [same_base](./same_base.rs)

Let's say the dealer wants to share `j * k` where base `j` is also a group generator and discrete log of `j` wrt. `g` is not known
such that party `i` gets `j * k_i`
The dealer follows a similar protocol as above and broadcasts `y'_i = j * k_i + g * k_i = (j + g) * k_i` in addition
to `y_i = h_i * k_i` and a proof that `k_i` is the same in both `y'_i` and `y_i`. Then each party can
compute `g * k_i` as described in the paper and compute `j * k_i = y'_i - g * k_i`. Essentially, `y'_i` is
an Elgamal ciphertext, `g * k_i` is the ephemeral secret key (between the dealer and party `i`) and
`j * k_i` is the message. This is implemented in [different_base](./different_base.rs). Note that both `j` and `g` must be in the same group.
