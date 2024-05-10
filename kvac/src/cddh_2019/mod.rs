//! Implements KVAC from [Fast Keyed-Verification Anonymous Credentials on Standard Smart Cards](https://eprint.iacr.org/2019/460)
//!
//! MAC_wBB - Follows section 3 of the paper
//! - Setup params contain a random G1 group element `g`. Creating by hashing a label.
//! - Secret key contains random field elements `x_i` and public key has same number of `X_i = g * x_i`.
//!   `i` would be an upper bound on number of supported messages and passed as an argument like PS sig
//! - Signing and verification work as described in the paper.
//!
//! Signature - Follows section 4.
//! - Does not support blind signing (for now) so the signer has to know all messages.
//! - Signer returns 2 objects, the signature composed of all `sigma`s and the proof composed of `2*n` Schnorr proofs
//!   for total `2*n` relations, each pair of the form `sigma_{x_i} = sigma * x_i` and `X_i = g * x_i`. For each `i`,
//!     - Generate random field element `r_i`
//!     - Create a Schnorr protocol and call its `init` with witness `x_i`, blinding `r_i` and base `sigma`.
//!     - Create a Schnorr protocol and call its `init` with witness `x_i`, blinding `r_i` and base `g`.
//!   For each of the above `2*n`, protocols generate their challenge contribution, hash to create the challenge and then generate `2*n` proofs.
//! - Use above MAC to generate `sigma` and `sigma_{x_i}` for `i` = 0 to `n`.
//! - User on getting signature verifies the `2*n` proofs and checks that the response for each of the `i` pairs above is same so `n` different responses in total.
//! - After verifying, user discards the proof but keeps `sigma` and all `sigma_{x_i}`
//! - The above can be made efficient by combining `2*n` relations into 1 using a challenge but thats an optimization for later.
//!
//! Proof of knowledge of signature - Follows section 4.2
//! - Proof generation follow similar API as `PoKOfSignatureG1Protocol` - `init`, `challenge_contribution` and `gen_proof`.
//! - In `init`
//!     - Given signature `sigma` and `sigma_{x_i}`, accept blindings for hidden messages like `PoKOfSignatureG1Protocol::init`
//!     - Generate random field element `r` and `sigma_hat = sigma * r`.
//!     - The existing Schnorr protocol abstraction can't be used because the verifier can himself create bases for the commitment.
//!     - Get `k+1` random blindings where `k` is the number of hidden attributes. blindings = `[rho_r, <rho_k, ...>]`. Here `<rho_k, ...>`
//!       correspond to the blindings for hidden attributes and are either generated randomly or passed as argument.
//!     - Use an MSM to create `t = g * rho_r + \sum_k{sigma_{x_k} * rho_k * r}` for all hidden message `m_k`
//!     - Set witness as `[r, <m_k, ...>]` for all hidden attributes `m_k`.
//! - In `challenge_contribution`, serialize the following for challenge
//!     - `t`, `g`, `sigma_hat` and `sigma_{x_k}` for all hidden message `m_k`
//!     - `\sum_i(sigma_{x_i} * m_i)` for all revealed messages `m_i`
//! - In `gen_proof`
//!     - Generate responses `s_rho = rho_r + c * r` and `s_k = rho_k - c * m_k` for challenge `c` and for hidden message `m_k`
//!     - The proof contains above responses and `sigma_hat`
//! - In `Proof::verify`
//!     - Accepts revealed messages `m_i` and challenge `c`
//!     - Check if `t == g * s_rho + sigma_hat * (\sum_k(x_k * s_k) - c * (\sum_i(x_i * m_i) - x_0))` for revealed messages `m_i` and hidden messages `m_k`.
//! - For separating the above check into parts that require secret key, above can be seen as `t == g * s_rho -  sigma_hat * (c * (\sum_i(x_i * m_i))) + sigma_hat * (\sum_k(x_k * s_k) - c * x_0)`
//! - Add a function `Proof::to_keyed_proof` that takes revealed messages and the challenge to output `KeyedProof`. It contains:
//!     - indices of hidden messages `k`,
//!     - responses for hidden messages `s_k`
//!     - `sigma_hat`,
//!     - challenge `c` and
//!     - `com = t - g * s_rho + sigma_hat * (c * (\sum_i(x_i * m_i)))` for revealed messages `m_i`
//! - In `KeyedProof`::verify` -
//!     - Checks `com == sigma_hat * (\sum_k(x_k * s_k) - c * x_0)` corresponding to hidden indices `*_k`
//! - Objective is to hide the revealed messages from `KeyedProof` thus building a joint verification protocol where verifier gets `Proof`
//!   and it passes `KeyedProof` to the signer who uses secret key to verify it without learning revealed messages `m_i`
//! - Add a function `Proof::get_resp_for_message` to get Schnorr responses for the hidden messages
