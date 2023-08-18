//! Implements KVAC from [Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials](https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20)
//!
//! MAC_BB - Follows section 3.2 of the paper
//! - All parties have access to `MACParams`, i.e. random G1 element `f, h, g, g_0, g_1, g_2, ..., g_n`. `MACParams` are like `SignatureParams` in BBS+.
//! - Signer creates secret key as a random field element `y` and public key `Y = g_0 * y` in group G1.
//! - MAC `generate` and `verify` work as mentioned in the paper.
//! - `MAC::generate` should accept `messages`, `sk` and `MACParams`
//! - `MAC::generate_with_committed_messages` should accept an additional commitment to messages. These are similar to `SignatureG1::new` and `SignatureG1::new_with_committed_messages`
//!
//! Signature - Follows Fig.2 (1) with some changes mentioned below.
//! - The signing API is almost same as BBS+ but unlike BBS+, signature will always be in group G1
//! - Like BBS+, signer might not know all attribute or might only some and receive a commitment to the the hidden attributes.
//! - Deviating from the paper, the user only generates his own `s` during blind signing, same as in BBS+. Also the signer
//!   does not send the proof `pi_2` with the signature and user stores only `A`, `s` and `r` but not `C_m` as that can be
//!   computed because he knows all `m`.
//! - The user does not send proof `pi_1` as this is created using `proof_system` crate, just like with BBS+. Its assumed that
//!   signer has verified that proof before calling sign.
//! - User unblinds the signature like in BBS+ when received a blind signature
//! - Uses MAC_BB from above
//!
//! Proof of knowledge of signature - Follows Fig.2 (2)
//! - Proof generation follow similar API as `PoKOfSignatureG1Protocol` - `init`, `challenge_contribution` and `gen_proof`.
//! - In `init`
//!     - Given signature `A`, `s` and `r` and accept blindings for hidden messages like `PoKOfSignatureG1Protocol::init`
//!     - Pick random field elements `l` and `t`
//!     - Compute `C_m = \sum_i(g_i * m_i) + g * s + h` for all messages `m_i` regardless of them being revealed or not.
//!     - Compute `B_0 = A * l` and `C = C_m * l + B_0 * -r`
//!     - 3 Schnorr's PoK will be created for relations
//!         1. `E = C * 1/l + f * t`
//!         2. `C = E * l + f * -l*t`
//!         3. `E - h = g * s + B_0 * -r/l + f * t + \sum_j(g_j * m_j)` for messages `m_j` not being revealed
//!     - 3 `SchnorrCommitment` and witness sets will be created as below, 1 for each of the above relation. Blindings `r_*` are randomly picked
//!         1. Create `SchnorrCommitment` with bases `[C, f]` and blindings `[r_1, r_2]`. Set its witness as `[1/l, t]`
//!         2. Create `SchnorrCommitment` with bases `[E, f]` and blindings `[r_3, r_4]`. Set its witness as `[l, -l*t]`
//!         3. Create `SchnorrCommitment` with bases `[g, B_0, f, <all g_j, ..>]`. `<all g_j, ..>` correspond to `g_*` for messages that are not revealed.
//!            Set blindings as `[r_5, r_6, r_2, <all r_j, ...>]` where `<all r_j, ...>` correspond to blindings for hidden messages. These are randomly generated
//!            if not provided to `init`. Set its witness as `[s, -r/l, t, <all m_j, ...>]` where `<all m_j, ...>` are the messages not revealed
//! - In `challenge_contribution`, serialize the following for challenge
//!     - `E`, `C`, `f`, `h`, `g`, `B_0` and all `g_j` corresponding to all `m_j` not revealed.
//!     - `\sum_i(g_i * m_i)` for all revealed messages `m_i`
//! - In `gen_proof`
//!     - Generate responses for all 3 `SchnorrCommitment` above
//!     - The proof struct will contains above 3 responses, `t` from all 3 Schnorr commitments and `B_0`, `C` and `E`
//! - In `Proof::verify`
//!     1. Check if `C == B_0 * y`
//!     2. Verify 1st Schnorr response by passing bases mentioned above, `E` and challenge
//!     3. Verify 2nd Schnorr response by passing bases mentioned above, `C` and challenge
//!     4. For 3rd Schnorr response, create bases as above and for argument `y` of `SchnorrResponse::is_valid`, pass `E - h - \sum_i{g_i * m_i}` for all `m_i` that are revealed
//! - Add a function called `Proof::verify_schnorr_proofs` which is same as `Proof::verify` except it does not do check 1.
//! - Add a function called `Proof::verify_except_schnorr_proofs` which does check 1 from `Proof::verify`
//! - The purpose of above 2 functions is to split the signer's/verifier's task into 2 parts where `Proof::verify_schnorr_proofs`
//!   can be done by an untrusted helper who does not know secret key `y` but `Proof::verify_except_schnorr_proofs` requires knowing
//!   secret key
//! - Add a function `get_resp_for_message` to get Schnorr responses for the hidden messages
