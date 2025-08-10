//! Protocol between the user and signer to create blinded tokens in half-offline (HOL) mode. Follows protocol in
//! Fig. 8 but this supports batching

use super::setup::{MACParams, SecretKey, SignerPublicKey, UserPublicKey};
use crate::{bbs_sharp::mac::MAC, error::KVACError};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand, Zero};
use core::mem;
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{msm::WindowTable, signature::MultiMessageSignatureParams};
use schnorr_pok::compute_random_oracle_challenge;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Instance of the protocol run by signer in HOL mode
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HOLSignerProtocol<G: AffineRepr>(
    /// Contains whats called `s` in the paper. One `s` for each token
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    Vec<G::ScalarField>,
);

/// Instance of the protocol run by user in HOL mode
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HOLUserProtocol<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    A_hat: Vec<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    B_bar: Vec<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    D: Vec<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    r1: Vec<G::ScalarField>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    r3: Vec<G::ScalarField>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    l: Vec<G::ScalarField>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    minus_e: G::ScalarField,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    u: Vec<G::ScalarField>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    v: Vec<G::ScalarField>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<Vec<ArkObjectBytes>>"))]
    c: Option<Vec<G::ScalarField>>,
}

/// Sent by the signer to the user and user uses it to create the challenge
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PreChallengeData<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    A_0: Vec<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    B_0: Vec<G>,
}

/// Sent by the user to the signer and signer uses it to create the response
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlindedChallenges<F: PrimeField>(
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] Vec<F>,
);

/// Sent by the signer to the user
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Responses<F: PrimeField>(
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] Vec<F>,
);

/// Called pi_EQ in the paper
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofOfValidity<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_hat: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_bar: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub c: G::ScalarField,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub r: G::ScalarField,
}

/// Private data of the user when it requests a proof of validity of the keyed-proof, i.e. `(A_hat * sk = B_bar)`
/// This is later used to create the proof of knowledge.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TokenPrivateData<G: AffineRepr> {
    /// `D = B * r2`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub D: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub r1: G::ScalarField,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub r3: G::ScalarField,
    // Following will remain same in all tokens so could be avoided here.
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub minus_e: G::ScalarField,
}

impl<G: AffineRepr> HOLUserProtocol<G> {
    /// `num_tokens` denotes the number of tokens to request and each token can be used to create one proof of knowledge.
    pub fn init<R: RngCore>(
        rng: &mut R,
        num_tokens: usize,
        mac: &MAC<G>,
        messages: &[G::ScalarField],
        user_public_key: &UserPublicKey<G>,
        params: &MACParams<G>,
    ) -> Result<Self, KVACError> {
        assert_eq!(params.supported_message_count(), messages.len());
        let mut u = vec![];
        for _ in 0..num_tokens {
            // u needs to be invertible
            let mut u_i = G::ScalarField::rand(rng);
            while u_i.is_zero() {
                u_i = G::ScalarField::rand(rng);
            }
            u.push(u_i);
        }
        let v = (0..num_tokens)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let minus_e = -mac.e;
        // B = (e+x) * A = g_0 + user_pk + \sum(g_vec_i*m_i) for all i in I
        let B = params.b(messages.iter().enumerate(), &user_public_key)?;
        let A_table = WindowTable::new(num_tokens, mac.A.into_group());
        let B_table = WindowTable::new(num_tokens, B);
        let mut A_hat = vec![];
        let mut B_bar = vec![];
        let mut D = vec![];
        let mut r1_vec = vec![];
        let mut r3_vec = vec![];
        let mut l = vec![];
        for _ in 0..num_tokens {
            let r1 = G::ScalarField::rand(rng);
            let mut r2 = G::ScalarField::rand(rng);
            while r2.is_zero() {
                r2 = G::ScalarField::rand(rng);
            }
            let r3 = r2.inverse().unwrap();

            let l_i = r1 * r2;
            // A_hat = A * r1 * r2
            let A_hat_i = (A_table.multiply(&l_i)).into_affine();
            // D = B * r2
            let D_i = B_table.multiply(&r2).into_affine();
            // D * r1 = B * r2 * r1
            // A_hat = A * r1 * r2
            // B_bar = D * r1 - A_hat * e = B * r2 * r1 - A * r1 * r2 * e
            let B_bar_i =
                (B_table.multiply(&l_i) + A_table.multiply(&(l_i * minus_e))).into_affine();
            A_hat.push(A_hat_i);
            B_bar.push(B_bar_i);
            D.push(D_i);
            r1_vec.push(r1);
            r3_vec.push(r3);
            l.push(l_i);
        }
        Ok(Self {
            A_hat,
            B_bar,
            D,
            minus_e,
            r1: r1_vec,
            r3: r3_vec,
            l,
            u,
            v,
            c: None,
        })
    }

    /// User computes the challenge. If the verifier(s) gave any nonces, then `nonces` won't be None
    /// and there will be one nonce per token. The nonce is what's called `m_DAB` in the paper.
    pub fn compute_challenge<D: Digest>(
        &mut self,
        pre_chal: PreChallengeData<G>,
        params: &MACParams<G>,
        nonces: Option<Vec<&[u8]>>,
    ) -> BlindedChallenges<G::ScalarField> {
        let num_tokens = self.A_hat.len();
        let nonces = if let Some(n) = nonces {
            assert_eq!(n.len(), num_tokens);
            n
        } else {
            vec![]
        };
        assert_eq!(pre_chal.A_0.len(), num_tokens);
        assert_eq!(pre_chal.A_0.len(), pre_chal.B_0.len());
        let g_table = WindowTable::new(num_tokens, params.g_tilde.into_group());
        let mut c = vec![];
        let mut c_0 = vec![];
        let PreChallengeData { A_0, B_0 } = pre_chal;
        for (i, (A_0_i, B_0_i)) in A_0.into_iter().zip(B_0.into_iter()).enumerate() {
            // u is enforced to be invertible so unwrap is fine
            let u_i_inv = self.u[i].inverse().unwrap();
            // u_i * v_i
            let uv_i = self.u[i] * self.v[i];
            let A_0_umlaut_i = (A_0_i * self.u[i] + g_table.multiply(&uv_i)).into_affine();
            let B_0_umlaut_i =
                (B_0_i * (self.u[i] * self.l[i]) + self.A_hat[i] * uv_i).into_affine();
            let mut challenge_bytes = vec![];
            self.A_hat[i]
                .serialize_compressed(&mut challenge_bytes)
                .unwrap();
            self.B_bar[i]
                .serialize_compressed(&mut challenge_bytes)
                .unwrap();
            A_0_umlaut_i
                .serialize_compressed(&mut challenge_bytes)
                .unwrap();
            B_0_umlaut_i
                .serialize_compressed(&mut challenge_bytes)
                .unwrap();
            if !nonces.is_empty() {
                challenge_bytes.extend_from_slice(&nonces[i]);
            }
            let c_i = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
            let c_0_i = c_i * u_i_inv;
            c.push(c_i);
            c_0.push(c_0_i);
        }
        self.c = Some(c);
        BlindedChallenges(c_0)
    }

    pub fn process_response(
        mut self,
        response: Responses<G::ScalarField>,
    ) -> (Vec<TokenPrivateData<G>>, Vec<ProofOfValidity<G>>) {
        assert_eq!(self.A_hat.len(), response.0.len());
        let c = mem::take(&mut self.c).unwrap();
        let v = mem::take(&mut self.v);
        let u = mem::take(&mut self.u);
        let A_hat = mem::take(&mut self.A_hat);
        let B_bar = mem::take(&mut self.B_bar);
        let D = mem::take(&mut self.D);
        let minus_e = mem::take(&mut self.minus_e);
        let r1 = mem::take(&mut self.r1);
        let r3 = mem::take(&mut self.r3);
        // r_i = (r_0_i + v_i) * u_i
        let r = cfg_into_iter!(u)
            .zip(cfg_into_iter!(v))
            .zip(cfg_into_iter!(response.0))
            .map(|((u_i, v_i), r_0_i)| (r_0_i + v_i) * u_i)
            .collect::<Vec<_>>();
        let mut t_pr = vec![];
        let mut pr_v = vec![];
        for i in 0..r.len() {
            t_pr.push(TokenPrivateData {
                D: D[i],
                r1: r1[i],
                r3: r3[i],
                minus_e,
            });
            pr_v.push(ProofOfValidity {
                A_hat: A_hat[i],
                B_bar: B_bar[i],
                c: c[i],
                r: r[i],
            });
        }
        (t_pr, pr_v)
    }
}

impl<G: AffineRepr> HOLSignerProtocol<G> {
    /// Its assumed that signer has authenticated the user and it has the `A` from user's MAC in
    /// its database and the user is eligible to get the token (non-revoked if applicable)
    pub fn init<R: RngCore>(
        rng: &mut R,
        num_tokens: usize,
        A: &G,
        params: &MACParams<G>,
    ) -> (Self, PreChallengeData<G>) {
        let s = (0..num_tokens)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let A_table = WindowTable::new(num_tokens, A.into_group());
        let g_table = WindowTable::new(num_tokens, params.g_tilde.into_group());
        let A_0 = g_table.multiply_many(&s);
        let B_0 = A_table.multiply_many(&s);
        (
            Self(s),
            PreChallengeData {
                A_0: G::Group::normalize_batch(&A_0),
                B_0: G::Group::normalize_batch(&B_0),
            },
        )
    }

    /// Computes `r_0_i = s_i + c_0_i * sk`
    pub fn compute_response(
        mut self,
        mut challenge: BlindedChallenges<G::ScalarField>,
        signer_secret_key: &SecretKey<G::ScalarField>,
    ) -> Responses<G::ScalarField> {
        assert_eq!(self.0.len(), challenge.0.len());
        let s = mem::take(&mut self.0);
        let c = mem::take(&mut challenge.0);
        let r = cfg_into_iter!(c)
            .zip(cfg_into_iter!(s))
            .map(|(c_i, s_i)| s_i + c_i * signer_secret_key.0)
            .collect::<Vec<_>>();
        Responses(r)
    }
}

impl<G: AffineRepr> ProofOfValidity<G> {
    pub fn verify<D: Digest>(
        &self,
        signer_pk: &SignerPublicKey<G>,
        params: &MACParams<G>,
        nonce: Option<&[u8]>,
    ) -> Result<(), KVACError> {
        Self::verify_given_destructured::<D>(
            &self.A_hat,
            &self.B_bar,
            &self.c,
            &self.r,
            &signer_pk.0,
            &params.g_tilde,
            nonce,
        )
    }

    pub fn verify_given_destructured<'a, D: Digest>(
        A_hat: &G,
        B_bar: &G,
        c: &G::ScalarField,
        r: &G::ScalarField,
        pk: impl Into<&'a G>,
        g_tilde: impl Into<&'a G>,
        nonce: Option<&[u8]>,
    ) -> Result<(), KVACError> {
        let g_tilde = g_tilde.into();
        let pk = pk.into();
        let mut challenge_bytes = vec![];
        let minus_c = c.neg();
        A_hat.serialize_compressed(&mut challenge_bytes).unwrap();
        B_bar.serialize_compressed(&mut challenge_bytes).unwrap();
        (*g_tilde * r + *pk * minus_c)
            .into_affine()
            .serialize_compressed(&mut challenge_bytes)
            .unwrap();
        (*A_hat * r + *B_bar * minus_c)
            .into_affine()
            .serialize_compressed(&mut challenge_bytes)
            .unwrap();
        if let Some(n) = nonce {
            challenge_bytes.extend_from_slice(n);
        }
        let computed_challenge =
            compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if computed_challenge != *c {
            return Err(KVACError::InvalidProofOfValidity);
        }
        Ok(())
    }
}
