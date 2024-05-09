#![cfg_attr(not(feature = "std"), no_std)]

//! Schnorr protocol to prove knowledge of 1 or more discrete logs in zero knowledge.
//! Refer [this](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) for more details of Schnorr protocol.
//!
//! Also implements the proof of knowledge of discrete log in pairing groups, i.e. given prover and verifier
//! both know (`A1`, `Y1`), and prover additionally knows `B1`, prove that `e(A1, B1) = Y1`. Similarly,
//! proving `e(A2, B2) = Y2` when only prover knows `A2` but both know (`B2`, `Y2`). See [`discrete_log_pairing`].
//!
//! Also implements the proof of **inequality of discrete log** (a value committed in a Pedersen commitment),
//! either with a public value or with another discrete log in [`Inequality`]. eg. Given a message `m`,
//! its commitment `C = g * m + h * r` and a public value `v`, proving that `m` ≠ `v`. Or given 2 messages
//! `m1` and `m2` and their commitments `C1 = g * m1 + h * r1` and `C2 = g * m2 + h * r2`, proving `m1` ≠ `m2`
//!
//! Also implements the proof of **inequality of discrete log** when only one of the discrete log is known to
//! the prover. i.e. given `y = g * x` and `z = h * k`, prover and verifier know `g`, `h`, `y` and `z` and
//! prover additionally knows `x` but not `k`.
//!
//! We outline the steps of Schnorr protocol.
//! Prover wants to prove knowledge of `x` in `y = g * x` (`y` and `g` are public knowledge)
//! **Step 1**: Prover generates randomness `r`, and sends `t = g * r` to Verifier.
//! **Step 2**: Verifier generates random challenge `c` and send to Prover.
//! **Step 3**: Prover produces `s = r + x*c`, and sends s to Verifier.
//! **Step 4**: Verifier checks that `g * s = (y * c) + t`.
//!
//! For proving knowledge of multiple messages like `x_1` and `x_2` in `y = g_1*x_1 + g_2*x_2`:
//! **Step 1**: Prover generates randomness `r_1` and `r_2`, and sends `t = g_1*r_1 + g_2*r_2` to Verifier
//! **Step 2**: Verifier generates random challenge `c` and send to Prover
//! **Step 3**: Prover produces `s_1 = r_1 + x_1*c` and `s_2 = r_2 + x_2*c`, and sends `s_1` and `s_2` to Verifier
//! **Step 4**: Verifier checks that `g_1*s_1 + g_2*s_2 = y*c + t`
//!
//! Above can be generalized to more than 2 `x`s
//!
//! There is another variant of Schnorr which gives shorter proof but is not implemented:
//! 1. Prover creates `r` and then `T = r * G`.
//! 2. Prover computes challenge as `c = Hash(G||Y||T)`.
//! 3. Prover creates response `s = r + c*x` and sends `c` and `s` to the Verifier as proof.
//! 4. Verifier creates `T'` as `T' = s * G - c * Y` and computes `c'` as `c' = Hash(G||Y||T')`
//! 5. Proof if valid if `c == c'`
//!
//! The problem with this variant is that it leads to poorer failure reporting as in case of failure, it can't be
//! pointed out which relation failed to verify. Eg. say there are 2 relations being proven which leads to 2
//! `T`s `T1` and `T2` and 2 responses `s1` and `s2`. If only the responses and challenge are sent then
//! in case of failure, the verifier will only know that its computed challenge `c'` doesn't match prover's given
//! challenge `c` but won't know which response `s1` or `s2` or both were incorrect. This is not the case
//! with the implemented variant as verifier checks 2 equations `s1 = r1 + x1*c` and `s2 = r2 + x2*c`
//!
//!
//! [`Inequality`]: crate::inequality
//! [`discrete_log_pairing`]: crate::discrete_log_pairing

use crate::error::SchnorrError;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, fmt::Debug, io::Write, ops::Add, vec::Vec};
use digest::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

use dock_crypto_utils::serde_utils::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use dock_crypto_utils::expect_equality;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub mod discrete_log;
pub mod discrete_log_pairing;
pub mod error;
pub mod inequality;

/// Trait implemented by Schnorr-based protocols for returning their contribution to the overall challenge.
/// i.e. overall challenge is of form Hash({m_i}), and this function returns the bytecode for m_j for some j.
pub trait SchnorrChallengeContributor {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SchnorrError>;
}

/// Commitment to randomness during step 1 of the Schnorr protocol to prove knowledge of 1 or more discrete logs
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct SchnorrCommitment<G: AffineRepr> {
    /// Randomness. 1 per discrete log
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub blindings: Vec<G::ScalarField>,
    /// The commitment to all the randomnesses, i.e. `bases[0] * blindings[0] + ... + bases[i] * blindings[i]`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
}

impl<G> SchnorrCommitment<G>
where
    G: AffineRepr,
{
    /// Create commitment as `bases[0] * blindings[0] + bases[1] * blindings[1] + ... + bases[i] * blindings[i]`
    /// for step-1 of the protocol. Extra `bases` or `blindings` are ignored.
    pub fn new(bases: &[G], blindings: Vec<G::ScalarField>) -> Self {
        let t = G::Group::msm_unchecked(bases, &blindings).into_affine();
        Self { blindings, t }
    }

    /// Create responses for each witness (discrete log) as `response[i] = self.blindings[i] + (witnesses[i] * challenge)`
    pub fn response(
        &self,
        witnesses: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> Result<SchnorrResponse<G>, SchnorrError> {
        expect_equality!(
            self.blindings.len(),
            witnesses.len(),
            SchnorrError::ExpectedSameSizeSequences
        );
        let responses = cfg_iter!(self.blindings)
            .zip(cfg_iter!(witnesses))
            .map(|(b, w)| *b + (*w * *challenge))
            .collect::<Vec<_>>();
        Ok(SchnorrResponse(responses))
    }
}

impl<G> SchnorrChallengeContributor for SchnorrCommitment<G>
where
    G: AffineRepr,
{
    /// The commitment's contribution to the overall challenge of the protocol, i.e. overall challenge is
    /// of form Hash({m_i}), and this function returns the bytecode for m_j for some j. Note that
    /// it does not include the bases or the commitment (`g_i`  and `y` in `{g_i} * {x_i} = y`) and
    /// they must be part of the challenge.
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SchnorrError> {
        self.t.serialize_compressed(writer).map_err(|e| e.into())
    }
}

/// Response during step 3 of the Schnorr protocol to prove knowledge of 1 or more discrete logs
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SchnorrResponse<G: AffineRepr>(
    #[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<G::ScalarField>,
);

impl<G> SchnorrResponse<G>
where
    G: AffineRepr,
{
    /// Check if response is valid and thus validity of Schnorr proof
    /// `bases[0]*responses[0] + bases[0]*responses[0] + ... + bases[i]*responses[i] - y*challenge == t`
    pub fn is_valid(
        &self,
        bases: &[G],
        y: &G,
        t: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), SchnorrError> {
        expect_equality!(
            self.0.len(),
            bases.len(),
            SchnorrError::ExpectedSameSizeSequences
        );
        if (G::Group::msm_unchecked(bases, &self.0).add(y.mul_bigint((-*challenge).into_bigint())))
            .into_affine()
            == *t
        {
            Ok(())
        } else {
            Err(SchnorrError::InvalidResponse)
        }
    }

    /// Get response for the specified discrete log
    pub fn get_response(&self, idx: usize) -> Result<&G::ScalarField, SchnorrError> {
        if idx >= self.0.len() {
            Err(SchnorrError::IndexOutOfBounds(idx, self.0.len()))
        } else {
            Ok(&self.0[idx])
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    // TODO: Add function for challenge contribution (bytes that are hashed)
}

/// Uses try-and-increment. Vulnerable to side channel attacks.
pub fn compute_random_oracle_challenge<F: PrimeField, D: Digest>(challenge_bytes: &[u8]) -> F {
    field_elem_from_try_and_incr::<F, D>(challenge_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, VariableBaseMSM};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[macro_export]
    macro_rules! test_serialization {
        ($obj_type:ty, $obj: ident) => {
            // Test ark serialization
            let mut serz = vec![];
            ark_serialize::CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
            let deserz: $obj_type =
                ark_serialize::CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            let mut serz = vec![];
            $obj.serialize_compressed(&mut serz).unwrap();
            let deserz: $obj_type =
                CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
            assert_eq!(deserz, $obj);

            // Test JSON serialization with serde
            let obj_ser = serde_json::to_string(&$obj).unwrap();
            let obj_deser = serde_json::from_str::<$obj_type>(&obj_ser).unwrap();
            assert_eq!($obj, obj_deser);

            // Test Message Pack serialization
            let ser = rmp_serde::to_vec_named(&$obj).unwrap();
            let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
            assert_eq!($obj, deser);
        };
    }

    macro_rules! test_schnorr_in_group {
        ( $group_element_proj:ident, $group_element_affine:ident ) => {
            let mut rng = StdRng::seed_from_u64(0u64);
            let count = 10;
            let bases = (0..count)
                .into_iter()
                .map(|_| <Bls12_381 as Pairing>::$group_element_proj::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let witnesses = (0..count)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            let y =
                <<Bls12_381 as Pairing>::$group_element_proj>::msm_unchecked(&bases, &witnesses)
                    .into_affine();

            let blindings = (0..count)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            let comm = SchnorrCommitment::new(&bases, blindings);
            test_serialization!(
                SchnorrCommitment<<Bls12_381 as Pairing>::$group_element_affine>,
                comm
            );

            let challenge = Fr::rand(&mut rng);

            let resp = comm.response(&witnesses, &challenge).unwrap();

            resp.is_valid(&bases, &y, &comm.t, &challenge).unwrap();

            drop(comm);

            test_serialization!(
                SchnorrResponse<<Bls12_381 as Pairing>::$group_element_affine>,
                resp
            );
        };
    }

    #[test]
    fn schnorr_vector() {
        test_schnorr_in_group!(G1, G1Affine);
        test_schnorr_in_group!(G2, G2Affine);
    }
}
