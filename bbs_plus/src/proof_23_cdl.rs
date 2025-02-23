//! Proof of knowledge of BBS signature and corresponding messages as per Appendix B of the BBS paper with
//! slight modification described below.
//! In section 5.2, the paper requires the prover to prove `e(A_bar, X_2) = e (B_bar, g2)` where `A_bar = A * r` and `B_bar = C(m)*r + A_bar*-e`.
//! The prover sends `A_bar`, `B_bar` to the verifier and also proves the knowledge of `r`, `e` and any
//! messages in `C(m)` in `B_bar`. Here `r` is a random element chosen by the prover on each proof of knowledge.
//! Above approach has a problem when some messages under 2 signatures need to be proven equal in zero
//! knowledge or proving predicates about the messages in zero-knowledge using LegoSnark where the proof
//! contains a Pedersen commitment to witness of the SNARK. Because `r` will be different for each signature,
//! the witnesses for the Schnorr proof will be different, i.e. `m*r` and `m*r'` for the same message `m` and
//! thus the folklore method of proving equal witnesses in multiple statements cant be used. Thus the protocol
//! below uses a similar approach as used in BBS+. The prover in addition to sending `A_bar = A*r1*r2`, `B_bar = (C(m) - A*e)*r1*r2`
//! to the verifier sends `d = C(m)*r2` as well for random `r1`, `r2`. The prover calculates `r3 = 1 / r2` and
//! creates 2 Schnorr proofs for:
//! 1. `B_bar = d * r1 + A_bar * -e`, here `r1` and `-e` is the witness and `B_bar, d, A_bar` are the instance
//! 2. `d * r3 = C(m)`. Here the witnesses are `r3` and any messages part of `C(m)` which the prover is hiding and
//! the instance is `g + \sum_i{h_i*m_i}` for all `m_i` that the prover is revealing.

use crate::{
    error::BBSPlusError,
    prelude::PreparedPublicKeyG2,
    setup::{PreparedSignatureParams23G1, SignatureParams23G1},
    signature_23::Signature23G1,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    io::Write,
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use core::mem;
use dock_crypto_utils::{
    misc::rand,
    randomized_pairing_check::RandomizedPairingChecker,
    serde_utils::*,
    signature::{
        msg_index_map_to_schnorr_response_map, msg_index_to_schnorr_response_index,
        schnorr_responses_to_msg_index_map, split_messages_and_blindings, MessageOrBlinding,
        MultiMessageSignatureParams,
    },
};
use itertools::multiunzip;
use schnorr_pok::{
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
    error::SchnorrError,
    partial::PartialSchnorrResponse,
    SchnorrCommitment, SchnorrResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of BBS signature in group G1.
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PoKOfSignature23G1Protocol<E: Pairing> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub B_bar: E::G1Affine,
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub d: E::G1Affine,
    /// For proving relation `B_bar = d * r1 + A_bar * -e`
    pub sc_comm_1: PokPedersenCommitmentProtocol<E::G1Affine>,
    /// For proving relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + sum_{j notin D}(h_j*m_j)`
    pub sc_comm_2: SchnorrCommitment<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    sc_wits_2: Vec<E::ScalarField>,
}

/// Proof of knowledge of BBS signature in G1. It contains the randomized signature, commitment (Schnorr step 1)
/// and response (Schnorr step 3) to both Schnorr protocols in `T_` and `sc_resp_`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PoKOfSignature23G1Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub B_bar: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub d: E::G1Affine,
    /// Proof of relation `B_bar = d * r3 + A_bar * -e`
    pub sc_resp_1: PokPedersenCommitment<E::G1Affine>,
    /// Proof of relation `g1 + h1*m1 + h2*m2 +.... + h_i*m_i` = `d*r3 + h1*{-m1} + h2*{-m2} + .... + h_j*{-m_j}` for all disclosed messages `m_i` and for all undisclosed messages `m_j`
    #[serde_as(as = "ArkObjectBytes")]
    pub T2: E::G1Affine,
    /// The following could be achieved by using Either<SchnorrResponse, PartialSchnorrResponse> but serialization
    /// for Either is not supported out of the box and had to be implemented
    pub sc_resp_2: Option<SchnorrResponse<E::G1Affine>>,
    pub sc_partial_resp_2: Option<PartialSchnorrResponse<E::G1Affine>>,
}

impl<E: Pairing> PoKOfSignature23G1Protocol<E> {
    /// Initiate the protocol, i.e. pre-challenge phase. This will generate the randomized signature and execute
    /// the commit-to-randomness step (Step 1) of both Schnorr protocols.
    /// Accepts an iterator of messages. Each message can be either randomly blinded, revealed, or blinded using supplied blinding.
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        signature: &Signature23G1<E>,
        params: &SignatureParams23G1<E>,
        messages_and_blindings: MBI,
    ) -> Result<Self, BBSPlusError>
    where
        MBI: IntoIterator<Item = MessageOrBlinding<'a, E::ScalarField>>,
    {
        let (messages, indexed_blindings) =
            match split_messages_and_blindings(rng, messages_and_blindings, params) {
                Ok(t) => t,
                Err(l) => {
                    return Err(BBSPlusError::MessageCountIncompatibleWithSigParams(
                        l,
                        params.supported_message_count(),
                    ))
                }
            };

        let r1 = E::ScalarField::rand(rng);
        let mut r2 = E::ScalarField::rand(rng);
        while r2.is_zero() {
            r2 = E::ScalarField::rand(rng);
        }
        // r3 = 1/r2
        let r3 = r2.inverse().unwrap();

        // b = (e+x) * A = g1 + sum(h_i*m_i) for all i in I. Called C(m) in the paper
        let b = params.b(messages.iter().enumerate())?;
        // d = b * r2
        let d = b * r2;
        // A_bar = A * r1 * r2
        let A_bar = signature.A * (r1 * r2);
        let A_bar_affine = A_bar.into_affine();
        // B_bar = d * r1 - e * A_bar
        let B_bar = d * r1 - (A_bar * signature.e);
        let d_affine = d.into_affine();

        // Following is the 1st step of the Schnorr protocol for the relation pi in the paper. pi is a
        // conjunction of 2 relations:
        // 1. `B_bar == d * r1 + A_bar*{-e}`
        // 2. `g1 + \sum_{i \in D}(h_i*m_i)` == `d*r3 + \sum_{j \notin D}(h_j*{-m_j})`
        // for all disclosed messages `m_i` and for all undisclosed messages `m_j`.
        // For each of the above relations, a Schnorr protocol is executed; the first to prove knowledge
        // of `(e, r1)`, and the second of `(r2, {m_j}_{j \notin D})`. The secret knowledge items are
        // referred to as witnesses, and the public items as instances.

        let sc_comm_1 = PokPedersenCommitmentProtocol::init(
            -signature.e,
            E::ScalarField::rand(rng),
            &A_bar_affine,
            r1,
            E::ScalarField::rand(rng),
            &d_affine,
        );

        // For proving relation `g1 + \sum_{i \in D}(h_i*m_i)` = `d*r2 + \sum_{j \notin D}(h_j*{-m_j})`
        // for all disclosed messages `m_i` and for all undisclosed messages `m_j`, usually the number of disclosed
        // messages is much less than the number of undisclosed messages; so it is better to avoid negations in
        // undisclosed messages and do them in disclosed messaged. So negate both sides of the relation to get:
        // `d*{-r2} + \sum_{j \notin D}(h_j*m_j)` = `-g1 + \sum_{i \in D}(h_i*{-m_i})`
        // Moreover `-g1 + \sum_{i \in D}(h_i*{-m_i})` is public and can be efficiently computed as -(g1 + \sum_{i \in D}(h_i*{m_i}))
        // Knowledge of all unrevealed messages `m_j` need to be proven in addition to knowledge of `-r2. Thus
        // all `m_j` and `-r2` are the witnesses, while all `h_j`, `d`, and `-g1 + \sum_{i \in D}(h_i*{-m_i})` is the instance.

        // Iterator of tuples of form `(h_i, blinding_i, message_i)`
        let h_blinding_message = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.h[idx], blinding, messages[idx]));

        let (bases_2, randomness_2, wits_2): (Vec<_>, Vec<_>, Vec<_>) =
            multiunzip(h_blinding_message.chain([(d_affine, rand(rng), -r3)].into_iter()));

        // Commit to randomness, i.e. `bases_2[0]*randomness_2[0] + bases_2[1]*randomness_2[1] + .... bases_2[j]*randomness_2[j]`
        let sc_comm_2 = SchnorrCommitment::new(&bases_2, randomness_2);

        Ok(Self {
            A_bar: A_bar_affine,
            B_bar: B_bar.into_affine(),
            d: d_affine,
            sc_comm_1,
            sc_comm_2,
            sc_wits_2: wits_2,
        })
    }

    /// Get the contribution of this protocol towards the challenge, i.e. bytecode of items that will be hashed
    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParams23G1<E>,
        writer: W,
    ) -> Result<(), BBSPlusError> {
        Self::compute_challenge_contribution(
            &self.A_bar,
            &self.B_bar,
            &self.d,
            &self.sc_comm_1.t,
            &self.sc_comm_2.t,
            revealed_msgs,
            params,
            writer,
        )
    }

    /// Generate proof. Post-challenge phase of the protocol.
    pub fn gen_proof(
        mut self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignature23G1Proof<E>, BBSPlusError> {
        let sc_resp_1 = mem::take(&mut self.sc_comm_1).gen_proof(challenge);

        // Schnorr response for relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + \sum_{j not in D}(h_j*{-m_j})`
        let sc_resp_2 = self.sc_comm_2.response(&self.sc_wits_2, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            d: self.d,
            sc_resp_1,
            T2: self.sc_comm_2.t,
            sc_resp_2: Some(sc_resp_2),
            sc_partial_resp_2: None,
        })
    }

    /// Generate a partial proof, i.e. don't generate responses for message indices in `skip_responses_for` as these will be
    /// generated by some other protocol.
    pub fn gen_partial_proof(
        mut self,
        challenge: &E::ScalarField,
        revealed_msg_ids: &BTreeSet<usize>,
        skip_responses_for: &BTreeSet<usize>,
    ) -> Result<PoKOfSignature23G1Proof<E>, BBSPlusError> {
        if !skip_responses_for.is_disjoint(revealed_msg_ids) {
            return Err(BBSPlusError::CommonIndicesFoundInRevealedAndSkip);
        }
        let sc_resp_1 = mem::take(&mut self.sc_comm_1).gen_proof(challenge);

        let wits = schnorr_responses_to_msg_index_map(
            mem::take(&mut self.sc_wits_2),
            revealed_msg_ids,
            skip_responses_for,
        );
        // Schnorr response for relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + {h_0}*{-s'} + \sum_{j not in D}(h_j*{-m_j})`
        let sc_resp_2 = self.sc_comm_2.partial_response(wits, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            d: self.d,
            sc_resp_1,
            T2: self.sc_comm_2.t,
            sc_resp_2: None,
            sc_partial_resp_2: Some(sc_resp_2),
        })
    }

    /// Helper that serializes state to get challenge contribution. Serialized the randomized signature,
    /// and commitments and instances for both Schnorr protocols
    pub fn compute_challenge_contribution<W: Write>(
        A_bar: &E::G1Affine,
        B_bar: &E::G1Affine,
        d: &E::G1Affine,
        T1: &E::G1Affine,
        T2: &E::G1Affine,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParams23G1<E>,
        mut writer: W,
    ) -> Result<(), BBSPlusError> {
        A_bar.serialize_compressed(&mut writer)?;
        B_bar.serialize_compressed(&mut writer)?;
        d.serialize_compressed(&mut writer)?;
        params.g1.serialize_compressed(&mut writer)?;
        T1.serialize_compressed(&mut writer)?;
        T2.serialize_compressed(&mut writer)?;

        for i in 0..params.h.len() {
            params.h[i].serialize_compressed(&mut writer)?;
            if let Some(m) = revealed_msgs.get(&i) {
                m.serialize_compressed(&mut writer)?;
            }
        }
        Ok(())
    }
}

impl<E: Pairing> PoKOfSignature23G1Proof<E> {
    /// Verify if the proof is valid. Assumes that the public key and parameters have been
    /// validated already.
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
    ) -> Result<(), BBSPlusError> {
        self._verify(revealed_msgs, challenge, pk, params, None)
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), BBSPlusError> {
        self._verify_with_randomized_pairing_checker(
            revealed_msgs,
            challenge,
            pk,
            params,
            pairing_checker,
            None,
        )
    }

    /// Similar to `Self::verify` but responses for some messages (witnesses) are provided in `missing_responses`.
    /// The keys of the map are message indices.
    pub fn verify_partial(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        missing_responses: BTreeMap<usize, E::ScalarField>,
    ) -> Result<(), BBSPlusError> {
        self._verify(
            revealed_msgs,
            challenge,
            pk,
            params,
            Some(missing_responses),
        )
    }

    /// Similar to `Self::verify_with_randomized_pairing_checker` but responses for some messages (witnesses) are provided in `missing_responses`.
    /// The keys of the map are message indices.
    pub fn verify_partial_with_randomized_pairing_checker(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
        missing_responses: BTreeMap<usize, E::ScalarField>,
    ) -> Result<(), BBSPlusError> {
        self._verify_with_randomized_pairing_checker(
            revealed_msgs,
            challenge,
            pk,
            params,
            pairing_checker,
            Some(missing_responses),
        )
    }

    pub fn get_responses(
        &self,
        msg_ids: &BTreeSet<usize>,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<BTreeMap<usize, E::ScalarField>, BBSPlusError> {
        let mut resps = BTreeMap::new();
        for msg_idx in msg_ids {
            resps.insert(
                *msg_idx,
                *self.get_resp_for_message(*msg_idx, revealed_msg_ids)?,
            );
        }
        Ok(resps)
    }

    /// For the verifier to independently calculate the challenge
    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParams23G1<E>,
        writer: W,
    ) -> Result<(), BBSPlusError> {
        PoKOfSignature23G1Protocol::compute_challenge_contribution(
            &self.A_bar,
            &self.B_bar,
            &self.d,
            &self.sc_resp_1.t,
            &self.T2,
            revealed_msgs,
            params,
            writer,
        )
    }

    /// Get the response from post-challenge phase of the Schnorr protocol for the given message index
    /// `msg_idx`. Used when comparing message equality
    pub fn get_resp_for_message(
        &self,
        msg_idx: usize,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<&E::ScalarField, BBSPlusError> {
        let adjusted_idx = msg_index_to_schnorr_response_index(msg_idx, revealed_msg_ids)
            .ok_or_else(|| BBSPlusError::InvalidMsgIdxForResponse(msg_idx))?;
        if let Some(resp) = self.sc_resp_2.as_ref() {
            Ok(resp.get_response(adjusted_idx)?)
        } else if let Some(resp) = self.sc_partial_resp_2.as_ref() {
            Ok(resp.get_response(adjusted_idx)?)
        } else {
            Err(BBSPlusError::NeedEitherPartialOrCompleteSchnorrResponse)
        }
    }

    pub fn _verify(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        missing_responses: Option<BTreeMap<usize, E::ScalarField>>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h, missing_responses)?;

        // Verify the randomized signature
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.A_bar),
                E::G1Prepared::from(-(self.B_bar.into_group())),
            ],
            [pk.into().0, g2],
        )
        .is_zero()
        {
            return Err(BBSPlusError::PairingCheckFailed);
        }
        Ok(())
    }

    pub fn _verify_with_randomized_pairing_checker(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
        missing_responses: Option<BTreeMap<usize, E::ScalarField>>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h, missing_responses)?;
        pairing_checker.add_sources(&self.A_bar, pk.into().0, &self.B_bar, g2);
        Ok(())
    }

    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h: Vec<E::G1Affine>,
        missing_responses: Option<BTreeMap<usize, E::ScalarField>>,
    ) -> Result<(), BBSPlusError> {
        // Verify the 1st Schnorr proof
        if !self
            .sc_resp_1
            .verify(&self.B_bar, &self.A_bar, &self.d, challenge)
        {
            return Err(BBSPlusError::FirstSchnorrVerificationFailed);
        }

        // Verify the 2nd Schnorr proof
        let mut bases_2 = Vec::with_capacity(1 + h.len() - revealed_msgs.len());

        let mut bases_revealed = Vec::with_capacity(revealed_msgs.len());
        let mut exponents = Vec::with_capacity(revealed_msgs.len());
        for i in 0..h.len() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_revealed.push(h[i]);
                exponents.push(*message);
            } else {
                bases_2.push(h[i]);
            }
        }
        bases_2.push(self.d);
        // pr = -g1 + \sum_{i in D}(h_i*{-m_i}) = -(g1 + \sum_{i in D}(h_i*{m_i}))
        let pr = -E::G1::msm_unchecked(&bases_revealed, &exponents) - g1;
        let pr = pr.into_affine();
        if let Some(resp) = &self.sc_resp_2 {
            if missing_responses.is_some() {
                return Err(BBSPlusError::MissingResponsesProvidedForFullSchnorrProofVerification);
            }
            return match resp.is_valid(&bases_2, &pr, &self.T2, challenge) {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => {
                    Err(BBSPlusError::SecondSchnorrVerificationFailed)
                }
                Err(other) => Err(BBSPlusError::SchnorrError(other)),
            };
        } else if let Some(resp) = &self.sc_partial_resp_2 {
            if missing_responses.is_none() {
                return Err(BBSPlusError::MissingResponsesNeededForPartialSchnorrProofVerification);
            }
            let adjusted_missing = msg_index_map_to_schnorr_response_map(
                missing_responses.unwrap(),
                revealed_msgs.keys(),
            );
            return match resp.is_valid(&bases_2, &pr, &self.T2, challenge, adjusted_missing) {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => {
                    Err(BBSPlusError::SecondSchnorrVerificationFailed)
                }
                Err(other) => Err(BBSPlusError::SchnorrError(other)),
            };
        } else {
            Err(BBSPlusError::NeedEitherPartialOrCompleteSchnorrResponse)
        }
    }

    /// Verify the proof except the pairing equations. This is useful when doing several verifications (of this
    /// protocol or others) and the pairing equations are combined in a randomized pairing check.
    fn verify_except_pairings(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h: Vec<E::G1Affine>,
        missing_responses: Option<BTreeMap<usize, E::ScalarField>>,
    ) -> Result<(), BBSPlusError> {
        if self.A_bar.is_zero() {
            return Err(BBSPlusError::ZeroSignature);
        }
        self.verify_schnorr_proofs(revealed_msgs, challenge, g1, h, missing_responses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gen_test_PoK_multiple_sigs_with_randomized_pairing_check,
        gen_test_PoK_multiple_sigs_with_same_msg, gen_test_pok_signature_revealed_message,
        gen_test_pok_signature_schnorr_response, proof_23::tests::sig_setup, setup::KeypairG2,
        test_serialization,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_serialize::CanonicalDeserialize;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    #[test]
    fn pok_signature_revealed_message() {
        gen_test_pok_signature_revealed_message!(
            PoKOfSignature23G1Protocol,
            PoKOfSignature23G1Proof
        )
    }

    #[test]
    fn test_PoK_multiple_sigs_with_same_msg() {
        gen_test_PoK_multiple_sigs_with_same_msg!(
            SignatureParams23G1,
            Signature23G1,
            generate_using_rng_and_bbs23_params,
            PoKOfSignature23G1Protocol
        )
    }

    #[test]
    fn pok_signature_schnorr_response() {
        gen_test_pok_signature_schnorr_response!(sig_setup, PoKOfSignature23G1Protocol, sc_resp_2);
    }

    #[test]
    fn test_PoK_multiple_sigs_with_randomized_pairing_check() {
        gen_test_PoK_multiple_sigs_with_randomized_pairing_check!(
            SignatureParams23G1,
            PreparedSignatureParams23G1,
            Signature23G1,
            generate_using_rng_and_bbs23_params,
            PoKOfSignature23G1Protocol
        )
    }
}
