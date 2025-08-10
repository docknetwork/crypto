//! Proof of knowledge of BBS signature and corresponding messages using the protocol described in Appendix A
//! of the paper. This protocol is used by the [BBS IETF draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/) in
//! sections 3.6.3, 3.6.4, 3.7. The difference with the IETF draft is that this does not assume the mandatory message called
//! "signature domain". The protocol works as follows
//! - Randomize the signature as `A_bar = A * r` and `B_bar = C(m) * r - A_bar * e`. Here `C(m)` is the commitment to the messages.
//! - Now it needs to be proven that `C(m) = B_bar * 1/r + A_bar * e * 1/r`
//! - If the revealed messages are `m_i` and unrevealed are `m_j` and the set of revealed message indices is `D`, then the
//! above relation becomes `g + \sum_{i \in D}{h_i * m_i} + \sum_{j \notin D}{h_j * m_j} = B_bar * 1/r + A_bar * e * 1/r`
//! - Above can be rewritten as `\sum_{j \notin D}{h_j * m_j} - B_bar * 1/r - A_bar * e * 1/r = g + \sum_{i \in D}{h_i * m_i}`. `g + \sum_{i \in D}{h_i * m_i}` will be known to the verifier.
//! - Note that I prove knowledge of `m_j` and not `-m_j` as shown in the paper as these might need to be proved equal to other values in
//! other protocols

use crate::{
    error::BBSPlusError,
    prelude::{
        PreparedPublicKeyG2, PreparedSignatureParams23G1, Signature23G1, SignatureParams23G1,
    },
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
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::*;
use dock_crypto_utils::{
    misc::rand,
    randomized_pairing_check::RandomizedPairingChecker,
    signature::{
        msg_index_map_to_schnorr_response_map, msg_index_to_schnorr_response_index,
        schnorr_responses_to_msg_index_map, split_messages_and_blindings, MessageOrBlinding,
        MultiMessageSignatureParams,
    },
};
use itertools::multiunzip;
use schnorr_pok::{
    error::SchnorrError, partial::PartialSchnorrResponse, SchnorrCommitment, SchnorrResponse,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of BBS signature in group G1.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoKOfSignature23G1Protocol<E: Pairing> {
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_bar: E::G1Affine,
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_bar: E::G1Affine,
    /// For proving relation `\sum_{j \notin D}{h_j * m_j} - B_bar * 1/r - A_bar * e * 1/r = g + \sum_{i \in D}{h_i * m_i}`
    pub sc_comm: SchnorrCommitment<E::G1Affine>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    sc_wits: Vec<E::ScalarField>,
}

/// Proof of knowledge of BBS signature in G1. It contains the randomized signature, commitment (Schnorr step 1)
/// and response (Schnorr step 3) to both Schnorr protocols in `T` and `sc_resp`
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoKOfSignature23G1Proof<E: Pairing> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_bar: E::G1Affine,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_bar: E::G1Affine,
    /// Proof of relation `\sum_{j \notin D}{h_j * m_j} - B_bar * 1/r - A_bar * e * 1/r = g + \sum_{i \in D}{h_i * m_i}`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub T: E::G1Affine,
    /// The following could be achieved by using Either<SchnorrResponse, PartialSchnorrResponse> but serialization
    /// for Either is not supported out of the box and had to be implemented
    pub sc_resp: Option<SchnorrResponse<E::G1Affine>>,
    pub sc_partial_resp: Option<PartialSchnorrResponse<E::G1Affine>>,
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

        let r = E::ScalarField::rand(rng);
        // -1/r
        let minus_r_inv = -r.inverse().unwrap();
        // -1/r * e
        let minus_r_inv_e = minus_r_inv * signature.e;

        // b = (e+x) * A = g1 + sum(h_i*m_i) for all i in I. Called C(m) in the paper
        let b = params.b(messages.iter().enumerate())?;

        // A_bar = A * r
        let A_bar = signature.A * r;
        // B_bar = b * r - e * A_bar
        let B_bar = b * r - (A_bar * signature.e);
        let A_bar_affine = A_bar.into_affine();
        let B_bar_affine = B_bar.into_affine();

        // Iterator of tuples of form `(h_i, blinding_i, message_i)`
        let h_blinding_message = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.h[idx], blinding, messages[idx]));

        // Following is the 1st step of the Schnorr protocol for the relation
        // 2. `\sum_{j \notin D}{h_j * m_j} - B_bar * 1/r - A_bar * e * 1/r = g + \sum_{i \in D}{h_i * m_i}`
        // for all disclosed messages `m_i` and for all undisclosed messages `m_j`.
        let (bases, randomness, sc_wits): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            h_blinding_message.chain(
                [
                    (A_bar_affine, rand(rng), minus_r_inv_e),
                    (B_bar_affine, rand(rng), minus_r_inv),
                ]
                .into_iter(),
            ),
        );
        let sc_comm = SchnorrCommitment::new(&bases, randomness);
        Ok(Self {
            A_bar: A_bar_affine,
            B_bar: B_bar_affine,
            sc_comm,
            sc_wits,
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
            &self.sc_comm.t,
            revealed_msgs,
            params,
            writer,
        )
    }

    /// Generate proof. Post-challenge phase of the protocol.
    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignature23G1Proof<E>, BBSPlusError> {
        let sc_resp = self.sc_comm.response(&self.sc_wits, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            T: self.sc_comm.t,
            sc_resp: Some(sc_resp),
            sc_partial_resp: None,
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
        let wits = schnorr_responses_to_msg_index_map(
            mem::take(&mut self.sc_wits),
            revealed_msg_ids,
            skip_responses_for,
        );
        let sc_resp = self.sc_comm.partial_response(wits, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            T: self.sc_comm.t,
            sc_resp: None,
            sc_partial_resp: Some(sc_resp),
        })
    }

    /// Helper that serializes state to get challenge contribution. Serialized the randomized signature,
    /// and commitments and instances for both Schnorr protocols
    pub fn compute_challenge_contribution<W: Write>(
        A_bar: &E::G1Affine,
        B_bar: &E::G1Affine,
        T: &E::G1Affine,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParams23G1<E>,
        mut writer: W,
    ) -> Result<(), BBSPlusError> {
        A_bar.serialize_compressed(&mut writer)?;
        B_bar.serialize_compressed(&mut writer)?;
        params.g1.serialize_compressed(&mut writer)?;
        T.serialize_compressed(&mut writer)?;

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

    /// Get the response from post-challenge phase of the Schnorr protocol for the given message index
    /// `msg_idx`. Used when comparing message equality
    pub fn get_resp_for_message(
        &self,
        msg_idx: usize,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<&E::ScalarField, BBSPlusError> {
        let adjusted_idx = msg_index_to_schnorr_response_index(msg_idx, revealed_msg_ids)
            .ok_or_else(|| BBSPlusError::InvalidMsgIdxForResponse(msg_idx))?;
        if let Some(resp) = self.sc_resp.as_ref() {
            Ok(resp.get_response(adjusted_idx)?)
        } else if let Some(resp) = self.sc_partial_resp.as_ref() {
            return Ok(resp.get_response(adjusted_idx)?);
        } else {
            Err(BBSPlusError::NeedEitherPartialOrCompleteSchnorrResponse)
        }
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
            &self.T,
            revealed_msgs,
            params,
            writer,
        )
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
        let mut bases = Vec::with_capacity(2 + h.len() - revealed_msgs.len());
        let mut bases_revealed = Vec::with_capacity(revealed_msgs.len());
        let mut exponents = Vec::with_capacity(revealed_msgs.len());
        for i in 0..h.len() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_revealed.push(h[i]);
                exponents.push(*message);
            } else {
                bases.push(h[i]);
            }
        }
        bases.push(self.A_bar);
        bases.push(self.B_bar);
        let pr = -E::G1::msm_unchecked(&bases_revealed, &exponents) - g1;
        let pr = pr.into_affine();
        if let Some(resp) = &self.sc_resp {
            if missing_responses.is_some() {
                return Err(BBSPlusError::MissingResponsesProvidedForFullSchnorrProofVerification);
            }
            return match resp.is_valid(&bases, &pr, &self.T, challenge) {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => {
                    Err(BBSPlusError::SecondSchnorrVerificationFailed)
                }
                Err(other) => Err(BBSPlusError::SchnorrError(other)),
            };
        }
        if let Some(resp) = &self.sc_partial_resp {
            if missing_responses.is_none() {
                return Err(BBSPlusError::MissingResponsesNeededForPartialSchnorrProofVerification);
            }
            let adjusted_missing = msg_index_map_to_schnorr_response_map(
                missing_responses.unwrap(),
                revealed_msgs.keys(),
            );
            return match resp.is_valid(&bases, &pr, &self.T, challenge, adjusted_missing) {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => {
                    Err(BBSPlusError::SecondSchnorrVerificationFailed)
                }
                Err(other) => Err(BBSPlusError::SchnorrError(other)),
            };
        }
        Err(BBSPlusError::NeedEitherPartialOrCompleteSchnorrResponse)
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
    fn test_PoK_multiple_sigs_with_randomized_pairing_check() {
        gen_test_PoK_multiple_sigs_with_randomized_pairing_check!(
            SignatureParams23G1,
            PreparedSignatureParams23G1,
            Signature23G1,
            generate_using_rng_and_bbs23_params,
            PoKOfSignature23G1Protocol
        )
    }

    #[test]
    fn pok_signature_schnorr_response() {
        gen_test_pok_signature_schnorr_response!(sig_setup, PoKOfSignature23G1Protocol, sc_resp);
    }
}
