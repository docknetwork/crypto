//! Protocol to prove knowledge of the MAC. This is adapted from the protocol to prove knowledge of BBS+ signatures as defined
//! in section 4.5 of the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663).
//! The difference is that for BBS+, pairings are used to verify the randomized signature but here the correctness of the randomized
//! signature can be verified by using the secret key. The protocol is described below.
//! Signer's secret key is `y` and the MAC is `(A, e, s)`
//! 1. Prover chooses random `r1, r2` from `Z_p` and `r3 = 1/r1`,
//! 2. Prover randomizes the MAC as `B_0 = A * r1`, `C = B_0 * -e + b * r1`, `s' = s - r2 * r3` where `b = A*(e+y)`. Note that `C = B_0 * y`.
//! 3. Prover creates `d = b * r1 - g * r2`
//! 4. Prover sends `B_0, C, d` to the verifier and proves the knowledge of `-e, r2` in `C - d = B_0 * -e + g * r2`  and `s', r3`
//! and disclosed messages `m_i` for all `i` not in `D`, the set of indices of disclosed messages
//! in `h + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + g*{-s'} + sum_{j notin D}(g_vec_j*m_j)`.
//! 5. Verifier uses the secret key `y` to check `C = B_0 * y` and the proofs of knowledge.

use crate::{
    bbdt_2016::{
        keyed_proof::KeyedProof,
        mac::MAC,
        setup::{MACParams, SecretKey},
    },
    error::KVACError,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use core::mem;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{
    misc::rand,
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
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of a MAC.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoKOfMACProtocol<G: AffineRepr> {
    /// Randomized MAC `B_0 = A * r1`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_0: G,
    /// `C = b * r1 - B_0 * e`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub C: G,
    /// `d = b * r1 - g * r2`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub d: G,
    /// For proving relation `C - d = B_0 * -e + g * r2`
    pub sc_C: PokPedersenCommitmentProtocol<G>,
    /// For proving relation `h + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + g*{-s'} + sum_{j notin D}(g_vec_j*m_j)`
    pub sc_comm_msgs: SchnorrCommitment<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    sc_wits_msgs: Vec<G::ScalarField>,
}

/// Proof of knowledge of a MAC.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKOfMAC<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_0: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub C: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub d: G,
    pub sc_C: PokPedersenCommitment<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub t_msgs: G,
    /// The following could be achieved by using Either<SchnorrResponse, PartialSchnorrResponse> but serialization
    /// for Either is not supported out of the box and had to be implemented
    pub sc_resp_msgs: Option<SchnorrResponse<G>>,
    pub sc_partial_resp_msgs: Option<PartialSchnorrResponse<G>>,
}

impl<G: AffineRepr> PoKOfMACProtocol<G> {
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        mac: &MAC<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
    ) -> Result<Self, KVACError>
    where
        MBI: IntoIterator<Item = MessageOrBlinding<'a, G::ScalarField>>,
    {
        let (messages, indexed_blindings) =
            match split_messages_and_blindings(rng, messages_and_blindings, params) {
                Ok(t) => t,
                Err(l) => {
                    return Err(KVACError::MessageCountIncompatibleWithMACParams(
                        l,
                        params.supported_message_count(),
                    ))
                }
            };

        let mut r1 = G::ScalarField::rand(rng);
        while r1.is_zero() {
            r1 = G::ScalarField::rand(rng);
        }
        let r2 = G::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        let minus_e = -mac.e;
        // s' = s - r2*r3
        let s_prime = mac.s - (r2 * r3);

        let B_0 = mac.A * r1;
        let B_0_affine = B_0.into_affine();
        // b = (e+x) * A = h + g*s + sum(g_vec_i*m_i) for all i in I
        let b = params.b(messages.iter().enumerate(), &mac.s)?;
        let b_r1 = b * r1;

        let C = b_r1 + B_0 * minus_e;
        let d = b_r1 - params.g * r2;
        let d_affine = d.into();

        let sc_C = PokPedersenCommitmentProtocol::init(
            minus_e,
            G::ScalarField::rand(rng),
            &B_0_affine,
            r2,
            G::ScalarField::rand(rng),
            &params.g,
        );

        // Iterator of tuples of form `(g_vec_i, blinding_i, message_i)`
        let msg_comm_iter = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.g_vec[idx], blinding, messages[idx]));
        let (bases, randomness, sc_wits_msgs): (Vec<_>, Vec<_>, Vec<_>) =
            multiunzip(msg_comm_iter.chain([
                (d_affine, G::ScalarField::rand(rng), -r3),
                (params.g, rand(rng), s_prime),
            ]));
        let sc_comm_msgs = SchnorrCommitment::new(&bases, randomness);
        Ok(Self {
            B_0: B_0_affine,
            C: C.into(),
            d: d_affine,
            sc_C,
            sc_comm_msgs,
            sc_wits_msgs,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        writer: W,
    ) -> Result<(), KVACError> {
        Self::compute_challenge_contribution(
            &self.B_0,
            &self.C,
            &self.d,
            &self.sc_C.t,
            &self.sc_comm_msgs.t,
            revealed_msgs,
            params,
            writer,
        )
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> Result<PoKOfMAC<G>, KVACError> {
        let sc_C = mem::take(&mut self.sc_C).gen_proof(challenge);
        let sc_resp_msgs = self.sc_comm_msgs.response(&self.sc_wits_msgs, challenge)?;
        Ok(PoKOfMAC {
            B_0: self.B_0,
            C: self.C,
            d: self.d,
            sc_C,
            t_msgs: self.sc_comm_msgs.t,
            sc_resp_msgs: Some(sc_resp_msgs),
            sc_partial_resp_msgs: None,
        })
    }

    /// Generate a partial proof, i.e. don't generate responses for message indices in `skip_responses_for` as these will be
    /// generated by some other protocol.
    pub fn gen_partial_proof(
        mut self,
        challenge: &G::ScalarField,
        revealed_msg_ids: &BTreeSet<usize>,
        skip_responses_for: &BTreeSet<usize>,
    ) -> Result<PoKOfMAC<G>, KVACError> {
        if !skip_responses_for.is_disjoint(revealed_msg_ids) {
            return Err(KVACError::CommonIndicesFoundInRevealedAndSkip);
        }
        let sc_C = mem::take(&mut self.sc_C).gen_proof(challenge);
        let wits = schnorr_responses_to_msg_index_map(
            mem::take(&mut self.sc_wits_msgs),
            revealed_msg_ids,
            skip_responses_for,
        );
        let sc_resp_msgs = self.sc_comm_msgs.partial_response(wits, challenge)?;
        Ok(PoKOfMAC {
            B_0: self.B_0,
            C: self.C,
            d: self.d,
            sc_C,
            t_msgs: self.sc_comm_msgs.t,
            sc_resp_msgs: None,
            sc_partial_resp_msgs: Some(sc_resp_msgs),
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        B_0: &G,
        C: &G,
        d: &G,
        t_C: &G,
        t_msgs: &G,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        mut writer: W,
    ) -> Result<(), KVACError> {
        B_0.serialize_compressed(&mut writer)?;
        C.serialize_compressed(&mut writer)?;
        d.serialize_compressed(&mut writer)?;
        params.h.serialize_compressed(&mut writer)?;
        params.g.serialize_compressed(&mut writer)?;
        t_C.serialize_compressed(&mut writer)?;
        t_msgs.serialize_compressed(&mut writer)?;
        for i in 0..params.g_vec.len() {
            params.g_vec[i].serialize_compressed(&mut writer)?;
            if let Some(m) = revealed_msgs.get(&i) {
                m.serialize_compressed(&mut writer)?;
            }
        }
        Ok(())
    }
}

impl<G: AffineRepr> PoKOfMAC<G> {
    /// Verify the proof of knowledge of MAC. Requires the knowledge of secret key. It can be seen as composed of 2 parts,
    /// one requiring knowledge of secret key and the other not requiring it. The latter can thus be verified by anyone.
    /// The former doesnt contain any revealed messages and contains no user specific data.
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        secret_key: &SecretKey<G::ScalarField>,
        params: &MACParams<G>,
    ) -> Result<(), KVACError> {
        self._verify(revealed_msgs, challenge, secret_key, params, None)
    }

    /// Similar to `Self::verify` but responses for some messages (witnesses) are provided in `missing_responses`.
    /// The keys of the map are message indices.
    pub fn verify_partial(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        secret_key: &SecretKey<G::ScalarField>,
        params: &MACParams<G>,
        missing_responses: BTreeMap<usize, G::ScalarField>,
    ) -> Result<(), KVACError> {
        self._verify(
            revealed_msgs,
            challenge,
            secret_key,
            params,
            Some(missing_responses),
        )
    }

    pub fn verify_schnorr_proof(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
    ) -> Result<(), KVACError> {
        self._verify_schnorr_proof(revealed_msgs, challenge, params, None)
    }

    /// Similar to `Self::verify_schnorr_proof` but responses for some messages (witnesses) are provided in `missing_responses`.
    /// The keys of the map are message indices.
    pub fn verify_partial_schnorr_proof(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
        missing_responses: BTreeMap<usize, G::ScalarField>,
    ) -> Result<(), KVACError> {
        self._verify_schnorr_proof(revealed_msgs, challenge, params, Some(missing_responses))
    }

    /// Get the response from post-challenge phase of the Schnorr protocol for the given message index
    /// `msg_idx`. Used when comparing message equality
    pub fn get_resp_for_message(
        &self,
        msg_idx: usize,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<&G::ScalarField, KVACError> {
        let adjusted_idx = msg_index_to_schnorr_response_index(msg_idx, revealed_msg_ids)
            .ok_or_else(|| KVACError::InvalidMsgIdxForResponse(msg_idx))?;
        if let Some(resp) = self.sc_resp_msgs.as_ref() {
            Ok(resp.get_response(adjusted_idx)?)
        } else if let Some(resp) = self.sc_partial_resp_msgs.as_ref() {
            Ok(resp.get_response(adjusted_idx)?)
        } else {
            Err(KVACError::NeedEitherPartialOrCompleteSchnorrResponse)
        }
    }

    pub fn get_responses(
        &self,
        msg_ids: &BTreeSet<usize>,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<BTreeMap<usize, G::ScalarField>, KVACError> {
        let mut resps = BTreeMap::new();
        for msg_idx in msg_ids {
            resps.insert(
                *msg_idx,
                *self.get_resp_for_message(*msg_idx, revealed_msg_ids)?,
            );
        }
        Ok(resps)
    }

    /// Create a new sub-proof that can be verified by someone with the secret key
    pub fn to_keyed_proof(&self) -> KeyedProof<G> {
        KeyedProof {
            B_0: self.B_0,
            C: self.C,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        writer: W,
    ) -> Result<(), KVACError> {
        PoKOfMACProtocol::compute_challenge_contribution(
            &self.B_0,
            &self.C,
            &self.d,
            &self.sc_C.t,
            &self.t_msgs,
            revealed_msgs,
            params,
            writer,
        )
    }

    pub fn _verify(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        secret_key: &SecretKey<G::ScalarField>,
        params: &MACParams<G>,
        missing_responses: Option<BTreeMap<usize, G::ScalarField>>,
    ) -> Result<(), KVACError> {
        if self.C != (self.B_0 * secret_key.0).into() {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        self._verify_schnorr_proof(revealed_msgs, challenge, params, missing_responses)?;
        Ok(())
    }

    pub fn _verify_schnorr_proof(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
        missing_responses: Option<BTreeMap<usize, G::ScalarField>>,
    ) -> Result<(), KVACError> {
        if !self.sc_C.verify(
            &(self.C.into_group() - self.d).into(),
            &self.B_0,
            &params.g,
            challenge,
        ) {
            return Err(KVACError::InvalidSchnorrProof);
        }
        let mut bases =
            Vec::with_capacity(2 + params.supported_message_count() - revealed_msgs.len());
        let mut bases_revealed = Vec::with_capacity(revealed_msgs.len());
        let mut exponents = Vec::with_capacity(revealed_msgs.len());
        for i in 0..params.supported_message_count() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_revealed.push(params.g_vec[i]);
                exponents.push(*message);
            } else {
                bases.push(params.g_vec[i]);
            }
        }
        bases.push(self.d);
        bases.push(params.g);
        let y = -G::Group::msm_unchecked(&bases_revealed, &exponents) - params.h;
        if let Some(resp) = &self.sc_resp_msgs {
            if missing_responses.is_some() {
                return Err(KVACError::MissingResponsesProvidedForFullSchnorrProofVerification);
            }
            return match resp.is_valid(&bases, &y.into(), &self.t_msgs, challenge) {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => Err(KVACError::InvalidSchnorrProof),
                Err(other) => Err(KVACError::SchnorrError(other)),
            };
        } else if let Some(resp) = &self.sc_partial_resp_msgs {
            if missing_responses.is_none() {
                return Err(KVACError::MissingResponsesNeededForPartialSchnorrProofVerification);
            }
            let adjusted_missing = msg_index_map_to_schnorr_response_map(
                missing_responses.unwrap(),
                revealed_msgs.keys(),
            );
            return match resp.is_valid(&bases, &y.into(), &self.t_msgs, challenge, adjusted_missing)
            {
                Ok(()) => Ok(()),
                Err(SchnorrError::InvalidResponse) => Err(KVACError::InvalidSchnorrProof),
                Err(other) => Err(KVACError::SchnorrError(other)),
            };
        } else {
            Err(KVACError::NeedEitherPartialOrCompleteSchnorrResponse)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::{
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    #[test]
    fn proof_of_knowledge_of_MAC() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", message_count);
        let sk = SecretKey::new(&mut rng);

        let mac = MAC::new(&mut rng, &messages, &sk, &params).unwrap();
        mac.verify(&messages, &sk, &params).unwrap();

        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let mut revealed_msgs = BTreeMap::new();
        for i in revealed_indices.iter() {
            revealed_msgs.insert(*i, messages[*i]);
        }

        let mut proof_create_duration = Duration::default();
        let start = Instant::now();
        let pok = PoKOfMACProtocol::init(
            &mut rng,
            &mac,
            &params,
            messages.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        )
        .unwrap();
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
        let proof = pok.gen_proof(&challenge_prover).unwrap();
        proof_create_duration += start.elapsed();

        let mut proof_verif_duration = Duration::default();
        let start = Instant::now();
        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify(&revealed_msgs, &challenge_verifier, &sk, &params)
            .unwrap();
        proof_verif_duration += start.elapsed();

        println!(
            "Time to create proof with message size {} and revealing {} messages is {:?}",
            message_count,
            revealed_indices.len(),
            proof_create_duration
        );
        println!(
            "Time to verify proof with message size {} and revealing {} messages is {:?}",
            message_count,
            revealed_indices.len(),
            proof_verif_duration
        );

        let keyed_proof = proof.to_keyed_proof();
        keyed_proof.verify(sk.as_ref()).unwrap();
        proof
            .verify_schnorr_proof(&revealed_msgs, &challenge_verifier, &params)
            .unwrap();
    }

    #[test]
    fn test_PoK_multiple_MACs_with_same_msg() {
        // Knowledge of 2 MACs and their corresponding messages is being proven.

        let mut rng = StdRng::seed_from_u64(0u64);

        let message_1_count = 10;
        let message_2_count = 9;
        let message_3_count = 8;
        let same_msg_idx = BTreeSet::from([0, 3, 4, 7]);
        let mut messages_1 = (0..message_1_count - same_msg_idx.len() as u32)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let mut messages_2 = (0..message_2_count - same_msg_idx.len() as u32)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let mut messages_3 = (0..message_3_count - same_msg_idx.len() as u32)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params_1 = MACParams::<G1Affine>::new::<Blake2b512>(b"test1", message_1_count);
        let params_2 = MACParams::<G1Affine>::new::<Blake2b512>(b"test2", message_2_count);
        let params_3 = MACParams::<G1Affine>::new::<Blake2b512>(b"test3", message_3_count);

        let sk_1 = SecretKey::new(&mut rng);
        let sk_2 = SecretKey::new(&mut rng);
        let sk_3 = SecretKey::new(&mut rng);

        let same_msgs = same_msg_idx
            .clone()
            .into_iter()
            .map(|i| (i, Fr::rand(&mut rng)))
            .collect::<BTreeMap<usize, Fr>>();
        for (i, m) in &same_msgs {
            messages_1.insert(*i, m.clone());
            messages_2.insert(*i, m.clone());
            messages_3.insert(*i, m.clone());
        }

        let mac_1 = MAC::new(&mut rng, &messages_1, &sk_1, &params_1).unwrap();
        mac_1.verify(&messages_1, &sk_1, &params_1).unwrap();
        let mac_2 = MAC::new(&mut rng, &messages_2, &sk_2, &params_2).unwrap();
        mac_2.verify(&messages_2, &sk_2, &params_2).unwrap();
        let mac_3 = MAC::new(&mut rng, &messages_3, &sk_3, &params_3).unwrap();
        mac_3.verify(&messages_3, &sk_3, &params_3).unwrap();

        let revealed_indices = BTreeSet::from([2, 5, 6]);

        let mut revealed_msgs_1 = BTreeMap::new();
        let mut revealed_msgs_2 = BTreeMap::new();
        let mut revealed_msgs_3 = BTreeMap::new();
        for i in revealed_indices.iter() {
            revealed_msgs_1.insert(*i, messages_1[*i]);
            revealed_msgs_2.insert(*i, messages_2[*i]);
            revealed_msgs_3.insert(*i, messages_3[*i]);
        }

        // Add the same blinding for the message which has to be proven equal across MACs
        let same_blindings = same_msg_idx
            .clone()
            .into_iter()
            .map(|i| (i, Fr::rand(&mut rng)))
            .collect::<BTreeMap<usize, Fr>>();

        let mut blindings_1 = BTreeMap::new();
        let mut blindings_2 = BTreeMap::new();
        let mut blindings_3 = BTreeMap::new();
        for (i, b) in &same_blindings {
            blindings_1.insert(*i, *b);
            blindings_2.insert(*i, *b);
            blindings_3.insert(*i, *b);
        }

        // Add some more blindings randomly,
        blindings_1.insert(1, Fr::rand(&mut rng));
        blindings_3.insert(2, Fr::rand(&mut rng));

        let pok_1 = PoKOfMACProtocol::init(
            &mut rng,
            &mac_1,
            &params_1,
            messages_1.iter().enumerate().map(|(idx, message)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(message)
                } else if let Some(blinding) = blindings_1.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .unwrap();
        let pok_2 = PoKOfMACProtocol::init(
            &mut rng,
            &mac_2,
            &params_2,
            messages_2.iter().enumerate().map(|(idx, message)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(message)
                } else if let Some(blinding) = blindings_2.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .unwrap();
        let pok_3 = PoKOfMACProtocol::init(
            &mut rng,
            &mac_3,
            &params_3,
            messages_3.iter().enumerate().map(|(idx, message)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(message)
                } else if let Some(blinding) = blindings_3.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .unwrap();

        let challenge = Fr::rand(&mut rng);

        let proof_1 = pok_1.gen_proof(&challenge).unwrap();
        let proof_2 = pok_2.gen_proof(&challenge).unwrap();
        let proof_3 = pok_3
            .gen_partial_proof(&challenge, &revealed_indices, &same_msg_idx)
            .unwrap();

        // Response for the same message should be same (this check is made by the verifier)
        for i in &same_msg_idx {
            assert_eq!(
                proof_1.get_resp_for_message(*i, &revealed_indices).unwrap(),
                proof_2.get_resp_for_message(*i, &revealed_indices).unwrap()
            );
            assert!(proof_3.get_resp_for_message(*i, &revealed_indices).is_err())
        }

        let missing_resps = proof_1
            .get_responses(&same_msg_idx, &revealed_indices)
            .unwrap();

        proof_1
            .verify(&revealed_msgs_1, &challenge, &sk_1, &params_1)
            .unwrap();
        proof_2
            .verify(&revealed_msgs_2, &challenge, &sk_2, &params_2)
            .unwrap();
        proof_3
            .verify_partial(
                &revealed_msgs_3,
                &challenge,
                &sk_3,
                &params_3,
                missing_resps,
            )
            .unwrap();

        assert!(proof_3
            .get_responses(&same_msg_idx, &revealed_indices)
            .is_err());

        let mut partial_resp_ids = BTreeSet::new();
        for i in 0..message_3_count as usize {
            if !same_msg_idx.contains(&i) && !revealed_indices.contains(&i) {
                partial_resp_ids.insert(i);
            }
        }
        let partial_resps = proof_3
            .get_responses(&partial_resp_ids, &revealed_indices)
            .unwrap();
        for i in partial_resp_ids {
            assert_eq!(
                proof_3.get_resp_for_message(i, &revealed_indices).unwrap(),
                partial_resps.get(&i).unwrap()
            );
        }
    }

    #[test]
    fn pok_MAC_schnorr_response() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let message_count = 6;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", message_count);
        let sk = SecretKey::new(&mut rng);

        let mac = MAC::new(&mut rng, &messages, &sk, &params).unwrap();
        mac.verify(&messages, &sk, &params).unwrap();

        let challenge = Fr::rand(&mut rng);

        // Test response when no hidden message
        let revealed_indices_1 = BTreeSet::new();
        let pok_1 = PoKOfMACProtocol::init(
            &mut rng,
            &mac,
            &params,
            messages.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices_1.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        )
        .unwrap();
        let proof_1 = pok_1.gen_proof(&challenge).unwrap();
        let resps = proof_1.sc_resp_msgs.as_ref().unwrap();
        for i in 0..message_count as usize {
            assert_eq!(
                *proof_1
                    .get_resp_for_message(i, &revealed_indices_1)
                    .unwrap(),
                resps.0[i]
            );
        }

        // Test response when some messages are revealed
        let mut revealed_indices_2 = BTreeSet::new();
        revealed_indices_2.insert(0);
        revealed_indices_2.insert(2);
        revealed_indices_2.insert(5);
        let pok_2 = PoKOfMACProtocol::init(
            &mut rng,
            &mac,
            &params,
            messages.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices_2.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        )
        .unwrap();
        let proof_2 = pok_2.gen_proof(&challenge).unwrap();

        // Getting response for messages that are revealed throws error as they are not included in
        // the proof of knowledge
        assert!(proof_2
            .get_resp_for_message(0, &revealed_indices_2)
            .is_err());
        assert!(proof_2
            .get_resp_for_message(2, &revealed_indices_2)
            .is_err());
        assert!(proof_2
            .get_resp_for_message(5, &revealed_indices_2)
            .is_err());

        let resps = proof_2.sc_resp_msgs.as_ref().unwrap();
        assert_eq!(
            *proof_2
                .get_resp_for_message(1, &revealed_indices_2)
                .unwrap(),
            resps.0[0]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(3, &revealed_indices_2)
                .unwrap(),
            resps.0[1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(4, &revealed_indices_2)
                .unwrap(),
            resps.0[2]
        );

        let mut revealed_indices_3 = BTreeSet::new();
        revealed_indices_3.insert(0);
        revealed_indices_3.insert(3);
        let pok_3 = PoKOfMACProtocol::init(
            &mut rng,
            &mac,
            &params,
            messages.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices_3.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        )
        .unwrap();
        let proof_3 = pok_3.gen_proof(&challenge).unwrap();

        // Getting response for messages that are revealed throws error as they are not included in
        // the proof of knowledge
        assert!(proof_3
            .get_resp_for_message(0, &revealed_indices_3)
            .is_err());
        assert!(proof_3
            .get_resp_for_message(3, &revealed_indices_3)
            .is_err());

        let resps = proof_3.sc_resp_msgs.as_ref().unwrap();
        assert_eq!(
            *proof_3
                .get_resp_for_message(1, &revealed_indices_3)
                .unwrap(),
            resps.0[0]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(2, &revealed_indices_3)
                .unwrap(),
            resps.0[1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(4, &revealed_indices_3)
                .unwrap(),
            resps.0[2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(5, &revealed_indices_3)
                .unwrap(),
            resps.0[3]
        );

        // Reveal one message only
        for i in 0..message_count as usize {
            let mut revealed_indices = BTreeSet::new();
            revealed_indices.insert(i);
            let pok = PoKOfMACProtocol::init(
                &mut rng,
                &mac,
                &params,
                messages.iter().enumerate().map(|(idx, msg)| {
                    if revealed_indices.contains(&idx) {
                        MessageOrBlinding::RevealMessage(msg)
                    } else {
                        MessageOrBlinding::BlindMessageRandomly(msg)
                    }
                }),
            )
            .unwrap();
            let proof = pok.gen_proof(&challenge).unwrap();
            let resps = proof.sc_resp_msgs.as_ref().unwrap();
            for j in 0..message_count as usize {
                if i == j {
                    assert!(proof.get_resp_for_message(j, &revealed_indices).is_err());
                } else if i < j {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        resps.0[j - 1]
                    );
                } else {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        resps.0[j]
                    );
                }
            }
        }
    }
}
