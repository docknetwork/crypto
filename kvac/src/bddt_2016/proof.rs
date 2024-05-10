//! Protocol to prove knowledge of the MAC. This is the "Show" protocol described in Fig.2 (2) in the paper

use crate::{
    bddt_2016::{
        keyed_proof::KeyedProof,
        mac::MAC,
        setup::{MACParams, SecretKey},
    },
    error::KVACError,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use core::mem;
use dock_crypto_utils::{
    misc::rand,
    serde_utils::ArkObjectBytes,
    signature::{split_messages_and_blindings, MessageOrBlinding, MultiMessageSignatureParams},
};
use itertools::multiunzip;
use schnorr_pok::{
    discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol},
    SchnorrCommitment, SchnorrResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of a MAC.
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
pub struct PoKOfMACProtocol<G: AffineRepr> {
    /// Randomized MAC `B_0 = A * l`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub B_0: G,
    /// `C = b * l - B_0 * e`, here `b = A * (e + y)`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub C: G,
    /// `E = C * 1/l + f * t`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub E: G,
    /// Protocol to prove knowledge of `1/l, t` in `E`
    pub sc_E: PokTwoDiscreteLogsProtocol<G>,
    /// Protocol to prove knowledge of `l, r` in `C`
    pub sc_C: PokTwoDiscreteLogsProtocol<G>,
    /// For proving relation `E - h - \sum_{i in D}(g_vec_i*m_i)` = `sum_{j notin D}(g_vec_j*m_j) + B_0*{-r/l} + f*t`
    pub sc_comm_msgs: SchnorrCommitment<G>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    sc_wits_msgs: Vec<G::ScalarField>,
}

/// Proof of knowledge of a MAC.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PoKOfMAC<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub B_0: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub E: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub C: G,
    pub sc_E: PokTwoDiscreteLogs<G>,
    pub sc_C: PokTwoDiscreteLogs<G>,
    #[serde_as(as = "ArkObjectBytes")]
    pub t_msgs: G,
    pub sc_resp_msgs: SchnorrResponse<G>,
}

impl<G: AffineRepr> PoKOfMACProtocol<G> {
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        mac: &MAC<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
        f: impl Into<G>,
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

        let f = f.into();
        let minus_e = -mac.e;

        let l = G::ScalarField::rand(rng);
        let t = G::ScalarField::rand(rng);
        let alpha = l.inverse().unwrap();
        let lambda = minus_e * alpha;
        let gamma = -l * t;

        let B_0 = mac.A * l;
        let B_0_affine = B_0.into_affine();
        let C = params.b(messages.iter().enumerate(), &mac.s)? * l + B_0 * minus_e;
        let C_affine = C.into_affine();
        let E = C * alpha + f * t;
        let E_affine = E.into_affine();
        let t_blinding = G::ScalarField::rand(rng);
        let sc_E = PokTwoDiscreteLogsProtocol::init(alpha, rand(rng), &C_affine, t, t_blinding, &f);
        let sc_C = PokTwoDiscreteLogsProtocol::init(l, rand(rng), &E_affine, gamma, rand(rng), &f);

        // Iterator of tuples of form `(g_vec_i, blinding_i, message_i)`
        let msg_comm_iter = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.g_vec[idx], blinding, messages[idx]));
        let (bases, randomness, sc_wits_msgs): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            msg_comm_iter.chain(
                [
                    (params.g, rand(rng), mac.s),
                    (B_0_affine, rand(rng), lambda),
                    (f, t_blinding, t),
                ]
                .into_iter(),
            ),
        );
        let sc_comm_msgs = SchnorrCommitment::new(&bases, randomness);
        Ok(Self {
            B_0: B_0_affine,
            C: C_affine,
            E: E_affine,
            sc_E,
            sc_C,
            sc_comm_msgs,
            sc_wits_msgs,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        f: &G,
        writer: W,
    ) -> Result<(), KVACError> {
        Self::compute_challenge_contribution(
            &self.B_0,
            &self.C,
            &self.E,
            &self.sc_C.t,
            &self.sc_E.t,
            revealed_msgs,
            params,
            f,
            writer,
        )
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> Result<PoKOfMAC<G>, KVACError> {
        let sc_E = mem::take(&mut self.sc_E).gen_proof(challenge);
        let sc_C = mem::take(&mut self.sc_C).gen_proof(challenge);
        let sc_resp_msgs = self.sc_comm_msgs.response(&self.sc_wits_msgs, challenge)?;
        Ok(PoKOfMAC {
            B_0: self.B_0,
            E: self.E,
            C: self.C,
            sc_E,
            sc_C,
            t_msgs: self.sc_comm_msgs.t,
            sc_resp_msgs,
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        B_0: &G,
        C: &G,
        E: &G,
        C_t: &G,
        E_t: &G,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        f: &G,
        mut writer: W,
    ) -> Result<(), KVACError> {
        B_0.serialize_compressed(&mut writer)?;
        E.serialize_compressed(&mut writer)?;
        C.serialize_compressed(&mut writer)?;
        f.serialize_compressed(&mut writer)?;
        params.h.serialize_compressed(&mut writer)?;
        params.g.serialize_compressed(&mut writer)?;
        C_t.serialize_compressed(&mut writer)?;
        E_t.serialize_compressed(&mut writer)?;
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
        f: impl Into<G>,
    ) -> Result<(), KVACError> {
        if self.C != (self.B_0 * secret_key.0).into() {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        self.verify_schnorr_proofs(revealed_msgs, challenge, params, f)?;
        Ok(())
    }

    /// Create a new sub-proof that can be verified by someone with the secret key
    pub fn to_keyed_proof(&self) -> KeyedProof<G> {
        KeyedProof {
            B_0: self.B_0,
            C: self.C,
        }
    }

    /// This verifies `pi_3` from the paper.
    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
        f: impl Into<G>,
    ) -> Result<(), KVACError> {
        let f = f.into();
        if !self.sc_E.verify(&self.E, &self.C, &f, challenge) {
            return Err(KVACError::InvalidSchnorrProof);
        }
        if !self.sc_C.verify(&self.C, &self.E, &f, challenge) {
            return Err(KVACError::InvalidSchnorrProof);
        }
        if self.sc_E.response2
            != *self
                .sc_resp_msgs
                .get_response(self.sc_resp_msgs.len() - 1)?
        {
            return Err(KVACError::InvalidSchnorrProof);
        }
        let mut bases = Vec::with_capacity(3 + params.g_vec.len() - revealed_msgs.len());
        let mut bases_revealed = Vec::with_capacity(revealed_msgs.len());
        let mut exponents = Vec::with_capacity(revealed_msgs.len());
        for i in 0..params.g_vec.len() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_revealed.push(params.g_vec[i]);
                exponents.push(*message);
            } else {
                bases.push(params.g_vec[i]);
            }
        }

        let y = self.E.into_group()
            - params.h.into_group()
            - G::Group::msm_unchecked(&bases_revealed, &exponents);
        bases.push(params.g);
        bases.push(self.B_0);
        bases.push(f);
        self.sc_resp_msgs
            .is_valid(&bases, &y.into_affine(), &self.t_msgs, challenge)?;
        Ok(())
    }

    pub fn get_resp_for_message(
        &self,
        msg_idx: usize,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<&G::ScalarField, KVACError> {
        // Revealed messages are not part of Schnorr protocol
        if revealed_msg_ids.contains(&msg_idx) {
            return Err(KVACError::InvalidMsgIdxForResponse(msg_idx));
        }
        let mut adjusted_idx = msg_idx;
        for i in revealed_msg_ids {
            if *i < msg_idx {
                adjusted_idx -= 1;
            }
        }
        Ok(self.sc_resp_msgs.get_response(adjusted_idx)?)
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        f: &G,
        writer: W,
    ) -> Result<(), KVACError> {
        PoKOfMACProtocol::compute_challenge_contribution(
            &self.B_0,
            &self.C,
            &self.E,
            &self.sc_C.t,
            &self.sc_E.t,
            revealed_msgs,
            params,
            f,
            writer,
        )
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
        let f = G1Affine::rand(&mut rng);

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
            f.clone(),
        )
        .unwrap();
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &f, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
        let proof = pok.gen_proof(&challenge_prover).unwrap();
        proof_create_duration += start.elapsed();

        let mut proof_verif_duration = Duration::default();
        let start = Instant::now();
        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&revealed_msgs, &params, &f, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify(&revealed_msgs, &challenge_verifier, &sk, &params, f)
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
            .verify_schnorr_proofs(&revealed_msgs, &challenge_verifier, &params, f)
            .unwrap();
    }

    #[test]
    fn test_PoK_multiple_MACs_with_same_msg() {
        // Knowledge of 2 MACs and their corresponding messages is being proven.

        let mut rng = StdRng::seed_from_u64(0u64);

        let message_1_count = 10;
        let message_2_count = 7;
        let mut messages_1 = (0..message_1_count - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let mut messages_2 = (0..message_2_count - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params_1 = MACParams::<G1Affine>::new::<Blake2b512>(b"test1", message_1_count);
        let params_2 = MACParams::<G1Affine>::new::<Blake2b512>(b"test2", message_2_count);

        let sk_1 = SecretKey::new(&mut rng);
        let sk_2 = SecretKey::new(&mut rng);
        let f = G1Affine::rand(&mut rng);

        let same_msg_idx = 4;
        let same_msg = Fr::rand(&mut rng);
        messages_1.insert(same_msg_idx, same_msg);
        messages_2.insert(same_msg_idx, same_msg);

        // A particular message is same
        assert_eq!(messages_1[same_msg_idx], messages_2[same_msg_idx]);
        assert_ne!(messages_1, messages_2);

        let mac_1 = MAC::new(&mut rng, &messages_1, &sk_1, &params_1).unwrap();
        mac_1.verify(&messages_1, &sk_1, &params_1).unwrap();
        let mac_2 = MAC::new(&mut rng, &messages_2, &sk_2, &params_2).unwrap();
        mac_2.verify(&messages_2, &sk_2, &params_2).unwrap();

        // Add the same blinding for the message which has to be proven equal across MACs
        let same_blinding = Fr::rand(&mut rng);

        let mut blindings_1 = BTreeMap::new();
        blindings_1.insert(same_msg_idx, same_blinding);

        let mut blindings_2 = BTreeMap::new();
        blindings_2.insert(same_msg_idx, same_blinding);

        // Add some more blindings randomly,
        blindings_1.insert(0, Fr::rand(&mut rng));
        blindings_1.insert(1, Fr::rand(&mut rng));
        blindings_2.insert(2, Fr::rand(&mut rng));

        // Blinding for the same message is kept same
        assert_eq!(
            blindings_1.get(&same_msg_idx),
            blindings_2.get(&same_msg_idx)
        );
        assert_ne!(blindings_1, blindings_2);

        let pok_1 = PoKOfMACProtocol::init(
            &mut rng,
            &mac_1,
            &params_1,
            messages_1.iter().enumerate().map(|(idx, message)| {
                if let Some(blinding) = blindings_1.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
            f.clone(),
        )
        .unwrap();
        let pok_2 = PoKOfMACProtocol::init(
            &mut rng,
            &mac_2,
            &params_2,
            messages_2.iter().enumerate().map(|(idx, message)| {
                if let Some(blinding) = blindings_2.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
            f.clone(),
        )
        .unwrap();

        let challenge = Fr::rand(&mut rng);

        let proof_1 = pok_1.gen_proof(&challenge).unwrap();
        let proof_2 = pok_2.gen_proof(&challenge).unwrap();

        // Response for the same message should be same (this check is made by the verifier)
        assert_eq!(
            proof_1
                .get_resp_for_message(same_msg_idx, &BTreeSet::new())
                .unwrap(),
            proof_2
                .get_resp_for_message(same_msg_idx, &BTreeSet::new())
                .unwrap()
        );

        proof_1
            .verify(&BTreeMap::new(), &challenge, &sk_1, &params_1, f.clone())
            .unwrap();
        proof_2
            .verify(&BTreeMap::new(), &challenge, &sk_2, &params_2, f.clone())
            .unwrap();
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
        let f = G1Affine::rand(&mut rng);

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
            f.clone(),
        )
        .unwrap();
        let proof_1 = pok_1.gen_proof(&challenge).unwrap();
        for i in 0..message_count as usize {
            assert_eq!(
                *proof_1
                    .get_resp_for_message(i, &revealed_indices_1)
                    .unwrap(),
                proof_1.sc_resp_msgs.0[i]
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
            f.clone(),
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

        assert_eq!(
            *proof_2
                .get_resp_for_message(1, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_msgs.0[0]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(3, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_msgs.0[1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(4, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_msgs.0[2]
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
            f.clone(),
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

        assert_eq!(
            *proof_3
                .get_resp_for_message(1, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_msgs.0[0]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(2, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_msgs.0[1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(4, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_msgs.0[2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(5, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_msgs.0[3]
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
                f.clone(),
            )
            .unwrap();
            let proof = pok.gen_proof(&challenge).unwrap();
            for j in 0..message_count as usize {
                if i == j {
                    assert!(proof.get_resp_for_message(j, &revealed_indices).is_err());
                } else if i < j {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_msgs.0[j - 1]
                    );
                } else {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_msgs.0[j]
                    );
                }
            }
        }
    }
}
