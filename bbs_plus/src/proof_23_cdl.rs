//! Proof of knowledge of BBS signature and corresponding messages as per section 5.2 of the BBS paper with
//! slight modification described below.
//! The paper requires the prover to prove `e(A_bar, X_2) = e (B_bar, g2)` where `A_bar = A * r` and `B_bar = C(m)*r + A_bar*-e`.
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
    vec,
    vec::Vec,
    One, UniformRand,
};
use dock_crypto_utils::{
    misc::rand,
    randomized_pairing_check::RandomizedPairingChecker,
    serde_utils::*,
    signature::{split_messages_and_blindings, MessageOrBlinding, MultiMessageSignatureParams},
};
use itertools::multiunzip;
use schnorr_pok::{error::SchnorrError, SchnorrCommitment, SchnorrResponse};
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
    pub sc_comm_1: SchnorrCommitment<E::G1Affine>,
    #[serde_as(as = "(ArkObjectBytes, ArkObjectBytes)")]
    sc_wits_1: (E::ScalarField, E::ScalarField),
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
    #[serde_as(as = "ArkObjectBytes")]
    pub T1: E::G1Affine,
    pub sc_resp_1: SchnorrResponse<E::G1Affine>,
    /// Proof of relation `g1 + h1*m1 + h2*m2 +.... + h_i*m_i` = `d*r3 + h1*{-m1} + h2*{-m2} + .... + h_j*{-m_j}` for all disclosed messages `m_i` and for all undisclosed messages `m_j`
    #[serde_as(as = "ArkObjectBytes")]
    pub T2: E::G1Affine,
    pub sc_resp_2: SchnorrResponse<E::G1Affine>,
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

        // b = (e+x) * A = g1 + sum(h_i*m_i) for all i in I
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
        let bases_1 = [A_bar_affine, d_affine];
        let randomness_1 = vec![E::ScalarField::rand(rng), E::ScalarField::rand(rng)];
        let wits_1 = (-signature.e, r1);

        let sc_comm_1 = SchnorrCommitment::new(&bases_1, randomness_1);

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

        let (bases_2, randomness_2, wits_2): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            [(d_affine, rand(rng), -r3)]
                .into_iter()
                .chain(h_blinding_message),
        );

        // Commit to randomness, i.e. `bases_2[0]*randomness_2[0] + bases_2[1]*randomness_2[1] + .... bases_2[j]*randomness_2[j]`
        let sc_comm_2 = SchnorrCommitment::new(&bases_2, randomness_2);

        Ok(Self {
            A_bar: A_bar_affine,
            B_bar: B_bar.into_affine(),
            d: d_affine,
            sc_comm_1,
            sc_wits_1: wits_1,
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
        self,
        challenge: &E::ScalarField,
    ) -> Result<PoKOfSignature23G1Proof<E>, BBSPlusError> {
        let resp_1 = self
            .sc_comm_1
            .response(&[self.sc_wits_1.0, self.sc_wits_1.1], challenge)?;

        // Schnorr response for relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + \sum_{j not in D}(h_j*{-m_j})`
        let resp_2 = self.sc_comm_2.response(&self.sc_wits_2, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            d: self.d,
            T1: self.sc_comm_1.t,
            sc_resp_1: resp_1,
            T2: self.sc_comm_2.t,
            sc_resp_2: resp_2,
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

impl<E> PoKOfSignature23G1Proof<E>
where
    E: Pairing,
{
    /// Verify if the proof is valid. Assumes that the public key and parameters have been
    /// validated already.
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h)?;

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

    pub fn verify_with_randomized_pairing_checker(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParams23G1<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h)?;
        pairing_checker.add_sources(&self.A_bar, pk.into().0, &self.B_bar, g2);
        Ok(())
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
            &self.T1,
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
        // Revealed messages are not part of Schnorr protocol
        if revealed_msg_ids.contains(&msg_idx) {
            return Err(BBSPlusError::InvalidMsgIdxForResponse(msg_idx));
        }
        // Adjust message index as the revealed messages are not part of the Schnorr protocol
        let mut adjusted_idx = msg_idx;
        for i in revealed_msg_ids {
            if *i < msg_idx {
                adjusted_idx -= 1;
            }
        }
        // 1 added to the index, since 0th index is reserved for `r2`
        Ok(self.sc_resp_2.get_response(1 + adjusted_idx)?)
    }

    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h: Vec<E::G1Affine>,
    ) -> Result<(), BBSPlusError> {
        // Verify the 1st Schnorr proof
        let bases_1 = [self.A_bar, self.d];
        match self
            .sc_resp_1
            .is_valid(&bases_1, &self.B_bar, &self.T1, challenge)
        {
            Ok(()) => (),
            Err(SchnorrError::InvalidResponse) => {
                return Err(BBSPlusError::FirstSchnorrVerificationFailed)
            }
            Err(other) => return Err(BBSPlusError::SchnorrError(other)),
        }

        // Verify the 2nd Schnorr proof
        let mut bases_2 = Vec::with_capacity(1 + h.len() - revealed_msgs.len());
        bases_2.push(self.d);

        let mut bases_revealed = Vec::with_capacity(1 + revealed_msgs.len());
        let mut exponents = Vec::with_capacity(1 + revealed_msgs.len());
        bases_revealed.push(g1);
        exponents.push(E::ScalarField::one());
        for i in 0..h.len() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_revealed.push(h[i]);
                exponents.push(*message);
            } else {
                bases_2.push(h[i]);
            }
        }
        // pr = -g1 + \sum_{i in D}(h_i*{-m_i}) = -(g1 + \sum_{i in D}(h_i*{m_i}))
        let pr = -E::G1::msm_unchecked(&bases_revealed, &exponents);
        let pr = pr.into_affine();
        match self.sc_resp_2.is_valid(&bases_2, &pr, &self.T2, challenge) {
            Ok(()) => (),
            Err(SchnorrError::InvalidResponse) => {
                return Err(BBSPlusError::SecondSchnorrVerificationFailed)
            }
            Err(other) => return Err(BBSPlusError::SchnorrError(other)),
        }

        Ok(())
    }

    /// Verify the proof except the pairing equations. This is useful when doing several verifications (of this
    /// protocol or others) and the pairing equations are combined in a randomized pairing check.
    fn verify_except_pairings(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h: Vec<E::G1Affine>,
    ) -> Result<(), BBSPlusError> {
        if self.A_bar.is_zero() {
            return Err(BBSPlusError::ZeroSignature);
        }
        self.verify_schnorr_proofs(revealed_msgs, challenge, g1, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gen_test_PoK_multiple_sigs_with_randomized_pairing_check,
        gen_test_PoK_multiple_sigs_with_same_msg, gen_test_pok_signature_revealed_message,
        setup::KeypairG2, test_serialization,
    };
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    fn sig_setup<R: RngCore>(
        rng: &mut R,
        message_count: u32,
    ) -> (
        Vec<Fr>,
        SignatureParams23G1<Bls12_381>,
        KeypairG2<Bls12_381>,
        Signature23G1<Bls12_381>,
    ) {
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
        let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, message_count);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
        let sig =
            Signature23G1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
        (messages, params, keypair, sig)
    }

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
        // Test response from Schnorr protocol from various messages
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 6;
        let (messages, params, _keypair, sig) = sig_setup(&mut rng, message_count);

        let challenge = Fr::rand(&mut rng);

        // Test response when no hidden message
        let revealed_indices_1 = BTreeSet::new();
        let pok_1 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            &sig,
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
        for i in 0..message_count as usize {
            assert_eq!(
                *proof_1
                    .get_resp_for_message(i, &revealed_indices_1)
                    .unwrap(),
                proof_1.sc_resp_2.0[i + 1]
            );
        }

        // Test response when some messages are revealed
        let mut revealed_indices_2 = BTreeSet::new();
        revealed_indices_2.insert(0);
        revealed_indices_2.insert(2);
        revealed_indices_2.insert(5);
        let pok_2 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            &sig,
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

        assert_eq!(
            *proof_2
                .get_resp_for_message(1, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_2.0[1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(3, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_2.0[1 + 1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(4, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_2.0[1 + 2]
        );

        let mut revealed_indices_3 = BTreeSet::new();
        revealed_indices_3.insert(0);
        revealed_indices_3.insert(3);
        let pok_3 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            &sig,
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

        assert_eq!(
            *proof_3
                .get_resp_for_message(1, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(2, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[1 + 1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(4, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[1 + 2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(5, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[1 + 3]
        );

        // Reveal one message only
        for i in 0..message_count as usize {
            let mut revealed_indices = BTreeSet::new();
            revealed_indices.insert(i);
            let pok = PoKOfSignature23G1Protocol::init(
                &mut rng,
                &sig,
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
            for j in 0..message_count as usize {
                if i == j {
                    assert!(proof.get_resp_for_message(j, &revealed_indices).is_err());
                } else if i < j {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_2.0[j + 1 - 1]
                    );
                } else {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_2.0[j + 1]
                    );
                }
            }
        }
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
