//! Proof of knowledge of BBS signature and corresponding messages as per section 5.2 of the BBS paper with
//! slight modification described below.
//! The paper requires the prover to prove `e(A_bar, X_2) = e (B_bar, g2)` where `B_bar = C(m)*r + A_bar*-e`.
//! The prover sends `A_bar`, `B_bar` to the verifier and also proves the knowledge of `r`, `e` and any
//! messages in `C(m)` in `B_bar`. Here `r` is a random element chosen by the prover on each proof of knowledge.
//! Above approach has a problem when some messages under 2 signatures need to be proven equal in zero
//! knowledge. Because `r` will be different for each signature, the witnesses for the Schnorr proof will be
//! different, i.e. `m*r` and `m*r'` for the same message `m` and thus the folklore method of proving equal
//! witnesses in multiple statements cant be used. Thus the protocol below accepts `r` (called signature randomizer)
//! from the prover who can use the same `r` when proving message equality in multiple signatures. When doing
//! so also prove the equality of `r` in term `C_j(m) * r` and thus use the same blinding eg. when proving equality of
//! certain messages under 2 signatures `sigma_1 = (A_1, e_1)` and `sigma_2 = A_2 * e_2`, it should be proven
//! that `r` and Schnorr responses for the equal messages `m_k` are equal. i.e. for known messages `J_1`,
//! `J_2`, hidden messages `I_1`, `I_2` for signatures `sigma_1`, `sigma_2` with equal messages `m_k` being
//! a subset of `I_1`, `I_2`, `r` and `m_k` are same in following 2 relations:
//! `{B_1}_bar = C_{J_1}(m) * r + \sum_{i in I_1}(h_i * (m_i*r)) + {A_1}_bar * -e_1`
//! `{B_2}_bar = C_{J_2}(m) * r + \sum_{i in I_2}(h_i * (m_i*r)) + {A_2}_bar * -e_2`
//! Its important to prove that `r` is same in `C_{J_1}(m)` and `C_{J_2}(m)` otherwise two unequal
//! messages `m_a` and `m_b` can be proven equal by using signature randomizers `r_1` and `r2` such that `m_a * r_1 = m_b * r_2`

use crate::{
    error::BBSPlusError,
    setup::{PreparedPublicKeyG2, SignatureParams23G1},
    signature_23::Signature23G1,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec::Vec,
};
use itertools::{multiunzip, MultiUnzip};

use crate::setup::PreparedSignatureParams23G1;
use dock_crypto_utils::{
    expect_equality,
    extend_some::ExtendSome,
    misc::rand,
    randomized_pairing_check::RandomizedPairingChecker,
    serde_utils::ArkObjectBytes,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
};
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
    /// For proving relation `g1 + \sum_{i in D}(h_i*m_i)` = `sum_{j notin D}(h_j*m_j)`
    pub sc_comm: SchnorrCommitment<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    sc_wits: Vec<E::ScalarField>,
}

/// Proof of knowledge of BBS signature in G1. It contains the randomized signature, commitment (Schnorr step 1)
/// and response (Schnorr step 3) to the Schnorr protocol in `T` and `sc_resp`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PoKOfSignature23G1Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub B_bar: E::G1Affine,
    /// Proof of relation `g1 + h1*m1 + h2*m2 +.... + h_i*m_i` = `h1*{-m1} + h2*{-m2} + .... + h_j*{-m_j}` for all disclosed messages `m_i` and for all undisclosed messages `m_j`
    #[serde_as(as = "ArkObjectBytes")]
    pub T: E::G1Affine,
    pub sc_resp: SchnorrResponse<E::G1Affine>,
}

impl<E: Pairing> PoKOfSignature23G1Protocol<E> {
    /// Initiate the protocol, i.e. pre-challenge phase. This will generate the randomized signature and execute
    /// the commit-to-randomness step (Step 1) of the Schnorr protocol.
    /// Accepts an iterator of messages. Each message can be either randomly blinded, revealed, or blinded using supplied blinding.
    /// `signature_randomizer` is `r` from the paper and `blinding_for_known_message_commitment` is the blinding used to prove
    /// knowledge of `r` in `C_j(m) * r`
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        signature_randomizer: Option<E::ScalarField>,
        blinding_for_known_message_commitment: Option<E::ScalarField>,
        signature: &Signature23G1<E>,
        params: &SignatureParams23G1<E>,
        messages_and_blindings: MBI,
    ) -> Result<Self, BBSPlusError>
    where
        MBI: IntoIterator<Item = MessageOrBlinding<'a, E::ScalarField>>,
    {
        let (
            messages,
            ExtendSome::<Vec<_>>(indexed_blindings),
            ExtendSome::<Vec<_>>(revealed_indices_h),
            ExtendSome::<Vec<_>>(revealed_messages),
        ): (Vec<_>, _, _, _) = messages_and_blindings
            .into_iter()
            .enumerate()
            .map(|(idx, msg_or_blinding)| match msg_or_blinding {
                MessageOrBlinding::BlindMessageRandomly(message) => {
                    (message, (idx, rand(rng)).into(), None, None)
                }
                MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding } => {
                    (message, (idx, blinding).into(), None, None)
                }
                MessageOrBlinding::RevealMessage(message) => (
                    message,
                    None,
                    (params.h.len() > idx).then_some(params.h[idx]),
                    Some(message),
                ),
            })
            .multiunzip();
        expect_equality!(
            messages.len(),
            params.supported_message_count(),
            BBSPlusError::MessageCountIncompatibleWithSigParams
        );

        let signature_randomizer = signature_randomizer.unwrap_or_else(|| rand(rng));
        let blinding_for_known_message_commitment =
            blinding_for_known_message_commitment.unwrap_or_else(|| rand(rng));

        // Commitment to all messages
        // `C(m) = (e+x) * A = g1 + \sum_{i}(h_i*m_i)` for all messages `m_i`
        let c_m = params.b(messages.iter().enumerate())?;

        let r_repr = signature_randomizer.into_bigint();
        // A_bar = A * r
        let A_bar = signature.A.mul_bigint(r_repr);
        // B_bar = r * C(m) - e * A_bar
        let c_m_r = c_m.mul_bigint(r_repr);
        let B_bar = c_m_r - (A_bar.mul_bigint(signature.e.into_bigint()));

        // Commitment to revealed messages
        // `C_j(m) = g1 + \sum_{j}(h_j*m_j)` for all revealed messages `m_j`
        let c_m_j = E::G1::msm_unchecked(&revealed_indices_h, &revealed_messages) + params.g1;

        let A_bar_affine = A_bar.into_affine();

        // Need to prove the knowledge of witnesses `r` (randomness), `e` from signature and hidden messages `m_i`
        // in the following relation where instance is `B_bar, A_bar, c_m_j and h_i`
        // `B_bar = c_m_j * r + \sum_{i}(h_i * (m_i*r)) + A_bar * -e`

        // Iterator of tuples of form `(h_i, blinding_i, message_i*r)`
        let h_blinding_message = indexed_blindings.into_iter().map(|(idx, blinding)| {
            (
                params.h[idx],
                blinding,
                messages[idx] * signature_randomizer,
            )
        });

        let (bases, randomness, sc_wits): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            [
                (
                    c_m_j.into_affine(),
                    blinding_for_known_message_commitment,
                    signature_randomizer,
                ),
                (A_bar_affine, rand(rng), -signature.e),
            ]
            .into_iter()
            .chain(h_blinding_message),
        );

        let sc_comm = SchnorrCommitment::new(&bases, randomness);

        Ok(Self {
            A_bar: A_bar_affine,
            B_bar: B_bar.into_affine(),
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
        // Schnorr response for relation `g1 + \sum_{i in D}(h_i*m_i)` = `\sum_{j not in D}(h_j*{-m_j})`
        let resp = self.sc_comm.response(&self.sc_wits, challenge)?;

        Ok(PoKOfSignature23G1Proof {
            A_bar: self.A_bar,
            B_bar: self.B_bar,
            T: self.sc_comm.t,
            sc_resp: resp,
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
        B_bar.serialize_compressed(&mut writer)?;
        A_bar.serialize_compressed(&mut writer)?;
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
            &self.T,
            revealed_msgs,
            params,
            writer,
        )
    }

    pub fn get_resp_for_known_messages_commitment(&self) -> &E::ScalarField {
        self.sc_resp.get_response(0).unwrap()
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
        // 2 added to the index, since 0th and 1st index are reserved for `r` and `-e`
        let r = self.sc_resp.get_response(2 + adjusted_idx)?;
        Ok(r)
    }

    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h: Vec<E::G1Affine>,
    ) -> Result<(), BBSPlusError> {
        let mut bases = Vec::with_capacity(2 + h.len() - revealed_msgs.len());
        bases.push(self.A_bar);

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
        let c_m_j = E::G1::msm_unchecked(&bases_revealed, &exponents) + g1;
        bases.insert(0, c_m_j.into_affine());

        match self
            .sc_resp
            .is_valid(&bases, &self.B_bar, &self.T, challenge)
        {
            Ok(()) => (),
            Err(SchnorrError::InvalidResponse) => {
                return Err(BBSPlusError::FirstSchnorrVerificationFailed)
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
pub mod tests {
    use super::*;
    use crate::{setup::KeypairG2, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_serialize::CanonicalDeserialize;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    pub fn sig_setup<R: RngCore>(
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
        // Create and verify proof of knowledge of a signature when some messages are revealed
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 20;
        let (messages, params, keypair, sig) = sig_setup(&mut rng, message_count);
        sig.verify(&messages, keypair.public_key.clone(), params.clone())
            .unwrap();

        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let mut revealed_msgs = BTreeMap::new();
        for i in revealed_indices.iter() {
            revealed_msgs.insert(*i, messages[*i]);
        }

        let mut proof_create_duration = Duration::default();
        let start = Instant::now();
        let pok = PoKOfSignature23G1Protocol::init(
            &mut rng,
            None,
            None,
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
        proof_create_duration += start.elapsed();

        // Protocol can be serialized
        test_serialization!(PoKOfSignature23G1Protocol<Bls12_381>, pok);

        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let start = Instant::now();
        let proof = pok.gen_proof(&challenge_prover).unwrap();
        proof_create_duration += start.elapsed();

        let public_key = &keypair.public_key;
        assert!(params.is_valid());
        assert!(public_key.is_valid());

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

        assert_eq!(chal_bytes_prover, chal_bytes_verifier);

        let mut proof_verif_duration = Duration::default();
        let start = Instant::now();
        proof
            .verify(
                &revealed_msgs,
                &challenge_verifier,
                public_key.clone(),
                params.clone(),
            )
            .unwrap();
        proof_verif_duration += start.elapsed();

        // Proof can be serialized
        test_serialization!(PoKOfSignature23G1Proof<Bls12_381>, proof);

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
    }

    #[test]
    fn test_PoK_multiple_sigs_with_same_msg() {
        // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
        // Knowledge of 2 signatures and their corresponding messages is being proven.

        let mut rng = StdRng::seed_from_u64(0u64);
        let message_1_count = 10;
        let message_2_count = 7;
        let params_1 =
            SignatureParams23G1::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), message_1_count);
        let params_2 = SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(
            "test-1".as_bytes(),
            message_2_count,
        );
        let keypair_1 =
            KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params_1);
        let keypair_2 =
            KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params_2);

        let mut messages_1: Vec<Fr> = (0..message_1_count - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect();
        let mut messages_2: Vec<Fr> = (0..message_2_count - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect();

        let same_msg_idx = 4;
        let same_msg = Fr::rand(&mut rng);
        messages_1.insert(same_msg_idx, same_msg);
        messages_2.insert(same_msg_idx, same_msg);

        // A particular message is same
        assert_eq!(messages_1[same_msg_idx], messages_2[same_msg_idx]);
        assert_ne!(messages_1, messages_2);

        let sig_1 = Signature23G1::<Bls12_381>::new(
            &mut rng,
            &messages_1,
            &keypair_1.secret_key,
            &params_1,
        )
        .unwrap();
        sig_1
            .verify(&messages_1, keypair_1.public_key.clone(), params_1.clone())
            .unwrap();

        let sig_2 = Signature23G1::<Bls12_381>::new(
            &mut rng,
            &messages_2,
            &keypair_2.secret_key,
            &params_2,
        )
        .unwrap();
        sig_2
            .verify(&messages_2, keypair_2.public_key.clone(), params_2.clone())
            .unwrap();

        // Add the same blinding for the message which has to be proven equal across messages
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

        // the witnesses of Schnorr protocol are not the messages alone but multiplied by randomness `r`
        // and thus using same randomness for both the protocols so that Schnorr responses can be compared
        // for equality.
        let same_randomness_for_sig = Fr::rand(&mut rng);
        let same_randomness_for_known_messages_commitment = Fr::rand(&mut rng);

        let pok_1 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            Some(same_randomness_for_sig),
            Some(same_randomness_for_known_messages_commitment),
            &sig_1,
            &params_1,
            messages_1.iter().enumerate().map(|(idx, message)| {
                if let Some(blinding) = blindings_1.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .unwrap();
        let pok_2 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            Some(same_randomness_for_sig),
            Some(same_randomness_for_known_messages_commitment),
            &sig_2,
            &params_2,
            messages_2.iter().enumerate().map(|(idx, message)| {
                if let Some(blinding) = blindings_2.remove(&idx) {
                    MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
                } else {
                    MessageOrBlinding::BlindMessageRandomly(message)
                }
            }),
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        pok_1
            .challenge_contribution(&BTreeMap::new(), &params_1, &mut chal_bytes_prover)
            .unwrap();
        pok_2
            .challenge_contribution(&BTreeMap::new(), &params_2, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof_1 = pok_1.gen_proof(&challenge_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&challenge_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes_verifier = vec![];
        proof_1
            .challenge_contribution(&BTreeMap::new(), &params_1, &mut chal_bytes_verifier)
            .unwrap();
        proof_2
            .challenge_contribution(&BTreeMap::new(), &params_2, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

        assert_eq!(
            proof_1.get_resp_for_known_messages_commitment(),
            proof_2.get_resp_for_known_messages_commitment()
        );

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
            .verify(
                &BTreeMap::new(),
                &challenge_verifier,
                keypair_1.public_key.clone(),
                params_1,
            )
            .unwrap();
        proof_2
            .verify(
                &BTreeMap::new(),
                &challenge_verifier,
                keypair_2.public_key.clone(),
                params_2,
            )
            .unwrap();
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
            None,
            None,
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
                proof_1.sc_resp.0[i + 2]
            );
        }

        // Test response when some messages are revealed
        let mut revealed_indices_2 = BTreeSet::new();
        revealed_indices_2.insert(0);
        revealed_indices_2.insert(2);
        revealed_indices_2.insert(5);
        let pok_2 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            None,
            None,
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
            proof_2.sc_resp.0[2]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(3, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp.0[2 + 1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(4, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp.0[2 + 2]
        );

        let mut revealed_indices_3 = BTreeSet::new();
        revealed_indices_3.insert(0);
        revealed_indices_3.insert(3);
        let pok_3 = PoKOfSignature23G1Protocol::init(
            &mut rng,
            None,
            None,
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
            proof_3.sc_resp.0[2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(2, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp.0[2 + 1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(4, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp.0[2 + 2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(5, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp.0[2 + 3]
        );

        // Reveal one message only
        for i in 0..message_count as usize {
            let mut revealed_indices = BTreeSet::new();
            revealed_indices.insert(i);
            let pok = PoKOfSignature23G1Protocol::init(
                &mut rng,
                None,
                None,
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
                        proof.sc_resp.0[j + 2 - 1]
                    );
                } else {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp.0[j + 2]
                    );
                }
            }
        }
    }

    #[test]
    fn test_PoK_multiple_sigs_with_randomized_pairing_check() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 5;
        let params =
            SignatureParams23G1::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), message_count);
        let keypair =
            KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(&mut rng, &params);

        let prepared_pk = PreparedPublicKeyG2::from(keypair.public_key.clone());
        let prepared_params = PreparedSignatureParams23G1::from(params.clone());

        test_serialization!(PreparedPublicKeyG2<Bls12_381>, prepared_pk);
        test_serialization!(PreparedSignatureParams23G1<Bls12_381>, prepared_params);

        let sig_count = 10;
        let mut msgs = vec![];
        let mut sigs = vec![];
        let mut chal_bytes_prover = vec![];
        let mut poks = vec![];
        let mut proofs = vec![];
        for i in 0..sig_count {
            msgs.push(
                (0..message_count)
                    .map(|_| Fr::rand(&mut rng))
                    .collect::<Vec<Fr>>(),
            );
            sigs.push(
                Signature23G1::<Bls12_381>::new(&mut rng, &msgs[i], &keypair.secret_key, &params)
                    .unwrap(),
            );
            let pok = PoKOfSignature23G1Protocol::init(
                &mut rng,
                None,
                None,
                &sigs[i],
                &params,
                msgs[i].iter().map(MessageOrBlinding::BlindMessageRandomly),
            )
            .unwrap();
            pok.challenge_contribution(&BTreeMap::new(), &params, &mut chal_bytes_prover)
                .unwrap();
            poks.push(pok);
        }

        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        for pok in poks {
            proofs.push(pok.gen_proof(&challenge_prover).unwrap());
        }

        let mut chal_bytes_verifier = vec![];

        for proof in &proofs {
            proof
                .challenge_contribution(&BTreeMap::new(), &params, &mut chal_bytes_verifier)
                .unwrap();
        }

        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

        let start = Instant::now();
        for proof in proofs.clone() {
            proof
                .verify(
                    &BTreeMap::new(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                )
                .unwrap();
        }
        println!("Time to verify {} sigs: {:?}", sig_count, start.elapsed());

        let start = Instant::now();
        for proof in proofs.clone() {
            proof
                .verify(
                    &BTreeMap::new(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                )
                .unwrap();
        }
        println!(
            "Time to verify {} sigs using prepared public key and params: {:?}",
            sig_count,
            start.elapsed()
        );

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        let start = Instant::now();
        for proof in proofs.clone() {
            proof
                .verify_with_randomized_pairing_checker(
                    &BTreeMap::new(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &mut pairing_checker,
                )
                .unwrap();
        }
        assert!(pairing_checker.verify());
        println!(
            "Time to verify {} sigs using randomized pairing checker: {:?}",
            sig_count,
            start.elapsed()
        );

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);
        let start = Instant::now();
        for proof in proofs.clone() {
            proof
                .verify_with_randomized_pairing_checker(
                    &BTreeMap::new(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &mut pairing_checker,
                )
                .unwrap();
        }
        assert!(pairing_checker.verify());
        println!(
            "Time to verify {} sigs using prepared public key and params and randomized pairing checker: {:?}",
            sig_count,
            start.elapsed()
        );
    }
}
