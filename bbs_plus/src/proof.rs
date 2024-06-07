//! Proof of knowledge of BBS+ signature and corresponding messages as per section 4.5 of the BBS+ paper
//! # Examples
//!
//! Creating proof of knowledge of signature and verifying it:
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use bbs_plus::setup::{SignatureParamsG1, KeypairG2};
//! use bbs_plus::signature::SignatureG1;
//! use bbs_plus::proof::PoKOfSignatureG1Protocol;
//! use ark_std::collections::{BTreeSet, BTreeMap};
//!
//! let params_g1 = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, 5);
//! let keypair_g2 = KeypairG2::<Bls12_381>::generate(&mut rng, &params_g1);
//!
//! let pk_g2 = &keypair_g2.public_key;
//!
//! // Verifiers should check that the signature parameters and public key are valid before verifying
//! // any signatures. This just needs to be done once when the verifier fetches/receives them.
//!
//! assert!(params_g1.is_valid());
//! assert!(pk_g2.is_valid());
//!
//! // `messages` contains elements of the scalar field
//! let sig_g1 = SignatureG1::<Bls12_381>::new(&mut rng, &messages, &keypair_g2.secret_key, &params_g1).unwrap();
//!
//! let mut blindings = BTreeMap::new();
//! let mut revealed_indices = BTreeSet::new();
//!
//! // Populate `blindings` with message index and corresponding blinding
//! // Populate `revealed_indices` with 0-based indices of revealed messages
//!
//! let pok = PoKOfSignatureG1Protocol::init(
//!             &mut rng,
//!             &sig_g1,
//!             &params_g1,
//!             &messages,
//!             blindings,
//!             &revealed_indices,
//!         )
//!         .unwrap();
//!
//! // challenge is generated (see tests)
//! let proof = pok.gen_proof(&challenge).unwrap();
//!
//! let mut revealed_msgs = BTreeMap::new();
//! proof
//!             .verify(
//!                 &revealed_msgs,
//!                 &challenge,
//!                 pk_g2,
//!                 &params_g1,
//!             )
//!             .unwrap();
//!
//! // See tests for more examples
//! ```
use crate::{
    error::BBSPlusError,
    prelude::PreparedPublicKeyG2,
    setup::{PreparedSignatureParamsG1, SignatureParamsG1},
    signature::SignatureG1,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, Zero};
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
    signature::{split_messages_and_blindings, MessageOrBlinding, MultiMessageSignatureParams},
};
use itertools::multiunzip;
use schnorr_pok::{
    discrete_log::{PokTwoDiscreteLogs, PokTwoDiscreteLogsProtocol},
    error::SchnorrError,
    SchnorrCommitment, SchnorrResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol to prove knowledge of BBS+ signature in group G1.
/// The BBS+ signature proves validity of a set of messages {m_i}, i in I. This stateful protocol proves knowledge of such
/// a signature whilst selectively disclosing only a subset of the messages, {m_i} for i in a disclosed set D. The
/// protocol randomizes the initial BBS+ signature, then conducts 2 Schnorr PoK protocols to prove exponent knowledge
/// for the relations in section 4.5 of the paper (refer to top). It contains commitments (Schnorr step 1; refer to schnorr_pok)
/// and witnesses to both Schnorr protocols in `sc_comm_` and `sc_wits_` respectively. The protocol executes in 2 phases,
/// pre-challenge (`init`) which is used to create the challenge and post-challenge (`gen_proof`). Thus, several instances of
/// the protocol can be used together where the pre-challenge phase of all protocols is used to create a combined challenge
/// and then that challenge is used in post-challenge phase of all protocols.
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
pub struct PoKOfSignatureG1Protocol<E: Pairing> {
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub A_prime: E::G1Affine,
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub d: E::G1Affine,
    /// For proving relation `A_bar - d = A_prime * -e + h_0 * r2`
    pub sc_comm_1: PokTwoDiscreteLogsProtocol<E::G1Affine>,
    /// For proving relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + {h_0}*{-s'} + sum_{j notin D}(h_j*m_j)`
    pub sc_comm_2: SchnorrCommitment<E::G1Affine>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    sc_wits_2: Vec<E::ScalarField>,
}

/// Proof of knowledge of BBS+ signature in G1. It contains the randomized signature, commitment (Schnorr step 1)
/// and response (Schnorr step 3) to both Schnorr protocols in `T_` and `sc_resp_`
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PoKOfSignatureG1Proof<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A_prime: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub A_bar: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub d: E::G1Affine,
    /// Proof of relation `A_bar - d = A_prime * -e + h_0 * r2`
    pub sc_resp_1: PokTwoDiscreteLogs<E::G1Affine>,
    /// Proof of relation `g1 + h1*m1 + h2*m2 +.... + h_i*m_i` = `d*r3 + {h_0}*{-s'} + h1*{-m1} + h2*{-m2} + .... + h_j*{-m_j}` for all disclosed messages `m_i` and for all undisclosed messages `m_j`
    #[serde_as(as = "ArkObjectBytes")]
    pub T2: E::G1Affine,
    pub sc_resp_2: SchnorrResponse<E::G1Affine>,
}

impl<E: Pairing> PoKOfSignatureG1Protocol<E> {
    /// Initiate the protocol, i.e. pre-challenge phase. This will generate the randomized signature and execute
    /// the commit-to-randomness step (Step 1) of both Schnorr protocols.
    /// Accepts an iterator of messages. Each message can be either randomly blinded, revealed, or blinded using supplied blinding.
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        signature: &SignatureG1<E>,
        params: &SignatureParamsG1<E>,
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

        let mut r1 = E::ScalarField::rand(rng);
        while r1.is_zero() {
            r1 = E::ScalarField::rand(rng);
        }
        let r2 = E::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        // b = (e+x) * A = g1 + h_0*s + sum(h_i*m_i) for all i in I
        let b = params.b(messages.iter().enumerate(), &signature.s)?;

        // A' = A * r1
        let A_prime = signature.A.mul_bigint(r1.into_bigint());
        // A_bar = r1 * b - e * A'
        let b_r1 = b * r1;
        let A_bar = b_r1 - (A_prime.mul_bigint(signature.e.into_bigint()));
        // d = r1 * b - r2 * h_0
        let d = b_r1 - params.h_0.mul_bigint(r2.into_bigint());
        let d_affine = d.into_affine();
        // s' = s - r2*r3
        let s_prime = signature.s - (r2 * r3);

        // Following is the 1st step of the Schnorr protocol for the relation pi in the paper. pi is a
        // conjunction of 2 relations:
        // 1. `A_bar - d == A'*{-e} + h_0*r2`
        // 2. `g1 + \sum_{i \in D}(h_i*m_i)` = `d*r3 + {h_0}*{-s'} + \sum_{j \notin D}(h_j*{-m_j})`
        // for all disclosed messages `m_i` and for all undisclosed messages `m_j`.
        // For each of the above relations, a Schnorr protocol is executed; the first to prove knowledge
        // of `(e, r2)`, and the second of `(r3, s', {m_j}_{j \notin D})`. The secret knowledge items are
        // referred to as witnesses, and the public items as instances.
        let A_prime_affine = A_prime.into_affine();

        // Commit to randomness with `h_0` and `A'`, i.e. `bases_1[0]*randomness_1[0] + bases_1[1]*randomness_1[1]`
        let sc_comm_1 = PokTwoDiscreteLogsProtocol::init(
            -signature.e,
            E::ScalarField::rand(rng),
            &A_prime_affine,
            r2,
            E::ScalarField::rand(rng),
            &params.h_0,
        );

        // For proving relation `g1 + \sum_{i \in D}(h_i*m_i)` = `d*r3 + {h_0}*{-s_prime} + \sum_{j \notin D}(h_j*{-m_j})`
        // for all disclosed messages `m_i` and for all undisclosed messages `m_j`, usually the number of disclosed
        // messages is much less than the number of undisclosed messages; so it is better to avoid negations in
        // undisclosed messages and do them in disclosed messaged. So negate both sides of the relation to get:
        // `d*{-r3} + h_0*s_prime + \sum_{j \notin D}(h_j*m_j)` = `-g1 + \sum_{i \in D}(h_i*{-m_i})`
        // Moreover `-g1 + \sum_{i \in D}(h_i*{-m_i})` is public and can be efficiently computed as -(g1 + \sum_{i \in D}(h_i*{m_i}))
        // Knowledge of all unrevealed messages `m_j` need to be proven in addition to knowledge of `-r3` and `s'`. Thus
        // all `m_j`, `-r3` and `s'` are the witnesses, while all `h_j`, `d`, `h_0` and `-g1 + \sum_{i \in D}(h_i*{-m_i})` is the instance.

        // Iterator of tuples of form `(h_i, blinding_i, message_i)`
        let h_blinding_message = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.h[idx], blinding, messages[idx]));

        let (bases_2, randomness_2, wits_2): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            h_blinding_message
                .into_iter()
                .chain([(d_affine, rand(rng), -r3), (params.h_0, rand(rng), s_prime)]),
        );

        // Commit to randomness, i.e. `bases_2[0]*randomness_2[0] + bases_2[1]*randomness_2[1] + .... bases_2[j]*randomness_2[j]`
        let sc_comm_2 = SchnorrCommitment::new(&bases_2, randomness_2);

        Ok(Self {
            A_prime: A_prime_affine,
            A_bar: A_bar.into_affine(),
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
        params: &SignatureParamsG1<E>,
        writer: W,
    ) -> Result<(), BBSPlusError> {
        Self::compute_challenge_contribution(
            &self.A_prime,
            &self.A_bar,
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
    ) -> Result<PoKOfSignatureG1Proof<E>, BBSPlusError> {
        // Schnorr response for relation `A_bar - d == A'*{-e} + h_0*r2`
        let sc_resp_1 = mem::take(&mut self.sc_comm_1).gen_proof(challenge);
        // Schnorr response for relation `g1 + \sum_{i in D}(h_i*m_i)` = `d*r3 + {h_0}*{-s'} + \sum_{j not in D}(h_j*{-m_j})`
        let sc_resp_2 = self.sc_comm_2.response(&self.sc_wits_2, challenge)?;

        Ok(PoKOfSignatureG1Proof {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
            d: self.d,
            sc_resp_1,
            T2: self.sc_comm_2.t,
            sc_resp_2,
        })
    }

    /// Helper that serializes state to get challenge contribution. Serialized the randomized signature,
    /// and commitments and instances for both Schnorr protocols
    pub fn compute_challenge_contribution<W: Write>(
        A_prime: &E::G1Affine,
        A_bar: &E::G1Affine,
        d: &E::G1Affine,
        T1: &E::G1Affine,
        T2: &E::G1Affine,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParamsG1<E>,
        mut writer: W,
    ) -> Result<(), BBSPlusError> {
        A_prime.serialize_compressed(&mut writer)?;
        A_bar.serialize_compressed(&mut writer)?;
        d.serialize_compressed(&mut writer)?;
        params.h_0.serialize_compressed(&mut writer)?;
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

impl<E: Pairing> PoKOfSignatureG1Proof<E> {
    /// Verify if the proof is valid. Assumes that the public key and parameters have been
    /// validated already.
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKeyG2<E>>,
        params: impl Into<PreparedSignatureParamsG1<E>>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h0 = params.h_0;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h0, h)?;

        // Verify the randomized signature
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.A_prime),
                E::G1Prepared::from(-(self.A_bar.into_group())),
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
        params: impl Into<PreparedSignatureParamsG1<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), BBSPlusError> {
        let params = params.into();
        let g1 = params.g1;
        let g2 = params.g2;
        let h0 = params.h_0;
        let h = params.h;
        self.verify_except_pairings(revealed_msgs, challenge, g1, h0, h)?;
        pairing_checker.add_sources(&self.A_prime, pk.into().0, &self.A_bar, g2);
        Ok(())
    }

    /// For the verifier to independently calculate the challenge
    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        params: &SignatureParamsG1<E>,
        writer: W,
    ) -> Result<(), BBSPlusError> {
        PoKOfSignatureG1Protocol::compute_challenge_contribution(
            &self.A_prime,
            &self.A_bar,
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
        Ok(self.sc_resp_2.get_response(adjusted_idx)?)
    }

    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, E::ScalarField>,
        challenge: &E::ScalarField,
        g1: E::G1Affine,
        h_0: E::G1Affine,
        h: Vec<E::G1Affine>,
    ) -> Result<(), BBSPlusError> {
        // Verify the 1st Schnorr proof
        // A_bar - d
        let A_bar_minus_d = (self.A_bar.into_group() - self.d.into_group()).into_affine();
        if !self
            .sc_resp_1
            .verify(&A_bar_minus_d, &self.A_prime, &h_0, challenge)
        {
            return Err(BBSPlusError::FirstSchnorrVerificationFailed);
        }

        // Verify the 2nd Schnorr proof
        let mut bases_2 = Vec::with_capacity(2 + h.len() - revealed_msgs.len());

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
        bases_2.push(h_0);
        // pr = -g1 + \sum_{i in D}(h_i*{-m_i}) = -(g1 + \sum_{i in D}(h_i*{m_i}))
        let pr = -E::G1::msm_unchecked(&bases_revealed, &exponents) - g1;
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
        h_0: E::G1Affine,
        h: Vec<E::G1Affine>,
    ) -> Result<(), BBSPlusError> {
        if self.A_prime.is_zero() {
            return Err(BBSPlusError::ZeroSignature);
        }
        self.verify_schnorr_proofs(revealed_msgs, challenge, g1, h_0, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{setup::KeypairG2, test_serialization};
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
        SignatureParamsG1<Bls12_381>,
        KeypairG2<Bls12_381>,
        SignatureG1<Bls12_381>,
    ) {
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
        let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
        let sig =
            SignatureG1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
        (messages, params, keypair, sig)
    }

    #[macro_export]
    macro_rules! gen_test_pok_signature_revealed_message {
        ($protocol: ident, $proof: ident) => {{
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
            let pok = $protocol::init(
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
            proof_create_duration += start.elapsed();

            // Protocol can be serialized
            test_serialization!($protocol<Bls12_381>, pok);

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
            test_serialization!($proof<Bls12_381>, proof);

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
        }};
    }

    #[macro_export]
    macro_rules! gen_test_PoK_multiple_sigs_with_same_msg {
        ($params: ident, $sig: ident, $fn_name: ident, $protocol: ident) => {{
            // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
            // Knowledge of 2 signatures and their corresponding messages is being proven.

            let mut rng = StdRng::seed_from_u64(0u64);
            let message_1_count = 10;
            let message_2_count = 7;
            let params_1 =
                $params::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), message_1_count);
            let params_2 =
                $params::<Bls12_381>::new::<Blake2b512>("test-1".as_bytes(), message_2_count);
            let keypair_1 = KeypairG2::<Bls12_381>::$fn_name(&mut rng, &params_1);
            let keypair_2 = KeypairG2::<Bls12_381>::$fn_name(&mut rng, &params_2);

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

            let sig_1 =
                $sig::<Bls12_381>::new(&mut rng, &messages_1, &keypair_1.secret_key, &params_1)
                    .unwrap();
            sig_1
                .verify(&messages_1, keypair_1.public_key.clone(), params_1.clone())
                .unwrap();

            let sig_2 =
                $sig::<Bls12_381>::new(&mut rng, &messages_2, &keypair_2.secret_key, &params_2)
                    .unwrap();
            sig_2
                .verify(&messages_2, keypair_2.public_key.clone(), params_2.clone())
                .unwrap();

            // Add the same blinding for the message which has to be proven equal across signatures
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

            let pok_1 = $protocol::init(
                &mut rng,
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
            let pok_2 = $protocol::init(
                &mut rng,
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
        }}
    }

    #[macro_export]
    macro_rules! gen_test_PoK_multiple_sigs_with_randomized_pairing_check {
        ($params: ident, $prepared_params: ident, $sig: ident, $fn_name: ident, $protocol: ident) => {{
            let mut rng = StdRng::seed_from_u64(0u64);
            let message_count = 5;
            let params =
                $params::<Bls12_381>::new::<Blake2b512>("test".as_bytes(), message_count);
            let keypair = KeypairG2::<Bls12_381>::$fn_name(&mut rng, &params);

            let prepared_pk = PreparedPublicKeyG2::from(keypair.public_key.clone());
            let prepared_params = $prepared_params::from(params.clone());

            test_serialization!(PreparedPublicKeyG2<Bls12_381>, prepared_pk);
            test_serialization!($prepared_params<Bls12_381>, prepared_params);

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
                    $sig::<Bls12_381>::new(&mut rng, &msgs[i], &keypair.secret_key, &params)
                        .unwrap(),
                );
                let pok = $protocol::init(
                    &mut rng,
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
        }}
    }

    #[macro_export]
    macro_rules! gen_test_pok_signature_schnorr_response {
        ($setup_fn_name: ident, $protocol: ident, $resp_name: ident) => {{
            // Test response from Schnorr protocol from various messages
            let mut rng = StdRng::seed_from_u64(0u64);
            let message_count = 6;
            let (messages, params, _keypair, sig) = $setup_fn_name(&mut rng, message_count);

            let challenge = Fr::rand(&mut rng);

            // Test response when no hidden message
            let revealed_indices_1 = BTreeSet::new();
            let pok_1 = $protocol::init(
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
                    proof_1.$resp_name.0[i]
                );
            }

            // Test response when some messages are revealed
            let mut revealed_indices_2 = BTreeSet::new();
            revealed_indices_2.insert(0);
            revealed_indices_2.insert(2);
            revealed_indices_2.insert(5);
            let pok_2 = $protocol::init(
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
                proof_2.$resp_name.0[0]
            );
            assert_eq!(
                *proof_2
                    .get_resp_for_message(3, &revealed_indices_2)
                    .unwrap(),
                proof_2.$resp_name.0[1]
            );
            assert_eq!(
                *proof_2
                    .get_resp_for_message(4, &revealed_indices_2)
                    .unwrap(),
                proof_2.$resp_name.0[2]
            );

            let mut revealed_indices_3 = BTreeSet::new();
            revealed_indices_3.insert(0);
            revealed_indices_3.insert(3);
            let pok_3 = $protocol::init(
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
                proof_3.$resp_name.0[0]
            );
            assert_eq!(
                *proof_3
                    .get_resp_for_message(2, &revealed_indices_3)
                    .unwrap(),
                proof_3.$resp_name.0[1]
            );
            assert_eq!(
                *proof_3
                    .get_resp_for_message(4, &revealed_indices_3)
                    .unwrap(),
                proof_3.$resp_name.0[2]
            );
            assert_eq!(
                *proof_3
                    .get_resp_for_message(5, &revealed_indices_3)
                    .unwrap(),
                proof_3.$resp_name.0[3]
            );

            // Reveal one message only
            for i in 0..message_count as usize {
                let mut revealed_indices = BTreeSet::new();
                revealed_indices.insert(i);
                let pok = $protocol::init(
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
                            proof.$resp_name.0[j - 1]
                        );
                    } else {
                        assert_eq!(
                            *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                            proof.$resp_name.0[j]
                        );
                    }
                }
            }
        }}
    }

    #[test]
    fn pok_signature_revealed_message() {
        gen_test_pok_signature_revealed_message!(PoKOfSignatureG1Protocol, PoKOfSignatureG1Proof)
    }

    #[test]
    fn test_PoK_multiple_sigs_with_same_msg() {
        gen_test_PoK_multiple_sigs_with_same_msg!(
            SignatureParamsG1,
            SignatureG1,
            generate_using_rng,
            PoKOfSignatureG1Protocol
        )
    }

    #[test]
    fn pok_signature_schnorr_response() {
        gen_test_pok_signature_schnorr_response!(sig_setup, PoKOfSignatureG1Protocol, sc_resp_2);
    }

    #[test]
    fn test_PoK_multiple_sigs_with_randomized_pairing_check() {
        gen_test_PoK_multiple_sigs_with_randomized_pairing_check!(
            SignatureParamsG1,
            PreparedSignatureParamsG1,
            SignatureG1,
            generate_using_rng,
            PoKOfSignatureG1Protocol
        )
    }
}
