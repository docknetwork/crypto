//! Proof of knowledge of the signature and corresponding messages as per section 4.5 of the paper
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
//! // `messages` contains elements of the scalar field
//! let sig_g1 = SignatureG1::<Bls12_381>::new(&mut rng, &messages, &keypair_g2.secret_key, &params_g1).unwrap();
//! let mut blindings = BTreeMap::new();
//! let mut revealed_indices = BTreeSet::new();
//! // Populate blindings with message index and corresponding blinding
//! // Populate revealed_indices with 0-based indices of revealed messages
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
//!                 &keypair_g2.public_key,
//!                 &params_g1,
//!             )
//!             .unwrap();
//!
//! // See tests for more examples
//! ```

use crate::error::BBSPlusError;
use crate::setup::{PublicKeyG2, SignatureParamsG1};
use crate::signature::SignatureG1;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    io::{Read, Write},
    rand::RngCore,
    vec,
    vec::Vec,
    One, UniformRand,
};
use schnorr_pok::{SchnorrCommitment, SchnorrResponse};

pub use serialization::*;

/// Stateful protocol to prove knowledge of signature. The protocol randomizes the signature and executes 2 Schnorr
/// proof of knowledge protocols with the verifier in addition to verification of the randomized signature.
/// It contains commitment (Schnorr step 1) and witnesses to both Schnorr protocols in `sc_comm_` and `sc_wits_`
/// respectively. The protocol executes in 2 phases, pre-challenge (`init`) which is used to create the
/// challenge and post-challenge (`gen_proof`). Thus, several instances of the protocol can be used
/// together where the pre-challenge phase of all protocols is used to create a combined challenge and then
/// that challenge is used in post-challenge phase of all protocols.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoKOfSignatureG1Protocol<E: PairingEngine> {
    pub A_prime: E::G1Affine,
    pub A_bar: E::G1Affine,
    pub d: E::G1Affine,
    /// For proving relation a_bar / d == a_prime^{-e} * h_0^r2
    pub sc_comm_1: SchnorrCommitment<E::G1Affine>,
    sc_wits_1: [E::Fr; 2],
    /// For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub sc_comm_2: SchnorrCommitment<E::G1Affine>,
    sc_wits_2: Vec<E::Fr>,
}

/// Proof of knowledge of the signature. It contains the randomized signature, commitment (Schnorr step 1)
/// and response (Schnorr step 3) to both Schnorr protocols in `T_` and `sc_resp_`
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoKOfSignatureG1Proof<E: PairingEngine> {
    pub A_prime: E::G1Affine,
    pub A_bar: E::G1Affine,
    pub d: E::G1Affine,
    /// Proof of relation a_bar / d == a_prime^{-e} * h_0^r2
    pub T1: E::G1Affine,
    pub sc_resp_1: SchnorrResponse<E::G1Affine>,
    /// Proof of relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
    pub T2: E::G1Affine,
    pub sc_resp_2: SchnorrResponse<E::G1Affine>,
}

impl<E> PoKOfSignatureG1Protocol<E>
where
    E: PairingEngine,
{
    /// Initiate the protocol, i.e. pre-challenge phase. This will generate the randomized signature and execute
    /// the commit-to-randomness step (step 1) of both Schnorr protocols. Accepts the indices of the
    /// multi-message which are revealed to the verifier and thus their knowledge is not proven.
    /// Accepts blindings (randomness) to be used for any messages in the multi-message. This is useful
    /// when some messages need to be proven same as they will generate same response (step 3 in Schnorr protocol).
    /// If extra blindings are passed, or passed for revealed messages, they are ignored. eg. If the
    /// multi-message is `[m_0, m_1, m_2, m_3, m_4, m_5]` and the user is providing blindings for messages
    /// `m_0` and `m_2` and revealing messages `m_3`, `m_4` and `m_5`, `blindings` is `(0 -> m_0), (2 -> m_2)`
    /// and `revealed_msg_indices` is `(3 -> m_3), (4 -> m_4), (5 -> m_5)`
    pub fn init<R: RngCore>(
        rng: &mut R,
        signature: &SignatureG1<E>,
        params: &SignatureParamsG1<E>,
        messages: &[E::Fr],
        mut blindings: BTreeMap<usize, E::Fr>,
        revealed_msg_indices: BTreeSet<usize>,
    ) -> Result<Self, BBSPlusError> {
        if messages.len() != params.max_message_count() {
            return Err(BBSPlusError::MessageCountIncompatibleWithSigParams);
        }

        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(BBSPlusError::InvalidMessageIdx);
            }
        }

        // Generate any blindings that are not explicitly passed
        for i in 0..messages.len() {
            if !revealed_msg_indices.contains(&i) && !blindings.contains_key(&i) {
                blindings.insert(i, E::Fr::rand(rng));
            }
        }

        let r1 = E::Fr::rand(rng);
        let r2 = E::Fr::rand(rng);
        let r3 = r1.inverse().unwrap();

        let b = params.b(
            messages
                .iter()
                .enumerate()
                .collect::<BTreeMap<usize, &E::Fr>>(),
            &signature.s,
        )?;
        // A' = A * r1
        let A_prime = signature.A.mul(r1.into_repr());
        let A_prime_affine = A_prime.into_affine();
        // A_bar = r1 * b - e * A'
        let mut b_r1 = b.clone();
        b_r1 *= r1;
        let A_bar = b_r1 - (A_prime_affine.mul(signature.e.into_repr()));
        // d = r1 * b - r2 * h_0
        let d = b_r1 - params.h_0.mul(r2.into_repr());
        let d_affine = d.into_affine();
        // s' = s - r2*r3
        let s_prime = signature.s - (r2 * r3);

        // For proving relation a_bar / d == a_prime^{-e} * h_0^r2
        let bases_1 = [A_prime_affine, params.h_0.clone()];
        let wits_1 = [-signature.e, r2];
        let sc_comm_1 = SchnorrCommitment::new(&bases_1, vec![E::Fr::rand(rng), E::Fr::rand(rng)]);

        // For proving relation g1 * h1^m1 * h2^m2.... for all disclosed messages m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_j
        // Usually the number of disclosed messages is much less than the number of undisclosed messages, its better to avoid negations in hidden messages and do
        // them in revealed messages. So transform the relation
        // g1 * h1^m1 * h2^m2.... * h_i^m_i for disclosed messages m_i = d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... * h_j^-m_j for all undisclosed messages m_j
        // into
        // d^{-r3} * h_0^s_prime * h1^m1 * h2^m2.... * h_j^m_j = g1 * h1^-m1 * h2^-m2.... * h_i^-m_i. Moreover g1 * h1^-m1 * h2^-m2.... * h_i^-m_i is public
        // and can be efficiently computed as (g1 * h1^m1 * h2^m2.... * h_i^m_i)^-1 and inverse in elliptic group is a point negation which is very cheap

        let mut bases_2 = Vec::with_capacity(2 + blindings.len());
        let mut scalars_2 = Vec::with_capacity(2 + blindings.len());
        let mut wits_2 = Vec::with_capacity(2 + blindings.len());
        let [A_prime_affine, h_0] = bases_1;
        bases_2.push(d_affine);
        scalars_2.push(E::Fr::rand(rng));
        wits_2.push(-r3);
        bases_2.push(h_0);
        scalars_2.push(E::Fr::rand(rng));
        wits_2.push(s_prime);

        for i in 0..messages.len() {
            if !revealed_msg_indices.contains(&i) {
                bases_2.push(params.h[i].clone());
                scalars_2.push(blindings.remove(&i).unwrap());
                wits_2.push(messages[i].clone());
            }
        }

        let sc_comm_2 = SchnorrCommitment::new(&bases_2, scalars_2);
        Ok(Self {
            A_prime: A_prime_affine,
            A_bar: A_bar.into_affine(),
            d: bases_2.remove(0),
            sc_comm_1,
            sc_wits_1: wits_1,
            sc_comm_2,
            sc_wits_2: wits_2,
        })
    }

    /// Get the contribution of this protocol towards the challenge.
    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, E::Fr>,
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

    /// Generate proof. post-challenge phase of the protocol.
    pub fn gen_proof(self, challenge: &E::Fr) -> Result<PoKOfSignatureG1Proof<E>, BBSPlusError> {
        let resp_1 = self.sc_comm_1.response(&self.sc_wits_1, challenge)?;
        let resp_2 = self.sc_comm_2.response(&self.sc_wits_2, challenge)?;

        Ok(PoKOfSignatureG1Proof {
            A_prime: self.A_prime,
            A_bar: self.A_bar,
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
        A_prime: &E::G1Affine,
        A_bar: &E::G1Affine,
        d: &E::G1Affine,
        T1: &E::G1Affine,
        T2: &E::G1Affine,
        revealed_msgs: &BTreeMap<usize, E::Fr>,
        params: &SignatureParamsG1<E>,
        mut writer: W,
    ) -> Result<(), BBSPlusError> {
        // NOTE: Using `_unchecked` variants for serialization for speed
        A_bar.serialize_unchecked(&mut writer)?;

        // For 1st Schnorr
        A_prime.serialize_unchecked(&mut writer)?;
        params.h_0.serialize_unchecked(&mut writer)?;
        // A_bar - d
        let mut A_bar_minus_d = A_bar.into_projective();
        A_bar_minus_d -= d.into_projective();
        let A_bar_minus_d = A_bar_minus_d.into_affine();
        A_bar_minus_d.serialize_unchecked(&mut writer)?;
        T1.serialize_unchecked(&mut writer)?;

        // For 2nd Schnorr
        // `bases_disclosed` and `exponents` below are used to create g1 * h1^-m1 * h2^-m2.... for all disclosed messages m_i
        let mut bases_disclosed = Vec::with_capacity(1 + revealed_msgs.len());
        let mut exponents = Vec::with_capacity(1 + revealed_msgs.len());

        params.g1.serialize_unchecked(&mut writer)?;
        bases_disclosed.push(params.g1);
        let r = E::Fr::one().into_repr();
        r.serialize_unchecked(&mut writer)?;
        exponents.push(r);
        for (i, msg) in revealed_msgs {
            assert!(*i < params.h.len());
            params.h[*i].serialize_unchecked(&mut writer)?;
            bases_disclosed.push(params.h[*i]);
            let r = msg.into_repr();
            r.serialize_unchecked(&mut writer)?;
            exponents.push(r);
        }
        VariableBaseMSM::multi_scalar_mul(&bases_disclosed, &exponents)
            .serialize_unchecked(&mut writer)?;
        T2.serialize_unchecked(&mut writer).map_err(|e| e.into())
    }
}

impl<E> PoKOfSignatureG1Proof<E>
where
    E: PairingEngine,
{
    /// Verify is the proof is valid
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, E::Fr>,
        challenge: &E::Fr,
        pk: &PublicKeyG2<E>,
        params: &SignatureParamsG1<E>,
    ) -> Result<(), BBSPlusError> {
        if self.A_prime.is_zero() {
            return Err(BBSPlusError::ZeroSignature);
        }

        // Verify the randomized signature
        if !E::product_of_pairings(&[
            (E::G1Prepared::from(self.A_prime), E::G2Prepared::from(pk.w)),
            (
                E::G1Prepared::from(-self.A_bar),
                E::G2Prepared::from(params.g2),
            ),
        ])
        .is_one()
        {
            return Err(BBSPlusError::PairingCheckFailed);
        }

        // Verify the 1st Schnorr proof
        let bases_1 = [self.A_prime, params.h_0];
        // A_bar - d
        let mut A_bar_minus_d = self.A_bar.into_projective();
        A_bar_minus_d -= self.d.into_projective();
        let A_bar_minus_d = A_bar_minus_d.into_affine();
        if !self
            .sc_resp_1
            .is_valid(&bases_1, &A_bar_minus_d, &self.T1, challenge)?
        {
            return Err(BBSPlusError::FirstSchnorrVerificationFailed);
        }

        // Verify the 2nd Schnorr proof
        let mut bases_2 = Vec::with_capacity(2 + params.max_message_count() - revealed_msgs.len());
        bases_2.push(self.d);
        bases_2.push(params.h_0);

        let mut bases_disclosed = Vec::with_capacity(1 + revealed_msgs.len());
        let mut exponents = Vec::with_capacity(1 + revealed_msgs.len());
        // XXX: g1 should come from a setup param and not generator
        bases_disclosed.push(params.g1);
        exponents.push(E::Fr::one().into_repr());
        for i in 0..params.max_message_count() {
            if revealed_msgs.contains_key(&i) {
                let message = revealed_msgs.get(&i).unwrap();
                bases_disclosed.push(params.h[i]);
                exponents.push(message.into_repr());
            } else {
                bases_2.push(params.h[i]);
            }
        }
        // pr = g1 * h1^-m1 * h2^-m2.... = (g1 * h1^m1 * h2^m2....)^-1 for all disclosed messages m_i
        let pr = -VariableBaseMSM::multi_scalar_mul(&bases_disclosed, &exponents);
        let pr = pr.into_affine();
        if !self
            .sc_resp_2
            .is_valid(&bases_2, &pr, &self.T2, challenge)?
        {
            return Err(BBSPlusError::SecondSchnorrVerificationFailed);
        }

        Ok(())
    }

    /// For the verifier to independently calculate the challenge
    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, E::Fr>,
        params: &SignatureParamsG1<E>,
        writer: W,
    ) -> Result<(), BBSPlusError> {
        PoKOfSignatureG1Protocol::compute_challenge_contribution(
            &self.A_prime,
            &self.A_bar,
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
    ) -> Result<&E::Fr, BBSPlusError> {
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
        // 2 added to the index, since 0th and 1st index are reserved for `s_prime` and `r2`
        let r = self.sc_resp_2.get_response(2 + adjusted_idx)?;
        Ok(r)
    }
}

mod serialization {
    use super::*;

    impl<E: PairingEngine> CanonicalSerialize for PoKOfSignatureG1Protocol<E> {
        fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            self.A_prime.serialize(&mut writer)?;
            self.A_bar.serialize(&mut writer)?;
            self.d.serialize(&mut writer)?;
            self.sc_comm_1.serialize(&mut writer)?;
            self.sc_wits_1[0].serialize(&mut writer)?;
            self.sc_wits_1[1].serialize(&mut writer)?;
            self.sc_comm_2.serialize(&mut writer)?;
            self.sc_wits_2.serialize(&mut writer)
        }

        fn serialized_size(&self) -> usize {
            self.A_prime.serialized_size()
                + self.A_bar.serialized_size()
                + self.d.serialized_size()
                + self.sc_comm_1.serialized_size()
                + self.sc_wits_1[0].serialized_size()
                + self.sc_wits_1[1].serialized_size()
                + self.sc_comm_2.serialized_size()
                + self.sc_wits_2.serialized_size()
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            self.A_prime.serialize_uncompressed(&mut writer)?;
            self.A_bar.serialize_uncompressed(&mut writer)?;
            self.d.serialize_uncompressed(&mut writer)?;
            self.sc_comm_1.serialize_uncompressed(&mut writer)?;
            self.sc_wits_1[0].serialize(&mut writer)?;
            self.sc_wits_1[1].serialize(&mut writer)?;
            self.sc_comm_2.serialize_uncompressed(&mut writer)?;
            self.sc_wits_2.serialize(&mut writer)
        }

        fn serialize_unchecked<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
            self.A_prime.serialize_unchecked(&mut writer)?;
            self.A_bar.serialize_unchecked(&mut writer)?;
            self.d.serialize_unchecked(&mut writer)?;
            self.sc_comm_1.serialize_unchecked(&mut writer)?;
            self.sc_wits_1[0].serialize(&mut writer)?;
            self.sc_wits_1[1].serialize(&mut writer)?;
            self.sc_comm_2.serialize_unchecked(&mut writer)?;
            self.sc_wits_2.serialize_unchecked(&mut writer)
        }

        fn uncompressed_size(&self) -> usize {
            self.A_prime.uncompressed_size()
                + self.A_bar.uncompressed_size()
                + self.d.uncompressed_size()
                + self.sc_comm_1.uncompressed_size()
                + self.sc_wits_1[0].serialized_size()
                + self.sc_wits_1[1].serialized_size()
                + self.sc_comm_2.uncompressed_size()
                + self.sc_wits_2.serialized_size()
        }
    }

    impl<E: PairingEngine> CanonicalDeserialize for PoKOfSignatureG1Protocol<E> {
        fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let A_prime = E::G1Affine::deserialize(&mut reader)?;
            let A_bar = E::G1Affine::deserialize(&mut reader)?;
            let d = E::G1Affine::deserialize(&mut reader)?;
            let sc_comm_1 = <SchnorrCommitment<E::G1Affine>>::deserialize(&mut reader)?;
            let sc_wits_1 = [
                E::Fr::deserialize(&mut reader)?,
                E::Fr::deserialize(&mut reader)?,
            ];
            let sc_comm_2 = <SchnorrCommitment<E::G1Affine>>::deserialize(&mut reader)?;
            let sc_wits_2 = <Vec<E::Fr>>::deserialize(&mut reader)?;
            Ok(Self {
                A_prime,
                A_bar,
                d,
                sc_comm_1,
                sc_wits_1,
                sc_comm_2,
                sc_wits_2,
            })
        }

        fn deserialize_uncompressed<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let A_prime = E::G1Affine::deserialize_uncompressed(&mut reader)?;
            let A_bar = E::G1Affine::deserialize_uncompressed(&mut reader)?;
            let d = E::G1Affine::deserialize_uncompressed(&mut reader)?;
            let sc_comm_1 =
                <SchnorrCommitment<E::G1Affine>>::deserialize_uncompressed(&mut reader)?;
            let sc_wits_1 = [
                E::Fr::deserialize(&mut reader)?,
                E::Fr::deserialize(&mut reader)?,
            ];
            let sc_comm_2 =
                <SchnorrCommitment<E::G1Affine>>::deserialize_uncompressed(&mut reader)?;
            let sc_wits_2 = <Vec<E::Fr>>::deserialize(&mut reader)?;
            Ok(Self {
                A_prime,
                A_bar,
                d,
                sc_comm_1,
                sc_wits_1,
                sc_comm_2,
                sc_wits_2,
            })
        }

        fn deserialize_unchecked<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
            let A_prime = E::G1Affine::deserialize_unchecked(&mut reader)?;
            let A_bar = E::G1Affine::deserialize_unchecked(&mut reader)?;
            let d = E::G1Affine::deserialize_unchecked(&mut reader)?;
            let sc_comm_1 = <SchnorrCommitment<E::G1Affine>>::deserialize_unchecked(&mut reader)?;
            let sc_wits_1 = [
                E::Fr::deserialize(&mut reader)?,
                E::Fr::deserialize(&mut reader)?,
            ];
            let sc_comm_2 = <SchnorrCommitment<E::G1Affine>>::deserialize_unchecked(&mut reader)?;
            let sc_wits_2 = <Vec<E::Fr>>::deserialize(&mut reader)?;
            Ok(Self {
                A_prime,
                A_bar,
                d,
                sc_comm_1,
                sc_wits_1,
                sc_comm_2,
                sc_wits_2,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::KeypairG2;
    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    fn sig_setup<R: RngCore>(
        rng: &mut R,
        message_count: usize,
    ) -> (
        Vec<Fr>,
        SignatureParamsG1<Bls12_381>,
        KeypairG2<Bls12_381>,
        SignatureG1<Bls12_381>,
    ) {
        let messages: Vec<Fr> = (0..message_count)
            .into_iter()
            .map(|_| Fr::rand(rng))
            .collect();
        let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
        let keypair = KeypairG2::<Bls12_381>::generate(rng, &params);
        let sig =
            SignatureG1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
        (messages, params, keypair, sig)
    }

    #[test]
    fn pok_signature_revealed_message() {
        // Create and verify proof of knowledge of a signature when some messages are revealed
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 20;
        let (messages, params, keypair, sig) = sig_setup(&mut rng, message_count);
        sig.verify(&messages, &keypair.public_key, &params).unwrap();

        let mut revealed_indices = BTreeSet::new();
        revealed_indices.insert(0);
        revealed_indices.insert(2);

        let mut revealed_msgs = BTreeMap::new();
        for i in revealed_indices.iter() {
            revealed_msgs.insert(*i, messages[*i]);
        }

        let mut proof_create_duration = Duration::default();
        let start = Instant::now();
        let pok = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            &params,
            messages.as_slice(),
            BTreeMap::new(),
            revealed_indices.clone(),
        )
        .unwrap();
        proof_create_duration += start.elapsed();

        // Protocol can be serialized
        test_serialization!(PoKOfSignatureG1Protocol, pok);

        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b>(&chal_bytes_prover);

        let start = Instant::now();
        let proof = pok.gen_proof(&challenge_prover).unwrap();
        proof_create_duration += start.elapsed();

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b>(&chal_bytes_verifier);

        let mut proof_verif_duration = Duration::default();
        let start = Instant::now();
        proof
            .verify(
                &revealed_msgs,
                &challenge_verifier,
                &keypair.public_key,
                &params,
            )
            .unwrap();
        proof_verif_duration += start.elapsed();

        // Proof can be serialized
        test_serialization!(PoKOfSignatureG1Proof, proof);

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
            SignatureParamsG1::<Bls12_381>::new::<Blake2b>("test".as_bytes(), message_1_count);
        let params_2 =
            SignatureParamsG1::<Bls12_381>::new::<Blake2b>("test-1".as_bytes(), message_2_count);
        let keypair_1 = KeypairG2::<Bls12_381>::generate(&mut rng, &params_1);
        let keypair_2 = KeypairG2::<Bls12_381>::generate(&mut rng, &params_2);

        let mut messages_1: Vec<Fr> = (0..message_1_count - 1)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect();
        let mut messages_2: Vec<Fr> = (0..message_2_count - 1)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect();

        let same_msg_idx = 4;
        let same_msg = Fr::rand(&mut rng);
        messages_1.insert(same_msg_idx, same_msg.clone());
        messages_2.insert(same_msg_idx, same_msg.clone());

        // A particular message is same
        assert_eq!(messages_1[same_msg_idx], messages_2[same_msg_idx]);
        assert_ne!(messages_1, messages_2);

        let sig_1 =
            SignatureG1::<Bls12_381>::new(&mut rng, &messages_1, &keypair_1.secret_key, &params_1)
                .unwrap();
        sig_1
            .verify(&messages_1, &keypair_1.public_key, &params_1)
            .unwrap();

        let sig_2 =
            SignatureG1::<Bls12_381>::new(&mut rng, &messages_2, &keypair_2.secret_key, &params_2)
                .unwrap();
        sig_2
            .verify(&messages_2, &keypair_2.public_key, &params_2)
            .unwrap();

        // Add the same blinding for the message which has to be proven equal across messages
        let same_blinding = Fr::rand(&mut rng);

        let mut blindings_1 = BTreeMap::new();
        blindings_1.insert(same_msg_idx, same_blinding.clone());

        let mut blindings_2 = BTreeMap::new();
        blindings_2.insert(same_msg_idx, same_blinding.clone());

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

        let pok_1 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig_1,
            &params_1,
            &messages_1,
            blindings_1,
            BTreeSet::new(),
        )
        .unwrap();
        let pok_2 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig_2,
            &params_2,
            &messages_2,
            blindings_2,
            BTreeSet::new(),
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        pok_1
            .challenge_contribution(&BTreeMap::new(), &params_1, &mut chal_bytes_prover)
            .unwrap();
        pok_2
            .challenge_contribution(&BTreeMap::new(), &params_2, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b>(&chal_bytes_prover);

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
            compute_random_oracle_challenge::<Fr, Blake2b>(&chal_bytes_verifier);

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
                &keypair_1.public_key,
                &params_1,
            )
            .unwrap();
        proof_2
            .verify(
                &BTreeMap::new(),
                &challenge_verifier,
                &keypair_2.public_key,
                &params_2,
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
        let pok_1 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            &params,
            messages.as_slice(),
            BTreeMap::new(),
            revealed_indices_1.clone(),
        )
        .unwrap();
        let proof_1 = pok_1.gen_proof(&challenge).unwrap();
        for i in 0..message_count {
            assert_eq!(
                *proof_1
                    .get_resp_for_message(i, &revealed_indices_1)
                    .unwrap(),
                proof_1.sc_resp_2.0[i + 2]
            );
        }

        // Test response when some messages are revealed
        let mut revealed_indices_2 = BTreeSet::new();
        revealed_indices_2.insert(0);
        revealed_indices_2.insert(2);
        revealed_indices_2.insert(5);
        let pok_2 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            &params,
            messages.as_slice(),
            BTreeMap::new(),
            revealed_indices_2.clone(),
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
            proof_2.sc_resp_2.0[2 + 0]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(3, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_2.0[2 + 1]
        );
        assert_eq!(
            *proof_2
                .get_resp_for_message(4, &revealed_indices_2)
                .unwrap(),
            proof_2.sc_resp_2.0[2 + 2]
        );

        let mut revealed_indices_3 = BTreeSet::new();
        revealed_indices_3.insert(0);
        revealed_indices_3.insert(3);
        let pok_3 = PoKOfSignatureG1Protocol::init(
            &mut rng,
            &sig,
            &params,
            messages.as_slice(),
            BTreeMap::new(),
            revealed_indices_3.clone(),
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
            proof_3.sc_resp_2.0[2 + 0]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(2, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[2 + 1]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(4, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[2 + 2]
        );
        assert_eq!(
            *proof_3
                .get_resp_for_message(5, &revealed_indices_3)
                .unwrap(),
            proof_3.sc_resp_2.0[2 + 3]
        );

        // Reveal one message only
        for i in 0..message_count {
            let mut revealed_indices = BTreeSet::new();
            revealed_indices.insert(i);
            let pok = PoKOfSignatureG1Protocol::init(
                &mut rng,
                &sig,
                &params,
                messages.as_slice(),
                BTreeMap::new(),
                revealed_indices.clone(),
            )
            .unwrap();
            let proof = pok.gen_proof(&challenge).unwrap();
            for j in 0..message_count {
                if i == j {
                    assert!(proof.get_resp_for_message(j, &revealed_indices).is_err());
                } else if i < j {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_2.0[j + 2 - 1]
                    );
                } else {
                    assert_eq!(
                        *proof.get_resp_for_message(j, &revealed_indices).unwrap(),
                        proof.sc_resp_2.0[j + 2]
                    );
                }
            }
        }
    }
}
