use crate::{
    bbdt_2016::keyed_proof::{KeyedProof, ProofOfValidityOfKeyedProof},
    bbs_sharp::{
        mac::MAC,
        setup::{MACParams, PublicKey, SecretKey},
    },
    error::KVACError,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec::Vec, UniformRand};
use core::mem;
use digest::Digest;
use dock_crypto_utils::{
    msm::WindowTable,
    schnorr_signature::Signature,
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
    /// Randomized MAC `A_hat = A * r1 * r2`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub A_hat: G,
    /// `D = B * r2`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub D: G,
    /// `B_bar = D * r1 - A_hat * e`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub B_bar: G,
    /// The randomized public key
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub blinded_pk: G,
    /// The blinding used to randomize the public key
    #[serde_as(as = "ArkObjectBytes")]
    pub blinding_pk: G::ScalarField,
    /// For proving relation `B_bar = A_hat * -e + D * r1`
    pub sc_B_bar: PokTwoDiscreteLogsProtocol<G>,
    /// For proving relation `g_0 + user_pk + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + sum_{j notin D}(g_vec_j * -m_j) + g * blinding_pk`
    pub sc_comm_msgs: SchnorrCommitment<G>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    sc_wits_msgs: Vec<G::ScalarField>,
}

/// Proof of knowledge of a MAC.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKOfMAC<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub A_hat: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub B_bar: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub D: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub blinded_pk: G,
    /// For proving relation `B_bar = A_hat * -e + D * r1`
    pub sc_B_bar: PokTwoDiscreteLogs<G>,
    /// For proving relation `g_0 + user_pk + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + sum_{j notin D}(g_vec_j * -m_j) + g * blinding_pk`
    #[serde_as(as = "ArkObjectBytes")]
    pub t_msgs: G,
    pub sc_resp_msgs: SchnorrResponse<G>,
}

/// Private data of the user when it requests a proof of validity of the keyed-proof, i.e. `(A_hat * sk = B_bar)`
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
pub struct KeyedProofRequestPrivateData<G: AffineRepr> {
    /// `D = B * r2`
    #[zeroize(skip)]
    #[serde_as(as = "ArkObjectBytes")]
    pub D: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub r1: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub r3: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub minus_e: G::ScalarField,
}

impl<G: AffineRepr> PoKOfMACProtocol<G> {
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        mac: &MAC<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
        user_public_key: &PublicKey<G>,
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

        let r1 = G::ScalarField::rand(rng);
        let mut r2 = G::ScalarField::rand(rng);
        while r2.is_zero() {
            r2 = G::ScalarField::rand(rng);
        }
        let r3 = r2.inverse().unwrap();

        let A_hat = mac.A * (r1 * r2);
        // B = (e+x) * A = g_0 + user_pk + \sum(g_vec_i*m_i) for all i in I
        let B = params.b(messages.iter().enumerate(), &user_public_key)?;
        let D = B * r2;

        let minus_e = -mac.e;
        let B_bar = D * r1 + A_hat * minus_e;
        Self::_init(
            rng,
            A_hat.into(),
            B_bar.into(),
            D.into(),
            r1,
            r3,
            minus_e,
            messages,
            indexed_blindings,
            params,
            user_public_key,
        )
    }

    pub fn init_using_keyed_proof_private_data<'a, MBI, R: RngCore>(
        rng: &mut R,
        private_data: KeyedProofRequestPrivateData<G>,
        keyed_proof: KeyedProof<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
        user_public_key: &PublicKey<G>,
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

        let KeyedProofRequestPrivateData { D, r1, r3, minus_e } = private_data;
        let KeyedProof {
            B_0: A_hat,
            C: B_bar,
        } = keyed_proof;
        Self::_init(
            rng,
            A_hat,
            B_bar,
            D,
            r1,
            r3,
            minus_e,
            messages,
            indexed_blindings,
            params,
            user_public_key,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        writer: W,
    ) -> Result<(), KVACError> {
        Self::compute_challenge_contribution(
            &self.A_hat,
            &self.B_bar,
            &self.D,
            &self.blinded_pk,
            &self.sc_B_bar.t,
            &self.sc_comm_msgs.t,
            revealed_msgs,
            params,
            writer,
        )
    }

    pub fn gen_proof(mut self, challenge: &G::ScalarField) -> Result<PoKOfMAC<G>, KVACError> {
        let sc_B_bar = mem::take(&mut self.sc_B_bar).gen_proof(challenge);
        let sc_resp_msgs = self.sc_comm_msgs.response(&self.sc_wits_msgs, challenge)?;
        Ok(PoKOfMAC {
            A_hat: self.A_hat,
            B_bar: self.B_bar,
            D: self.D,
            blinded_pk: self.blinded_pk,
            sc_B_bar,
            t_msgs: self.sc_comm_msgs.t,
            sc_resp_msgs,
        })
    }

    /// Transform the Schnorr signature received from user (likely from the secure hardware) to be verifiable
    /// by the blinded public key.
    pub fn transform_schnorr_sig(&self, sig: Signature<G>) -> Signature<G> {
        Signature {
            response: sig.response + self.blinding_pk * sig.challenge,
            challenge: sig.challenge,
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        A_bat: &G,
        B_bar: &G,
        D: &G,
        blinded_pk: &G,
        t_B_bar: &G,
        t_msgs: &G,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        mut writer: W,
    ) -> Result<(), KVACError> {
        A_bat.serialize_compressed(&mut writer)?;
        B_bar.serialize_compressed(&mut writer)?;
        D.serialize_compressed(&mut writer)?;
        blinded_pk.serialize_compressed(&mut writer)?;
        params.g.serialize_compressed(&mut writer)?;
        t_B_bar.serialize_compressed(&mut writer)?;
        t_msgs.serialize_compressed(&mut writer)?;
        for i in 0..params.g_vec.len() {
            params.g_vec[i].serialize_compressed(&mut writer)?;
            if let Some(m) = revealed_msgs.get(&i) {
                m.serialize_compressed(&mut writer)?;
            }
        }
        Ok(())
    }

    fn _init<R: RngCore>(
        rng: &mut R,
        A_hat: G,
        B_bar: G,
        D: G,
        r1: G::ScalarField,
        r3: G::ScalarField,
        minus_e: G::ScalarField,
        messages: Vec<G::ScalarField>,
        indexed_blindings: impl IntoIterator<Item = (usize, G::ScalarField)>,
        params: &MACParams<G>,
        user_public_key: &PublicKey<G>,
    ) -> Result<Self, KVACError> {
        let blinding_pk = G::ScalarField::rand(rng);
        let blinded_pk = user_public_key.get_blinded(&blinding_pk, &params.g);

        let sc_C_bar = PokTwoDiscreteLogsProtocol::init(
            minus_e,
            G::ScalarField::rand(rng),
            &A_hat,
            r1,
            G::ScalarField::rand(rng),
            &D,
        );

        // Iterator of tuples of form `(g_vec_i, blinding_i, message_i)`
        let msg_comm_iter = indexed_blindings
            .into_iter()
            .map(|(idx, blinding)| (params.g_vec[idx], blinding, messages[idx]));
        let (bases, randomness, sc_wits_msgs): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            msg_comm_iter.chain(
                [
                    (D, G::ScalarField::rand(rng), -r3),
                    (params.g, G::ScalarField::rand(rng), -blinding_pk),
                ]
                .into_iter(),
            ),
        );
        let sc_comm_msgs = SchnorrCommitment::new(&bases, randomness);
        Ok(Self {
            A_hat,
            B_bar,
            D,
            blinded_pk: blinded_pk.0,
            blinding_pk,
            sc_B_bar: sc_C_bar,
            sc_comm_msgs,
            sc_wits_msgs,
        })
    }
}

impl<G: AffineRepr> PoKOfMAC<G> {
    /// Verify the proof of knowledge of MAC. Requires the knowledge of the signer's secret key. It can be seen as composed of 2 parts,
    /// one requiring knowledge of secret key and the other not requiring it. The latter can thus be verified by anyone.
    /// The former doesn't contain any revealed messages and contains no user specific data.
    pub fn verify(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        secret_key: &SecretKey<G::ScalarField>,
        params: &MACParams<G>,
    ) -> Result<(), KVACError> {
        if self.B_bar != (self.A_hat * secret_key.0).into() {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        self.verify_schnorr_proofs(revealed_msgs, challenge, params)?;
        Ok(())
    }

    /// Verify the proof of knowledge of MAC. Doesn't require the knowledge of the signer's secret key
    /// but consists of proof of correctness of randomized MAC given by the signer
    /// NOTE: The pair (PoKOfMAC, ProofOfValidityOfKeyedProof) could be combined in a single struct.
    pub fn verify_given_proof_of_validity_of_keyed_proof<D: Digest>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        proof_of_validity: &ProofOfValidityOfKeyedProof<G>,
        signer_pk: &PublicKey<G>,
        params: &MACParams<G>,
    ) -> Result<(), KVACError> {
        proof_of_validity.verify_given_destructured::<D>(
            &self.A_hat,
            &self.B_bar,
            &signer_pk.0,
            &params.g,
        )?;
        self.verify_schnorr_proofs(revealed_msgs, challenge, params)?;
        Ok(())
    }

    /// Create a new sub-proof that can be verified by someone with the secret key
    pub fn to_keyed_proof(&self) -> KeyedProof<G> {
        KeyedProof {
            B_0: self.A_hat,
            C: self.B_bar,
        }
    }

    pub fn verify_schnorr_proofs(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
    ) -> Result<(), KVACError> {
        if !self
            .sc_B_bar
            .verify(&self.B_bar, &self.A_hat, &self.D, challenge)
        {
            return Err(KVACError::InvalidSchnorrProof);
        }
        let mut bases = Vec::with_capacity(2 + params.g_vec.len() - revealed_msgs.len());
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
        bases.push(self.D);
        bases.push(params.g);
        let y =
            -(G::Group::msm_unchecked(&bases_revealed, &exponents) + params.g_0 + self.blinded_pk);
        self.sc_resp_msgs
            .is_valid(&bases, &y.into(), &self.t_msgs, challenge)?;
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        params: &MACParams<G>,
        writer: W,
    ) -> Result<(), KVACError> {
        PoKOfMACProtocol::compute_challenge_contribution(
            &self.A_hat,
            &self.B_bar,
            &self.D,
            &self.blinded_pk,
            &self.sc_B_bar.t,
            &self.t_msgs,
            revealed_msgs,
            params,
            writer,
        )
    }
}

/// Called by the user to create requests to send to the signer in half-offline mode. `count` denotes the
/// number of requests to create and each request can be used to create one proof of knowledge.
/// Outputs a pair where the first items is kept private by the user and later used to create the proof
/// of knowledge and the second item is sent to the signer.
/// NOTE: These requests likely should be accompanied by a proof that the user possesses a valid
/// MAC and the randomized MAC in the keyed proof is the randomization of the possessed MAC.
pub fn generate_keyed_proof_requests<R: RngCore, G: AffineRepr>(
    rng: &mut R,
    count: usize,
    mac: &MAC<G>,
    messages: &[G::ScalarField],
    user_public_key: &PublicKey<G>,
    params: &MACParams<G>,
) -> Result<(Vec<KeyedProofRequestPrivateData<G>>, Vec<KeyedProof<G>>), KVACError> {
    let minus_e = -mac.e;
    // B = (e+x) * A = g_0 + user_pk + \sum(g_vec_i*m_i) for all i in I
    let B = params.b(messages.iter().enumerate(), &user_public_key)?;
    let A_table = WindowTable::new(count, mac.A.into_group());
    let B_table = WindowTable::new(count, B);

    let mut kp_req = Vec::with_capacity(count);
    let mut kp = Vec::with_capacity(count);
    for _ in 0..count {
        let r1 = G::ScalarField::rand(rng);
        let mut r2 = G::ScalarField::rand(rng);
        while r2.is_zero() {
            r2 = G::ScalarField::rand(rng);
        }
        let r3 = r2.inverse().unwrap();

        let r1_times_r2 = r1 * r2;
        let A_hat = A_table.multiply(&r1_times_r2);
        let D = B_table.multiply(&r2).into_affine();
        // D * r1 = B * r2 * r1
        let B_bar = B_table.multiply(&r1_times_r2) + A_hat * minus_e;
        kp_req.push(KeyedProofRequestPrivateData { D, r1, r3, minus_e });
        kp.push(KeyedProof {
            B_0: A_hat.into_affine(),
            C: B_bar.into_affine(),
        });
    }
    Ok((kp_req, kp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs_sharp::{mac::ProofOfValidityOfMAC, setup::SecretKey};
    use ark_secp256r1::{Affine, Fr};
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use schnorr_pok::compute_random_oracle_challenge;
    use sha2::Sha256;
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
        let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
        let signer_sk = SecretKey::new(&mut rng);
        let signer_pk = PublicKey::new(&signer_sk, &params.g);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = PublicKey::new(&user_sk, &params.g);

        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof =
            ProofOfValidityOfMAC::new::<_, Sha256>(&mut rng, &mac, &signer_sk, &signer_pk, &params);

        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
            .unwrap();

        let user_auth_message = [1, 2, 3, 4, 5];
        let schnorr_signature =
            Signature::new::<_, Sha256>(&mut rng, &user_auth_message, &user_sk.0, &params.g);
        assert!(schnorr_signature.verify::<Sha256>(&user_auth_message, &user_pk.0, &params.g));

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
            &user_pk,
        )
        .unwrap();
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
        let transformed_schnorr_sig = pok.transform_schnorr_sig(schnorr_signature);
        let proof = pok.gen_proof(&challenge_prover).unwrap();
        proof_create_duration += start.elapsed();

        let mut proof_verif_duration = Duration::default();
        let start = Instant::now();
        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_verifier);

        assert_eq!(challenge_prover, challenge_verifier);

        // The verifier needs to check that the Schnorr signature is valid
        assert!(transformed_schnorr_sig.verify::<Sha256>(
            &user_auth_message,
            &proof.blinded_pk,
            &params.g
        ));
        // This is an example where the verifier has the secret key
        proof
            .verify(&revealed_msgs, &challenge_verifier, &signer_sk, &params)
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

        // This is an example where the verifier does not have the secret key but creates the keyed proof
        // which will be verified by the signer and the verifier checks the part of proof that contains the
        // revealed messages
        let keyed_proof = proof.to_keyed_proof();
        keyed_proof.verify(signer_sk.as_ref()).unwrap();
        proof
            .verify_schnorr_proofs(&revealed_msgs, &challenge_verifier, &params)
            .unwrap();
    }

    #[test]
    fn proof_of_knowledge_of_MAC_in_half_offline_mode() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
        let signer_sk = SecretKey::new(&mut rng);
        let signer_pk = PublicKey::new(&signer_sk, &params.g);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = PublicKey::new(&user_sk, &params.g);

        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof =
            ProofOfValidityOfMAC::new::<_, Sha256>(&mut rng, &mac, &signer_sk, &signer_pk, &params);

        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
            .unwrap();

        // User generates several requests of keyed-proofs and sends them to the signer and gets their proof of validity.
        // These will be used later to create proof of knowledge of MAC
        let count = 10;
        let start = Instant::now();
        let (private_data, keyed_proofs) =
            generate_keyed_proof_requests(&mut rng, count, &mac, &messages, &user_pk, &params)
                .unwrap();
        println!(
            "Time to create {} requests with each request of {} messages is {:?}",
            count,
            message_count,
            start.elapsed()
        );

        // Signer on getting the requests, creates a proof of validity of each request
        let mut proofs_of_validity_of_keyed_proofs = vec![];
        let start = Instant::now();
        for i in 0..count {
            proofs_of_validity_of_keyed_proofs.push(
                keyed_proofs[i].create_proof_of_validity::<_, Sha256>(
                    &mut rng,
                    signer_sk.0,
                    &signer_pk.0,
                    &params.g,
                ),
            );
        }
        println!("Time to serve {} requests is {:?}", count, start.elapsed());

        for i in 0..count {
            let user_auth_message = [1, 2, 3, 4, 5];
            let schnorr_signature =
                Signature::new::<_, Sha256>(&mut rng, &user_auth_message, &user_sk.0, &params.g);
            assert!(schnorr_signature.verify::<Sha256>(&user_auth_message, &user_pk.0, &params.g));
            let mut revealed_indices = BTreeSet::new();
            revealed_indices.insert(0);
            revealed_indices.insert(2);

            let mut revealed_msgs = BTreeMap::new();
            for i in revealed_indices.iter() {
                revealed_msgs.insert(*i, messages[*i]);
            }

            let mut proof_create_duration = Duration::default();
            let start = Instant::now();
            let pok = PoKOfMACProtocol::init_using_keyed_proof_private_data(
                &mut rng,
                private_data[i].clone(),
                keyed_proofs[i].clone(),
                &params,
                messages.iter().enumerate().map(|(idx, msg)| {
                    if revealed_indices.contains(&idx) {
                        MessageOrBlinding::RevealMessage(msg)
                    } else {
                        MessageOrBlinding::BlindMessageRandomly(msg)
                    }
                }),
                &user_pk,
            )
            .unwrap();
            let mut chal_bytes_prover = vec![];
            pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
            let transformed_schnorr_sig = pok.transform_schnorr_sig(schnorr_signature);
            let proof = pok.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let mut proof_verif_duration = Duration::default();
            let start = Instant::now();
            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_verifier);

            assert_eq!(challenge_prover, challenge_verifier);

            // This is an example where the verifier has the secret key
            assert!(transformed_schnorr_sig.verify::<Sha256>(
                &user_auth_message,
                &proof.blinded_pk,
                &params.g
            ));
            proof
                .verify_given_proof_of_validity_of_keyed_proof::<Sha256>(
                    &revealed_msgs,
                    &challenge_verifier,
                    &proofs_of_validity_of_keyed_proofs[i],
                    &signer_pk,
                    &params,
                )
                .unwrap();
            proof_verif_duration += start.elapsed();

            if i == 0 {
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
        }
    }
}
