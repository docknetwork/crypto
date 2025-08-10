use crate::{
    bbdt_2016::keyed_proof::KeyedProof,
    bbs_sharp::{
        ecdsa::Signature as EcdsaSignature,
        hol::{ProofOfValidity, TokenPrivateData},
        mac::MAC,
        setup::{
            DesignatedVerifierPoKOfPublicKey, MACParams, SecretKey, SignerPublicKey, UserPublicKey,
        },
    },
    error::KVACError,
};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use core::mem;
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{
    schnorr_signature::Signature as SchnorrSignature,
    signature::{
        msg_index_to_schnorr_response_index, split_messages_and_blindings, MessageOrBlinding,
        MultiMessageSignatureParams,
    },
};
use itertools::multiunzip;
use schnorr_pok::{
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
    SchnorrCommitment, SchnorrResponse,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type of the signature produced by the user's secure hardware. The implementation of the proof of
/// knowledge protocol changes slightly based on the signature type.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HardwareSignatureType {
    #[default]
    Schnorr,
    Ecdsa,
}

#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoKOfMACProtocol<G: AffineRepr> {
    /// Randomized MAC `A_hat = A * r1 * r2`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_hat: G,
    /// `D = B * r2`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub D: G,
    /// `B_bar = D * r1 - A_hat * e`
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_bar: G,
    /// The randomized public key
    #[zeroize(skip)]
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub blinded_pk: G,
    /// The blinding used to randomize the public key
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub blinding_pk: G::ScalarField,
    /// For proving relation `B_bar = A_hat * -e + D * r1`
    pub sc_B_bar: PokPedersenCommitmentProtocol<G>,
    /// For proving relation `g_0 + user_pk + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + sum_{j notin D}(g_vec_j * -m_j) + g * blinding_pk`
    pub sc_comm_msgs: SchnorrCommitment<G>,
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))]
    sc_wits_msgs: Vec<G::ScalarField>,
    #[zeroize(skip)]
    pub hw_sig_type: HardwareSignatureType,
    /// Part of the token received from issuer during HOL mode. This won't be set when the user didn't
    /// use the token to create the proof.
    #[zeroize(skip)]
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "Option<(ArkObjectBytes, ArkObjectBytes)>")
    )]
    proof_of_validity: Option<(G::ScalarField, G::ScalarField)>,
    /// This is only set if the prover is creating a designated verifier proof
    #[zeroize(skip)]
    pub designated_verifier_pk_proof: Option<DesignatedVerifierPoKOfPublicKey<G>>,
}

/// Proof of knowledge of a MAC.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PoKOfMAC<G: AffineRepr> {
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub A_hat: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub B_bar: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub D: G,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub blinded_pk: G,
    /// For proving relation `B_bar = A_hat * -e + D * r1`
    pub sc_B_bar: PokPedersenCommitment<G>,
    /// For proving relation `g_0 + user_pk + \sum_{i in D}(g_vec_i*m_i)` = `d*r3 + sum_{j notin D}(g_vec_j * -m_j) + g * blinding_pk`
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub t_msgs: G,
    pub sc_resp_msgs: SchnorrResponse<G>,
    pub hw_sig_type: HardwareSignatureType,
    /// Part of the token received from issuer during HOL mode. This won't be set when the user didn't
    /// use the token to create the proof. If this is set, then verifier does not need to interact
    /// with the issuer to verify the proof.
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "Option<(ArkObjectBytes, ArkObjectBytes)>")
    )]
    pub proof_of_validity: Option<(G::ScalarField, G::ScalarField)>,
    /// This is only set if the prover is creating a designated verifier proof
    pub designated_verifier_pk_proof: Option<DesignatedVerifierPoKOfPublicKey<G>>,
}

impl<G: AffineRepr> PoKOfMACProtocol<G> {
    /// Pass the appropriate type in `hw_sig_type` which corresponds to the signature type generated by user's secure hardware
    /// If `verifier_pub_key` is provided, then create a designated verifier proof which only the verifier can verify
    pub fn init<'a, MBI, R: RngCore>(
        rng: &mut R,
        mac: &MAC<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
        user_public_key: &UserPublicKey<G>,
        hw_sig_type: HardwareSignatureType,
        verifier_pub_key: Option<&G>,
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
            hw_sig_type,
            None,
            verifier_pub_key,
        )
    }

    /// Initialize the protocol using token received in HOL mode.
    /// Pass the appropriate type in `hw_sig_type` which corresponds to the signature type generated by user's secure hardware
    /// If `verifier_pub_key` is provided, then create a designated verifier proof which only the verifier can verify
    pub fn init_using_token<'a, MBI, R: RngCore>(
        rng: &mut R,
        private_data: TokenPrivateData<G>,
        proof_of_validity: ProofOfValidity<G>,
        params: &MACParams<G>,
        messages_and_blindings: MBI,
        user_public_key: &UserPublicKey<G>,
        hw_sig_type: HardwareSignatureType,
        verifier_pub_key: Option<&G>,
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

        let TokenPrivateData { D, r1, r3, minus_e } = private_data;
        let ProofOfValidity { A_hat, B_bar, c, r } = proof_of_validity;
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
            hw_sig_type,
            Some((c, r)),
            verifier_pub_key,
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
        // Adjust challenge if creating designated verifier proof
        let designated_verifier_pk_proof = mem::take(&mut self.designated_verifier_pk_proof);
        let chal = if designated_verifier_pk_proof.is_none() {
            *challenge
        } else {
            *challenge - designated_verifier_pk_proof.as_ref().unwrap().challenge
        };

        let sc_B_bar = mem::take(&mut self.sc_B_bar).gen_proof(&chal);
        let sc_resp_msgs = self.sc_comm_msgs.response(&self.sc_wits_msgs, &chal)?;
        Ok(PoKOfMAC {
            A_hat: self.A_hat,
            B_bar: self.B_bar,
            D: self.D,
            blinded_pk: self.blinded_pk,
            sc_B_bar,
            t_msgs: self.sc_comm_msgs.t,
            sc_resp_msgs,
            hw_sig_type: mem::take(&mut self.hw_sig_type),
            proof_of_validity: self.proof_of_validity,
            designated_verifier_pk_proof,
        })
    }

    /// Transform the Schnorr signature received from user (likely from the secure hardware) to be verifiable
    /// by the blinded public key.
    pub fn transform_schnorr_sig(
        &self,
        sig: SchnorrSignature<G>,
    ) -> Result<SchnorrSignature<G>, KVACError> {
        match &self.hw_sig_type {
            HardwareSignatureType::Schnorr => Ok(SchnorrSignature {
                response: sig.response + self.blinding_pk * sig.challenge,
                challenge: sig.challenge,
            }),
            _ => Err(KVACError::IncompatibleWithHardwareSignatureTypeProvidedDuringInitialization),
        }
    }

    /// Transform the ECDSA signature received from user (likely from the secure hardware) to be verifiable
    /// by the blinded public key.
    pub fn transform_ecdsa_sig(&self, sig: EcdsaSignature) -> Result<EcdsaSignature, KVACError> {
        match &self.hw_sig_type {
            HardwareSignatureType::Ecdsa => {
                let blinding = ark_secp256r1::Fr::from_le_bytes_mod_order(
                    &self.blinding_pk.into_bigint().to_bytes_le(),
                );
                Ok(EcdsaSignature {
                    response: sig.response * blinding,
                    rand_x_coord: sig.rand_x_coord,
                })
            }
            _ => Err(KVACError::IncompatibleWithHardwareSignatureTypeProvidedDuringInitialization),
        }
    }

    /// Transform the message to be given to ECDSA signing. Called before generating signature and thus before calling `Self::transform_ecdsa_sig`
    pub fn transform_message_for_ecdsa_sig(
        &self,
        message: ark_secp256r1::Fr,
    ) -> Result<ark_secp256r1::Fr, KVACError> {
        match &self.hw_sig_type {
            HardwareSignatureType::Ecdsa => {
                let blinding = ark_secp256r1::Fr::from_le_bytes_mod_order(
                    &self.blinding_pk.into_bigint().to_bytes_le(),
                );
                Ok(message * (blinding.inverse().unwrap()))
            }
            _ => Err(KVACError::IncompatibleWithHardwareSignatureTypeProvidedDuringInitialization),
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
        user_public_key: &UserPublicKey<G>,
        hw_sig_type: HardwareSignatureType,
        proof_of_validity: Option<(G::ScalarField, G::ScalarField)>,
        verifier_pub_key: Option<&G>,
    ) -> Result<Self, KVACError> {
        // Needs to be invertible to work with ECDSA
        let mut blinding_pk = G::ScalarField::rand(rng);
        while blinding_pk.is_zero() {
            blinding_pk = G::ScalarField::rand(rng);
        }
        let blinded_pk = match hw_sig_type {
            HardwareSignatureType::Schnorr => {
                user_public_key.get_blinded_for_schnorr_sig(&blinding_pk, &params.g)
            }
            HardwareSignatureType::Ecdsa => user_public_key.get_blinded_for_ecdsa(&blinding_pk),
        };

        let sc_C_bar = PokPedersenCommitmentProtocol::init(
            minus_e,
            G::ScalarField::rand(rng),
            &A_hat,
            r1,
            G::ScalarField::rand(rng),
            &D,
        );

        let (bases, randomness, sc_wits_msgs): (Vec<_>, Vec<_>, Vec<_>) = match hw_sig_type {
            HardwareSignatureType::Schnorr => {
                // Iterator of tuples of form `(g_vec_i, blinding_i, message_i)`
                let msg_comm_iter = indexed_blindings
                    .into_iter()
                    .map(|(idx, blinding)| (params.g_vec[idx], blinding, messages[idx]));
                multiunzip(
                    msg_comm_iter.chain(
                        [
                            (D, G::ScalarField::rand(rng), -r3),
                            (params.g, G::ScalarField::rand(rng), -blinding_pk),
                        ]
                        .into_iter(),
                    ),
                )
            }
            HardwareSignatureType::Ecdsa => {
                // As per the paper
                // The paper (in footnote 31) suggests to prove relation F * r + PK_blind = D * r * r3 + \sum(g_j * -m_j * r) for all j in unrevealed indices
                // Here F = g_0 + \sum(g_i * m_i) for all i in revealed indices and prover proves the knowledge of r, r*r3, and -m_j * r.
                // r and PK_blind correspond to variables blinding_pk and blinded_pk in the code

                // let mut revealed_indices = BTreeSet::from_iter(0..messages.len());
                // // Iterator of tuples of form `(g_vec_i, blinding_i, message_i * blinding_pk)`
                // let msg_comm_iter = indexed_blindings
                //     .into_iter()
                //     .map(|(idx, blinding)| {
                //         revealed_indices.remove(&idx);
                //         (params.g_vec[idx], blinding, messages[idx] * blinding_pk)
                //     }).collect::<Vec<_>>();
                // let mut bases_revealed = Vec::with_capacity(revealed_indices.len());
                // let mut exponents = Vec::with_capacity(revealed_indices.len());
                // for i in 0..params.g_vec.len() {
                //     if revealed_indices.contains(&i) {
                //         bases_revealed.push(params.g_vec[i]);
                //         exponents.push(messages[i]);
                //     }
                // }
                // F = g_0 + \sum{g_i * m_i} for index i of revealed messages
                // let F = (G::Group::msm_unchecked(&bases_revealed, &exponents) + params.g_0).into_affine();
                // multiunzip(
                //     msg_comm_iter.into_iter().chain(
                //         [
                //             (D, G::ScalarField::rand(rng), -r3 * blinding_pk),
                //             (F, G::ScalarField::rand(rng), blinding_pk)
                //         ]
                //             .into_iter(),
                //     ),
                // )

                // An optimized approach where messages are not multiplied by the blinding used for blinding public
                // key which also makes the protocol suitable for combining with other Schnorr protocols.
                // The modification is as follows (using notation from above note):
                // Rather than proving the knowledge of r, r*r3, and -m_j * r in relation F * r + PK_blind = D * r * r3 + \sum(g_j * -m_j * r) for all j in unrevealed indices,
                // the prover proves the knowledge of 1/r, r3, and m_j in relation PK_blind * 1/r + D * -r3 + \sum(g_j * m_j) = F

                // Iterator of tuples of form `(g_vec_i, blinding_i, message_i)`
                let msg_comm_iter = indexed_blindings
                    .into_iter()
                    .map(|(idx, blinding)| (params.g_vec[idx], blinding, messages[idx]));
                multiunzip(
                    msg_comm_iter.chain(
                        [
                            (D, G::ScalarField::rand(rng), -r3),
                            (
                                blinded_pk.0,
                                G::ScalarField::rand(rng),
                                blinding_pk.inverse().unwrap(),
                            ),
                        ]
                        .into_iter(),
                    ),
                )
            }
        };
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
            hw_sig_type,
            proof_of_validity,
            designated_verifier_pk_proof: verifier_pub_key
                .map(|pk| DesignatedVerifierPoKOfPublicKey::new(rng, pk, &params.g_tilde)),
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
        verifier_pub_key: Option<&G>,
    ) -> Result<(), KVACError> {
        if self.B_bar != (self.A_hat * secret_key.0).into() {
            return Err(KVACError::InvalidRandomizedMAC);
        }
        self.verify_common(revealed_msgs, challenge, params, verifier_pub_key)?;
        Ok(())
    }

    /// Verify the proof of knowledge of MAC. Doesn't require the knowledge of the signer's secret key
    /// but consists of proof of correctness of randomized MAC given by the signer
    /// The nonce is what's called `m_DAB` in the paper. For credentials that can be revoked or if a
    /// verifier needs a "fresh" credential, it should use a nonce.
    pub fn verify_given_proof_of_validity_of_keyed_proof<D: Digest>(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        signer_pk: &SignerPublicKey<G>,
        params: &MACParams<G>,
        nonce: Option<&[u8]>,
        verifier_pub_key: Option<&G>,
    ) -> Result<(), KVACError> {
        let proof_of_validity = self
            .proof_of_validity
            .as_ref()
            .ok_or_else(|| KVACError::MissingProofOfValidity)?;
        ProofOfValidity::<G>::verify_given_destructured::<D>(
            &self.A_hat,
            &self.B_bar,
            &proof_of_validity.0,
            &proof_of_validity.1,
            &signer_pk.0,
            &params.g_tilde,
            nonce,
        )?;
        self.verify_common(revealed_msgs, challenge, params, verifier_pub_key)?;
        Ok(())
    }

    /// Create a new sub-proof that can be verified by someone with the secret key.
    /// This doesn't need to be created if `self.proof_of_validity` is set.
    pub fn to_keyed_proof(&self) -> KeyedProof<G> {
        KeyedProof {
            B_0: self.A_hat,
            C: self.B_bar,
        }
    }

    /// Verify Schnorr proofs and proof of knowledge of public key if designated verifier proof
    pub fn verify_common(
        &self,
        revealed_msgs: &BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
        params: &MACParams<G>,
        verifier_pub_key: Option<&G>,
    ) -> Result<(), KVACError> {
        // Adjust challenge if designated verifier proof provided
        let chal = if let Some(dvp) = &self.designated_verifier_pk_proof {
            if let Some(vpk) = verifier_pub_key {
                dvp.verify(vpk, &params.g_tilde)?;
                *challenge - dvp.challenge
            } else {
                return Err(KVACError::MissingVerifierPubKeyForDesignatedVerifierProof);
            }
        } else {
            *challenge
        };
        if !self
            .sc_B_bar
            .verify(&self.B_bar, &self.A_hat, &self.D, &chal)
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
        let y = match self.hw_sig_type {
            HardwareSignatureType::Schnorr => {
                bases.push(params.g);
                -(G::Group::msm_unchecked(&bases_revealed, &exponents)
                    + params.g_0
                    + self.blinded_pk)
            }
            HardwareSignatureType::Ecdsa => {
                // As described in the paper
                // let F = (G::Group::msm_unchecked(&bases_revealed, &exponents) + params.g_0).into_affine();
                // bases.push(F);
                // self.blinded_pk.into_group().neg()

                // An optimized approach with other benefits. See more details in comments in the proof generation code
                bases.push(self.blinded_pk);
                -(G::Group::msm_unchecked(&bases_revealed, &exponents) + params.g_0)
            }
        };

        self.sc_resp_msgs
            .is_valid(&bases, &y.into(), &self.t_msgs, &chal)?;
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

    /// Get the response from post-challenge phase of the Schnorr protocol for the given message index
    /// `msg_idx`. Used when comparing message equality
    pub fn get_resp_for_message(
        &self,
        msg_idx: usize,
        revealed_msg_ids: &BTreeSet<usize>,
    ) -> Result<&G::ScalarField, KVACError> {
        let adjusted_idx = msg_index_to_schnorr_response_index(msg_idx, revealed_msg_ids)
            .ok_or_else(|| KVACError::InvalidMsgIdxForResponse(msg_idx))?;
        Ok(self.sc_resp_msgs.get_response(adjusted_idx)?)
    }
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, SerializationError, Valid, Validate};
    use ark_std::io::Read;

    impl Valid for HardwareSignatureType {
        fn check(&self) -> Result<(), SerializationError> {
            Ok(())
        }
    }

    impl CanonicalSerialize for HardwareSignatureType {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Schnorr => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)
                }
                Self::Ecdsa => CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress),
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::Schnorr => 0u8.serialized_size(compress),
                Self::Ecdsa => 1u8.serialized_size(compress),
            }
        }

        fn serialize_uncompressed<W: Write>(
            &self,
            mut writer: W,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Schnorr => 0u8.serialize_uncompressed(&mut writer),
                Self::Ecdsa => 1u8.serialize_uncompressed(&mut writer),
            }
        }

        fn uncompressed_size(&self) -> usize {
            match self {
                Self::Schnorr => 0u8.uncompressed_size(),
                Self::Ecdsa => 1u8.uncompressed_size(),
            }
        }
    }

    impl CanonicalDeserialize for HardwareSignatureType {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            match u8::deserialize_with_mode(&mut reader, compress, validate)? {
                0u8 => Ok(Self::Schnorr),
                1u8 => Ok(Self::Ecdsa),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs_sharp::{
        hol::{HOLSignerProtocol, HOLUserProtocol},
        mac::ProofOfValidityOfMAC,
        setup::SecretKey,
    };
    use ark_ec::CurveGroup;
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
        let signer_pk = SignerPublicKey::new_from_params(&signer_sk, &params);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = UserPublicKey::new_from_params(&user_sk, &params);

        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof = ProofOfValidityOfMAC::new::<_, Sha256>(
            &mut rng, &mac, &signer_sk, &signer_pk, &params, None,
        );

        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
            .unwrap();

        let user_auth_message = [1, 2, 3, 4, 5];
        let schnorr_signature =
            SchnorrSignature::new::<_, Sha256>(&mut rng, &user_auth_message, &user_sk.0, &params.g);
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
            HardwareSignatureType::Schnorr,
            None,
        )
        .unwrap();
        assert!(pok.designated_verifier_pk_proof.is_none());
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        // The proves can include the verifier's given nonce if exists
        let challenge_prover = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
        let transformed_schnorr_sig = pok.transform_schnorr_sig(schnorr_signature).unwrap();
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
            .verify(
                &revealed_msgs,
                &challenge_verifier,
                &signer_sk,
                &params,
                None,
            )
            .unwrap();
        proof_verif_duration += start.elapsed();

        assert!(proof.designated_verifier_pk_proof.is_none());

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
            .verify_common(&revealed_msgs, &challenge_verifier, &params, None)
            .unwrap();
    }

    #[test]
    fn proof_of_knowledge_of_MAC_in_half_offline_mode() {
        let num_tokens = 10;

        fn check(message_count: u32, num_tokens: usize, nonces: Option<Vec<&[u8]>>) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let messages = (0..message_count)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
            let signer_sk = SecretKey::new(&mut rng);
            let signer_pk = SignerPublicKey::new_from_params(&signer_sk, &params);

            let user_sk = SecretKey::new(&mut rng);
            let user_pk = UserPublicKey::new_from_params(&user_sk, &params);

            let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
            let proof = ProofOfValidityOfMAC::new::<_, Sha256>(
                &mut rng, &mac, &signer_sk, &signer_pk, &params, None,
            );

            mac.verify(&messages, &user_pk, &signer_sk, &params)
                .unwrap();
            proof
                .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
                .unwrap();

            // User generates several requests of keyed-proofs and sends them to the signer and gets their proof of validity.
            // These will be used later to create proof of knowledge of MAC
            let mut signer_time = Duration::default();
            let mut user_time = Duration::default();

            // User proves knowledge of secret key to signer using a Schnorr signature (called pi_U in paper)
            let signer_challenge = b"signer's challenge";
            let start = Instant::now();
            let schnorr_signature = SchnorrSignature::new::<_, Sha256>(
                &mut rng,
                signer_challenge,
                &user_sk.0,
                &params.g,
            );
            user_time += start.elapsed();

            let start = Instant::now();
            assert!(schnorr_signature.verify::<Sha256>(signer_challenge, &user_pk.0, &params.g));
            signer_time += start.elapsed();

            let start = Instant::now();
            let mut user_protocol =
                HOLUserProtocol::init(&mut rng, num_tokens, &mac, &messages, &user_pk, &params)
                    .unwrap();
            user_time += start.elapsed();

            let start = Instant::now();
            let (signer_protocol, pre_challenge) =
                HOLSignerProtocol::init(&mut rng, num_tokens, &mac.A, &params);
            signer_time += start.elapsed();

            let start = Instant::now();
            let blinded_challenges =
                user_protocol.compute_challenge::<Sha256>(pre_challenge, &params, nonces.clone());
            user_time += start.elapsed();

            let start = Instant::now();
            let responses = signer_protocol.compute_response(blinded_challenges, &signer_sk);
            signer_time += start.elapsed();

            let start = Instant::now();
            let (tokens_private, proofs) = user_protocol.process_response(responses);

            // User verifies each proof
            for i in 0..num_tokens {
                let nonce = if let Some(n) = &nonces {
                    Some(n[i])
                } else {
                    None
                };
                proofs[i]
                    .verify::<Sha256>(&signer_pk, &params, nonce)
                    .unwrap();
            }
            user_time += start.elapsed();

            println!(
                "Time to generate {} tokens with each request of {} messages by signer is {:?}, and by user is {:?}",
                num_tokens,
                message_count,
                signer_time,
                user_time
            );

            for i in 0..num_tokens {
                let user_auth_message = [1, 2, 3, 4, 5];
                let schnorr_signature = SchnorrSignature::new::<_, Sha256>(
                    &mut rng,
                    &user_auth_message,
                    &user_sk.0,
                    &params.g,
                );
                assert!(schnorr_signature.verify::<Sha256>(
                    &user_auth_message,
                    &user_pk.0,
                    &params.g
                ));

                let mut revealed_indices = BTreeSet::new();
                revealed_indices.insert(0);
                revealed_indices.insert(2);

                let mut revealed_msgs = BTreeMap::new();
                for i in revealed_indices.iter() {
                    revealed_msgs.insert(*i, messages[*i]);
                }

                let mut proof_create_duration = Duration::default();
                let start = Instant::now();
                let pok = PoKOfMACProtocol::init_using_token(
                    &mut rng,
                    tokens_private[i].clone(),
                    proofs[i].clone(),
                    &params,
                    messages.iter().enumerate().map(|(idx, msg)| {
                        if revealed_indices.contains(&idx) {
                            MessageOrBlinding::RevealMessage(msg)
                        } else {
                            MessageOrBlinding::BlindMessageRandomly(msg)
                        }
                    }),
                    &user_pk,
                    HardwareSignatureType::Schnorr,
                    None,
                )
                .unwrap();
                let mut chal_bytes_prover = vec![];
                pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
                    .unwrap();
                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
                let transformed_schnorr_sig = pok.transform_schnorr_sig(schnorr_signature).unwrap();
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
                let nonce = if let Some(n) = &nonces {
                    Some(n[i])
                } else {
                    None
                };
                proof
                    .verify_given_proof_of_validity_of_keyed_proof::<Sha256>(
                        &revealed_msgs,
                        &challenge_verifier,
                        &signer_pk,
                        &params,
                        nonce,
                        None,
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

        check(10, num_tokens, None);
        let mut nonces = vec![];
        for _ in 0..num_tokens {
            nonces.push(b"test-nonce".as_slice());
        }
        check(10, num_tokens, Some(nonces));
    }

    #[test]
    fn designated_verifier_proof_of_knowledge_of_MAC() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
        let signer_sk = SecretKey::new(&mut rng);
        let signer_pk = SignerPublicKey::new_from_params(&signer_sk, &params);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = UserPublicKey::new_from_params(&user_sk, &params);

        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof = ProofOfValidityOfMAC::new::<_, Sha256>(
            &mut rng, &mac, &signer_sk, &signer_pk, &params, None,
        );

        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
            .unwrap();

        let user_auth_message = [1, 2, 3, 4, 5];
        let schnorr_signature =
            SchnorrSignature::new::<_, Sha256>(&mut rng, &user_auth_message, &user_sk.0, &params.g);
        assert!(schnorr_signature.verify::<Sha256>(&user_auth_message, &user_pk.0, &params.g));

        // Its assumed the generator used in creating verifier's public key is g_tilde
        let verifier_sk = Fr::rand(&mut rng);
        let verifier_pk = (params.g_tilde * verifier_sk).into_affine();

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
            HardwareSignatureType::Schnorr,
            Some(&verifier_pk),
        )
        .unwrap();
        assert!(pok.designated_verifier_pk_proof.is_some());
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        // The proves can include the verifier's given nonce if exists
        let challenge_prover = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
        let transformed_schnorr_sig = pok.transform_schnorr_sig(schnorr_signature).unwrap();
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
            .verify(
                &revealed_msgs,
                &challenge_verifier,
                &signer_sk,
                &params,
                Some(&verifier_pk),
            )
            .unwrap();
        proof_verif_duration += start.elapsed();

        assert!(proof.designated_verifier_pk_proof.is_some());

        println!(
            "Time to create designated verifier proof with message size {} and revealing {} messages is {:?}",
            message_count,
            revealed_indices.len(),
            proof_create_duration
        );
        println!(
            "Time to verify designated verifier proof with message size {} and revealing {} messages is {:?}",
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
            .verify_common(
                &revealed_msgs,
                &challenge_verifier,
                &params,
                Some(&verifier_pk),
            )
            .unwrap();
    }

    #[test]
    fn proof_of_knowledge_of_MAC_with_ecdsa() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let message_count = 10;
        let messages = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        // g is being overridden with the standard generator of ECDSA. This isn't clean
        let mut params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
        params.g = EcdsaSignature::generator();

        let signer_sk = SecretKey::new(&mut rng);
        let signer_pk = SignerPublicKey::new_from_params(&signer_sk, &params);

        let user_sk = SecretKey::new(&mut rng);
        let user_pk = UserPublicKey::new_from_params(&user_sk, &params);

        let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
        let proof = ProofOfValidityOfMAC::new::<_, Sha256>(
            &mut rng, &mac, &signer_sk, &signer_pk, &params, None,
        );

        mac.verify(&messages, &user_pk, &signer_sk, &params)
            .unwrap();
        proof
            .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
            .unwrap();

        // ECDSA works. Assumes that the user has hashed its message
        let user_auth_message = Fr::rand(&mut rng);
        let ecdsa_signature = EcdsaSignature::new_prehashed(&mut rng, user_auth_message, user_sk.0);
        assert!(ecdsa_signature.verify_prehashed(user_auth_message, user_pk.0));

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
            HardwareSignatureType::Ecdsa,
            None,
        )
        .unwrap();
        assert!(pok.designated_verifier_pk_proof.is_none());

        let transformed_user_auth_message = pok
            .transform_message_for_ecdsa_sig(user_auth_message)
            .unwrap();
        proof_create_duration += start.elapsed();
        // Signature is on transformed message is correct
        let ecdsa_signature =
            EcdsaSignature::new_prehashed(&mut rng, transformed_user_auth_message, user_sk.0);
        assert!(ecdsa_signature.verify_prehashed(transformed_user_auth_message, user_pk.0));
        assert!(!ecdsa_signature.verify_prehashed(transformed_user_auth_message, pok.blinded_pk));

        let start = Instant::now();
        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
            .unwrap();
        // The proves can include the verifier's given nonce if exists
        let challenge_prover = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
        let transformed_ecdsa_sig = pok.transform_ecdsa_sig(ecdsa_signature).unwrap();
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

        // The verifier needs to check that the ECDSA signature is valid
        assert!(transformed_ecdsa_sig.verify_prehashed(user_auth_message, proof.blinded_pk));

        // This is an example where the verifier has the secret key
        proof
            .verify(
                &revealed_msgs,
                &challenge_verifier,
                &signer_sk,
                &params,
                None,
            )
            .unwrap();
        proof_verif_duration += start.elapsed();

        assert!(proof.designated_verifier_pk_proof.is_none());

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
            .verify_common(&revealed_msgs, &challenge_verifier, &params, None)
            .unwrap();
    }
}
