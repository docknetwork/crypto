use crate::{
    error::ProofSystemError,
    statement_proof::{
        PedersenCommitmentProof, SaverProof, SaverProofWhenAggregatingSnarks, StatementProof,
    },
    sub_protocols::schnorr::SchnorrProtocol,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    collections::BTreeMap,
    io::Write,
    ops::Add,
    rand::{Rng, RngCore},
    vec,
    vec::Vec,
    UniformRand,
};
use dock_crypto_utils::{ff::powers, randomized_pairing_check::RandomizedPairingChecker};
use saver::{
    commitment::ChunkedCommitment,
    encryption::{Ciphertext, Encryption},
    keygen::PreparedEncryptionKey,
    prelude::{ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey, SaverError},
    saver_groth16::calculate_d,
    setup::PreparedEncryptionGens,
    utils::decompose,
};

/// Apart from the SAVER protocol (encryption and snark proof), this also runs 3 Schnorr proof of knowledge protocols
#[derive(Clone, Debug, PartialEq)]
pub struct SaverProtocol<'a, E: Pairing> {
    pub id: usize,
    pub chunk_bit_size: u8,
    pub encryption_gens: &'a EncryptionGens<E>,
    pub chunked_commitment_gens: &'a ChunkedCommitmentGens<E::G1Affine>,
    pub encryption_key: &'a EncryptionKey<E>,
    /// The SNARK proving key, will be `None` if invoked by verifier.
    pub snark_proving_key: Option<&'a ProvingKey<E>>,
    /// The SNARK verifying key, will be `None` if invoked by prover.
    pub snark_verifying_key: Option<&'a VerifyingKey<E>>,
    pub ciphertext: Option<Ciphertext<E>>,
    pub snark_proof: Option<saver::saver_groth16::Proof<E>>,
    /// Schnorr protocol for proving knowledge of message chunks in ciphertext's commitment
    pub sp_ciphertext: Option<SchnorrProtocol<'a, E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of message chunks in the chunked commitment
    pub sp_chunks: Option<SchnorrProtocol<'a, E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of the whole message in the combined commitment
    pub sp_combined: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: Pairing> SaverProtocol<'a, E> {
    /// Create an instance of this protocol for the prover.
    pub fn new_for_prover(
        id: usize,
        chunk_bit_size: u8,
        encryption_gens: &'a EncryptionGens<E>,
        chunked_commitment_gens: &'a ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: &'a EncryptionKey<E>,
        snark_proving_key: &'a ProvingKey<E>,
    ) -> Self {
        Self {
            id,
            chunk_bit_size,
            encryption_gens,
            chunked_commitment_gens,
            encryption_key,
            snark_proving_key: Some(snark_proving_key),
            snark_verifying_key: None,
            ciphertext: None,
            snark_proof: None,
            sp_ciphertext: None,
            sp_chunks: None,
            sp_combined: None,
        }
    }

    /// Create an instance of this protocol for the verifier.
    pub fn new_for_verifier(
        id: usize,
        chunk_bit_size: u8,
        encryption_gens: &'a EncryptionGens<E>,
        chunked_commitment_gens: &'a ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: &'a EncryptionKey<E>,
        snark_verifying_key: &'a VerifyingKey<E>,
    ) -> Self {
        Self {
            id,
            chunk_bit_size,
            encryption_gens,
            chunked_commitment_gens,
            encryption_key,
            snark_proving_key: None,
            snark_verifying_key: Some(snark_verifying_key),
            ciphertext: None,
            snark_proof: None,
            sp_ciphertext: None,
            sp_chunks: None,
            sp_combined: None,
        }
    }

    /// Encrypt the message and create proof using SAVER. Then initialize 3 Schnorr proof of knowledge
    /// protocols
    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        ck_comm_ct: &'a [E::G1Affine],
        ck_comm_chunks: &'a [E::G1Affine],
        ck_comm_combined: &'a [E::G1Affine],
        message: E::ScalarField,
        blinding_combined_message: Option<E::ScalarField>,
    ) -> Result<(), ProofSystemError> {
        if self.ciphertext.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let snark_proving_key = self
            .snark_proving_key
            .ok_or(ProofSystemError::SaverSnarkProvingKeyNotProvided)?;

        // Create ciphertext and the snark proof
        let (ciphertext, randomness_enc, proof) = Encryption::encrypt_with_proof(
            rng,
            &message,
            self.encryption_key,
            snark_proving_key,
            self.chunk_bit_size,
        )?;

        self.init_schnorr_protocols(
            rng,
            ck_comm_ct,
            ck_comm_chunks,
            ck_comm_combined,
            message,
            blinding_combined_message,
            ciphertext,
            randomness_enc,
            proof,
        )
    }

    pub fn init_with_ciphertext_and_proof<R: RngCore>(
        &mut self,
        rng: &mut R,
        ck_comm_ct: &'a [E::G1Affine],
        ck_comm_chunks: &'a [E::G1Affine],
        ck_comm_combined: &'a [E::G1Affine],
        message: E::ScalarField,
        blinding_combined_message: Option<E::ScalarField>,
        old_randomness: E::ScalarField,
        ciphertext: Ciphertext<E>,
        proof: ark_groth16::Proof<E>,
    ) -> Result<(), ProofSystemError> {
        if self.ciphertext.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        };
        let snark_proving_key = self
            .snark_proving_key
            .ok_or(ProofSystemError::SaverSnarkProvingKeyNotProvided)?;

        let (ciphertext, randomness_enc, proof) = Encryption::rerandomize_ciphertext_and_proof(
            ciphertext,
            proof,
            &snark_proving_key.pk.vk,
            self.encryption_key,
            rng,
        )?;

        self.init_schnorr_protocols(
            rng,
            ck_comm_ct,
            ck_comm_chunks,
            ck_comm_combined,
            message,
            blinding_combined_message,
            ciphertext,
            old_randomness + randomness_enc,
            proof,
        )
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.ciphertext.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.sp_ciphertext
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        self.sp_chunks
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        self.sp_combined
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }

    /// Generate responses for the 3 Schnorr protocols
    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E>, ProofSystemError> {
        if self.ciphertext.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        let mut sp_chunks = self.sp_chunks.take().unwrap();
        let mut sp_combined = self.sp_combined.take().unwrap();
        Ok(StatementProof::Saver(SaverProof {
            ciphertext: self.ciphertext.take().unwrap(),
            snark_proof: self.snark_proof.take().unwrap(),
            comm_chunks: sp_chunks.commitment,
            comm_combined: sp_combined.commitment,
            sp_ciphertext: self
                .sp_ciphertext
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
            sp_chunks: sp_chunks.gen_proof_contribution_as_struct(challenge)?,
            sp_combined: sp_combined.gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    /// Verify that the snark proof is valid, the commitment in the ciphertext is correct, the commitment
    /// to the chunks and the combined message are equal, the chunks committed in ciphertext are same
    /// as the ones committed in the chunked commitment and all the 3 Schnorr proofs are valid.
    pub fn verify_proof_contribution(
        &self,
        challenge: &E::ScalarField,
        proof: &SaverProof<E>,
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
        pvk: &PreparedVerifyingKey<E>,
        pgens: impl Into<PreparedEncryptionGens<E>>,
        pek: impl Into<PreparedEncryptionKey<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        let pek = pek.into();
        let pgens = pgens.into();
        let expected_count = pek.supported_chunks_count()? as usize;
        if proof.ciphertext.enc_chunks.len() != expected_count {
            return Err(SaverError::IncompatibleEncryptionKey(
                proof.ciphertext.enc_chunks.len(),
                expected_count,
            )
            .into());
        }
        match pairing_checker {
            Some(c) => {
                let (a, b) = (
                    Encryption::<E>::get_g1_for_ciphertext_commitment_pairing_checks(
                        &proof.ciphertext.X_r,
                        &proof.ciphertext.enc_chunks,
                        &proof.ciphertext.commitment,
                    ),
                    Encryption::get_g2_for_ciphertext_commitment_pairing_checks(&pek, &pgens),
                );
                c.add_multiple_sources_and_target(&a, b, &PairingOutput::zero());
                let d = calculate_d(pvk, &proof.ciphertext)?;
                c.add_multiple_sources_and_target(
                    &[proof.snark_proof.a, proof.snark_proof.c, d],
                    [
                        proof.snark_proof.b.into(),
                        pvk.delta_g2_neg_pc.clone(),
                        pvk.gamma_g2_neg_pc.clone(),
                    ],
                    &PairingOutput(pvk.alpha_g1_beta_g2),
                );
            }
            None => proof
                .ciphertext
                .verify_commitment_and_proof(&proof.snark_proof, pvk, pek, pgens)
                .map_err(|e| ProofSystemError::SaverProofContributionFailed(self.id as u32, e))?,
        }

        self.verify_ciphertext_and_commitment(
            challenge,
            &proof.ciphertext,
            proof.comm_combined.clone(),
            proof.comm_chunks.clone(),
            &proof.sp_ciphertext,
            &proof.sp_chunks,
            &proof.sp_combined,
            ck_comm_ct,
            ck_comm_chunks,
            ck_comm_combined,
        )
    }

    pub fn verify_ciphertext_and_commitment(
        &self,
        challenge: &E::ScalarField,
        ciphertext: &Ciphertext<E>,
        comm_combined: E::G1Affine,
        comm_chunks: E::G1Affine,
        s_pr_ciphertext: &PedersenCommitmentProof<E::G1Affine>,
        s_pr_chunks: &PedersenCommitmentProof<E::G1Affine>,
        s_pr_combined: &PedersenCommitmentProof<E::G1Affine>,
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        // NOTE: value of id is dummy
        let sp_ciphertext = SchnorrProtocol::new(10000, ck_comm_ct, ciphertext.commitment);
        let sp_chunks = SchnorrProtocol::new(10000, ck_comm_chunks, comm_chunks);
        let sp_combined = SchnorrProtocol::new(10000, ck_comm_combined, comm_combined);

        sp_ciphertext
            .verify_proof_contribution(challenge, s_pr_ciphertext)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))?;
        sp_chunks
            .verify_proof_contribution(challenge, s_pr_chunks)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))?;
        sp_combined
            .verify_proof_contribution(challenge, s_pr_combined)
            .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
    }

    pub fn verify_ciphertext_commitments_in_batch<R: Rng>(
        rng: &mut R,
        ciphertexts: &[Ciphertext<E>],
        pgens: impl Into<PreparedEncryptionGens<E>>,
        pek: impl Into<PreparedEncryptionKey<E>>,
        pairing_checker: &mut Option<RandomizedPairingChecker<E>>,
    ) -> Result<(), ProofSystemError> {
        let r = E::ScalarField::rand(rng);
        let r_powers = powers(
            &r,
            ciphertexts
                .len()
                .try_into()
                .map_err(|_| ProofSystemError::TooManyCiphertexts(ciphertexts.len()))?,
        );
        let pek = pek.into();
        let pgens = pgens.into();
        match pairing_checker {
            Some(c) => {
                assert_eq!(r_powers.len(), ciphertexts.len());
                let expected_count = pek.supported_chunks_count()? as usize;
                for c in ciphertexts {
                    if c.enc_chunks.len() != expected_count {
                        return Err(SaverError::IncompatibleEncryptionKey(
                            c.enc_chunks.len(),
                            expected_count,
                        )
                        .into());
                    }
                }

                let a = Encryption::get_g1_for_ciphertext_commitments_in_batch_pairing_checks(
                    ciphertexts,
                    &r_powers,
                );
                let b = Encryption::get_g2_for_ciphertext_commitment_pairing_checks(&pek, &pgens);
                c.add_multiple_sources_and_target(&a, b, &PairingOutput::zero());
                Ok(())
            }
            None => Encryption::verify_commitments_in_batch(ciphertexts, &r_powers, pek, pgens)
                .map_err(|e| e.into()),
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
        proof: &SaverProof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        ck_comm_ct.serialize_compressed(&mut writer)?;
        proof
            .ciphertext
            .commitment
            .serialize_compressed(&mut writer)?;
        proof.sp_ciphertext.t.serialize_compressed(&mut writer)?;

        ck_comm_chunks.serialize_compressed(&mut writer)?;
        proof.comm_chunks.serialize_compressed(&mut writer)?;
        proof.sp_chunks.t.serialize_compressed(&mut writer)?;

        ck_comm_combined.serialize_compressed(&mut writer)?;
        proof.comm_combined.serialize_compressed(&mut writer)?;
        proof.sp_combined.t.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn compute_challenge_contribution_when_aggregating_snark<W: Write>(
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
        proof: &SaverProofWhenAggregatingSnarks<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        ck_comm_ct.serialize_compressed(&mut writer)?;
        proof
            .ciphertext
            .commitment
            .serialize_compressed(&mut writer)?;
        proof.sp_ciphertext.t.serialize_compressed(&mut writer)?;

        ck_comm_chunks.serialize_compressed(&mut writer)?;
        proof.comm_chunks.serialize_compressed(&mut writer)?;
        proof.sp_chunks.t.serialize_compressed(&mut writer)?;

        ck_comm_combined.serialize_compressed(&mut writer)?;
        proof.comm_combined.serialize_compressed(&mut writer)?;
        proof.sp_combined.t.serialize_compressed(&mut writer)?;
        Ok(())
    }

    pub fn validate_encryption_key(
        chunk_bit_size: u8,
        encryption_key: &EncryptionKey<E>,
    ) -> Result<(), ProofSystemError> {
        if encryption_key.supported_chunks_count()?
            != saver::utils::chunks_count::<E::ScalarField>(chunk_bit_size)
        {
            Err(ProofSystemError::SaverError(
                saver::error::SaverError::IncompatibleEncryptionKey(
                    saver::utils::chunks_count::<E::ScalarField>(chunk_bit_size) as usize,
                    encryption_key.supported_chunks_count()? as usize,
                ),
            ))
        } else {
            Ok(())
        }
    }

    /// Commitment key for the commitment in ciphertext
    pub fn encryption_comm_key(encryption_key: &EncryptionKey<E>) -> Vec<E::G1Affine> {
        encryption_key.commitment_key()
    }

    /// Commitment key for chunked commitment
    pub fn chunked_comm_keys(
        chunked_commitment_gens: &ChunkedCommitmentGens<E::G1Affine>,
        chunk_bit_size: u8,
    ) -> (Vec<E::G1Affine>, Vec<E::G1Affine>) {
        let ck_comm_chunks = ChunkedCommitment::<E::G1Affine>::commitment_key(
            chunked_commitment_gens,
            chunk_bit_size,
        );
        let ck_comm_combined = vec![chunked_commitment_gens.G, chunked_commitment_gens.H];
        (ck_comm_chunks, ck_comm_combined)
    }

    /// Initialize 3 Schnorr proof of knowledge protocols to prove the knowledge of committed value
    /// in ciphertext
    fn init_schnorr_protocols<R: RngCore>(
        &mut self,
        rng: &mut R,
        ck_comm_ct: &'a [E::G1Affine],
        ck_comm_chunks: &'a [E::G1Affine],
        ck_comm_combined: &'a [E::G1Affine],
        message: E::ScalarField,
        blinding_combined_message: Option<E::ScalarField>,
        ciphertext: Ciphertext<E>,
        randomness_enc: E::ScalarField,
        proof: ark_groth16::Proof<E>,
    ) -> Result<(), ProofSystemError> {
        // blinding used for `H` in both commitments
        let h_blinding = E::ScalarField::rand(rng);

        // blinding used to prove knowledge of message in `comm_combined`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding_combined_message = if blinding_combined_message.is_none() {
            E::ScalarField::rand(rng)
        } else {
            blinding_combined_message.unwrap()
        };

        // Initialize the 3 Schnorr protocols

        let comm_combined = self
            .chunked_commitment_gens
            .G
            .mul_bigint(message.into_bigint())
            .add(
                &(self
                    .chunked_commitment_gens
                    .H
                    .mul_bigint(h_blinding.into_bigint())),
            )
            .into_affine();
        let comm_chunks = ChunkedCommitment::<E::G1Affine>::get_commitment_given_commitment_key(
            &message,
            &h_blinding,
            self.chunk_bit_size,
            ck_comm_chunks,
        )?;

        let message_chunks = decompose(&message, self.chunk_bit_size)?
            .into_iter()
            .map(|m| E::ScalarField::from(m as u64))
            .collect::<Vec<_>>();

        // NOTE: value of id is dummy
        let mut sp_ciphertext = SchnorrProtocol::new(10000, ck_comm_ct, ciphertext.commitment);
        let mut sp_chunks = SchnorrProtocol::new(10000, ck_comm_chunks, comm_chunks);
        let mut sp_combined = SchnorrProtocol::new(10000, ck_comm_combined, comm_combined);

        let blindings_chunks = (0..message_chunks.len())
            .map(|i| (i, E::ScalarField::rand(rng)))
            .collect::<BTreeMap<usize, E::ScalarField>>();
        let mut sp_ciphertext_wit = message_chunks.clone();
        sp_ciphertext_wit.push(randomness_enc);
        sp_ciphertext.init(rng, blindings_chunks.clone(), sp_ciphertext_wit)?;

        let mut sp_chunks_wit = message_chunks;
        sp_chunks_wit.push(h_blinding);
        sp_chunks.init(rng, blindings_chunks, sp_chunks_wit)?;

        let mut blinding = BTreeMap::new();
        blinding.insert(0, blinding_combined_message);
        sp_combined.init(rng, blinding, vec![message, h_blinding])?;

        self.ciphertext = Some(ciphertext);
        self.snark_proof = Some(proof);
        self.sp_ciphertext = Some(sp_ciphertext);
        self.sp_chunks = Some(sp_chunks);
        self.sp_combined = Some(sp_combined);
        Ok(())
    }
}
