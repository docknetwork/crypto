use crate::error::ProofSystemError;
use crate::statement_proof::{SaverProof, StatementProof};
use crate::sub_protocols::schnorr::SchnorrProtocol;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use ark_std::{collections::BTreeMap, io::Write, ops::Add, vec, vec::Vec, UniformRand};
use saver::commitment::ChunkedCommitment;
use saver::encryption::{Ciphertext, Encryption};
use saver::keygen::PreparedEncryptionKey;
use saver::prelude::{ChunkedCommitmentGens, EncryptionGens, EncryptionKey, ProvingKey};
use saver::setup::PreparedEncryptionGens;
use saver::utils::decompose;

/// Apart from the SAVER protocol (encryption and snark proof), this also runs 3 Schnorr proof of knowledge protocols
#[derive(Clone, Debug, PartialEq)]
pub struct SaverProtocol<'a, E: PairingEngine> {
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
    /// Randomness used in encryption
    pub randomness_enc: Option<E::Fr>,
    pub snark_proof: Option<saver::saver_groth16::Proof<E>>,
    /// Schnorr protocol for proving knowledge of message chunks in ciphertext's commitment
    pub sp_ciphertext: Option<SchnorrProtocol<'a, E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of message chunks in the chunked commitment
    pub sp_chunks: Option<SchnorrProtocol<'a, E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of the whole message in the combined commitment
    pub sp_combined: Option<SchnorrProtocol<'a, E::G1Affine>>,
}

impl<'a, E: PairingEngine> SaverProtocol<'a, E> {
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
            randomness_enc: None,
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
            randomness_enc: None,
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
        message: E::Fr,
        blinding_combined_message: Option<E::Fr>,
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

        // blinding used for `H` in both commitments
        let h_blinding = E::Fr::rand(rng);

        // blinding used to prove knowledge of message in `comm_combined`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding_combined_message = if blinding_combined_message.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding_combined_message.unwrap()
        };

        // Initialize the 3 Schnorr protocols

        let comm_combined = self
            .chunked_commitment_gens
            .G
            .mul(message.into_repr())
            .add(&(self.chunked_commitment_gens.H.mul(h_blinding.into_repr())))
            .into_affine();
        let comm_chunks = ChunkedCommitment::<E::G1Affine>::get_commitment_given_commitment_key(
            &message,
            &h_blinding,
            self.chunk_bit_size,
            &ck_comm_chunks,
        )?;

        let message_chunks = decompose(&message, self.chunk_bit_size)?
            .into_iter()
            .map(|m| E::Fr::from(m as u64))
            .collect::<Vec<_>>();

        // NOTE: value of id is dummy
        let mut sp_ciphertext = SchnorrProtocol::new(10000, ck_comm_ct, ciphertext.commitment);
        let mut sp_chunks = SchnorrProtocol::new(10000, ck_comm_chunks, comm_chunks);
        let mut sp_combined = SchnorrProtocol::new(10000, ck_comm_combined, comm_combined);

        let blindings_chunks = (0..message_chunks.len())
            .map(|i| (i, E::Fr::rand(rng)))
            .collect::<BTreeMap<usize, E::Fr>>();
        let mut sp_ciphertext_wit = message_chunks.clone();
        sp_ciphertext_wit.push(randomness_enc);
        sp_ciphertext.init(rng, blindings_chunks.clone(), sp_ciphertext_wit)?;

        let mut sp_chunks_wit = message_chunks.clone();
        sp_chunks_wit.push(h_blinding);
        sp_chunks.init(rng, blindings_chunks, sp_chunks_wit)?;

        let mut blinding = BTreeMap::new();
        blinding.insert(0, blinding_combined_message);
        sp_combined.init(rng, blinding, vec![message, h_blinding])?;

        self.ciphertext = Some(ciphertext);
        self.randomness_enc = Some(randomness_enc);
        self.snark_proof = Some(proof);
        self.sp_ciphertext = Some(sp_ciphertext);
        self.sp_chunks = Some(sp_chunks);
        self.sp_combined = Some(sp_combined);
        Ok(())
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
    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
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
        challenge: &E::Fr,
        proof: &SaverProof<E>,
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
    ) -> Result<(), ProofSystemError> {
        // Both commitments, one to the chunks and the other to the combined message must be same
        if proof.comm_chunks != proof.comm_combined {
            return Err(ProofSystemError::SaverInequalChunkedCommitment);
        }

        // Each chunk in the chunked commitment should be same as the chunk in ciphertext's
        // commitment
        if proof.sp_chunks.response.len() != proof.sp_ciphertext.response.len() {
            return Err(ProofSystemError::SaverInsufficientChunkedCommitmentResponses);
        }
        for i in 0..(proof.sp_chunks.response.len() - 1) {
            if proof.sp_chunks.response.get_response(i)?
                != proof.sp_ciphertext.response.get_response(i)?
            {
                return Err(ProofSystemError::SaverInequalChunkedCommitmentResponse);
            }
        }

        let snark_verifying_key = self
            .snark_verifying_key
            .ok_or(ProofSystemError::SaverSnarkVerifyingKeyNotProvided)?;

        let pvk = prepare_verifying_key(snark_verifying_key);
        let pek = self.encryption_key.prepared();
        let pgens = self.encryption_gens.prepared();
        self.verify_proof_contribution_using_prepared(
            challenge,
            proof,
            ck_comm_ct,
            ck_comm_chunks,
            ck_comm_combined,
            &pvk,
            &pgens,
            &pek,
        )
    }

    pub fn verify_proof_contribution_using_prepared(
        &self,
        challenge: &E::Fr,
        proof: &SaverProof<E>,
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
        pvk: &PreparedVerifyingKey<E>,
        pgens: &PreparedEncryptionGens<E>,
        pek: &PreparedEncryptionKey<E>,
    ) -> Result<(), ProofSystemError> {
        proof
            .ciphertext
            .verify_commitment_and_proof_given_prepared(&proof.snark_proof, &pvk, &pek, &pgens)?;

        // NOTE: value of id is dummy
        let sp_ciphertext = SchnorrProtocol::new(10000, ck_comm_ct, proof.ciphertext.commitment);
        let sp_chunks = SchnorrProtocol::new(10000, ck_comm_chunks, proof.comm_chunks);
        let sp_combined = SchnorrProtocol::new(10000, ck_comm_combined, proof.comm_combined);

        sp_ciphertext.verify_proof_contribution_as_struct(challenge, &proof.sp_ciphertext)?;
        sp_chunks.verify_proof_contribution_as_struct(challenge, &proof.sp_chunks)?;
        sp_combined.verify_proof_contribution_as_struct(challenge, &proof.sp_combined)?;
        Ok(())
    }

    pub fn compute_challenge_contribution<W: Write>(
        ck_comm_ct: &[E::G1Affine],
        ck_comm_chunks: &[E::G1Affine],
        ck_comm_combined: &[E::G1Affine],
        proof: &SaverProof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        ck_comm_ct.serialize_unchecked(&mut writer)?;
        proof
            .ciphertext
            .commitment
            .serialize_unchecked(&mut writer)?;
        proof.sp_ciphertext.t.serialize_unchecked(&mut writer)?;

        ck_comm_chunks.serialize_unchecked(&mut writer)?;
        proof.comm_chunks.serialize_unchecked(&mut writer)?;
        proof.sp_chunks.t.serialize_unchecked(&mut writer)?;

        ck_comm_combined.serialize_unchecked(&mut writer)?;
        proof.comm_combined.serialize_unchecked(&mut writer)?;
        proof.sp_combined.t.serialize_unchecked(&mut writer)?;
        Ok(())
    }

    pub fn validate_encryption_key(
        chunk_bit_size: u8,
        encryption_key: &EncryptionKey<E>,
    ) -> Result<(), ProofSystemError> {
        if encryption_key.supported_chunks_count()?
            != saver::utils::chunks_count::<E::Fr>(chunk_bit_size)
        {
            Err(ProofSystemError::SaverError(
                saver::error::SaverError::IncompatibleEncryptionKey(
                    saver::utils::chunks_count::<E::Fr>(chunk_bit_size) as usize,
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
}
