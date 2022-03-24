use crate::error::ProofSystemError;
use crate::prelude::schnorr::SchnorrProtocol;
use crate::prelude::SaverProof;
use crate::statement;
use crate::statement::PedersenCommitment;
use crate::statement_proof::StatementProof;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_groth16::prepare_verifying_key;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::RngCore;
use ark_std::{
    collections::BTreeMap,
    format,
    io::{Read, Write},
    ops::Add,
    vec,
    vec::Vec,
    UniformRand,
};
use saver::commitment::ChunkedCommitment;
use saver::encryption::{Ciphertext, Encryption};
use saver::utils::decompose;

/// Apart from the SNARK protocol, this also runs 3 Schnorr proof of knowledge protocols
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SaverProtocol<E: PairingEngine> {
    pub id: usize,
    pub statement: statement::Saver<E>,
    pub ciphertext: Option<Ciphertext<E>>,
    pub randomness_enc: Option<E::Fr>,
    pub snark_proof: Option<saver::saver_groth16::Proof<E>>,
    pub comm_chunks: Option<E::G1Affine>,
    pub comm_combined: Option<E::G1Affine>,
    /// Schnorr protocol for proving knowledge of message chunks in ciphertext's commitment
    pub sp_ciphertext: Option<SchnorrProtocol<E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of message chunks in the chunked commitment
    pub sp_chunks: Option<SchnorrProtocol<E::G1Affine>>,
    /// Schnorr protocol for proving knowledge of the whole message in the combined commitment
    pub sp_combined: Option<SchnorrProtocol<E::G1Affine>>,
}

impl<E: PairingEngine> SaverProtocol<E> {
    pub fn new(id: usize, statement: statement::Saver<E>) -> Self {
        Self {
            id,
            statement,
            ciphertext: None,
            randomness_enc: None,
            snark_proof: None,
            comm_chunks: None,
            comm_combined: None,
            sp_ciphertext: None,
            sp_chunks: None,
            sp_combined: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        message: E::Fr,
        blinding_combined_message: Option<E::Fr>,
    ) -> Result<(), ProofSystemError> {
        if self.ciphertext.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let (ciphertext, randomness_enc, proof) = Encryption::encrypt_with_proof(
            rng,
            &message,
            &self.statement.encryption_key,
            &self.statement.snark_proving_key,
            self.statement.chunk_bit_size,
        )?;
        let h_blinding = E::Fr::rand(rng);
        let blinding_combined_message = if blinding_combined_message.is_none() {
            E::Fr::rand(rng)
        } else {
            blinding_combined_message.unwrap()
        };
        let comm_combined = self
            .statement
            .chunked_commitment_gens
            .G
            .mul(message.into_repr())
            .add(
                &(self
                    .statement
                    .chunked_commitment_gens
                    .H
                    .mul(h_blinding.into_repr())),
            )
            .into_affine();
        let comm_chunks = ChunkedCommitment::<E::G1Affine>::new(
            &message,
            &h_blinding,
            self.statement.chunk_bit_size,
            &self.statement.chunked_commitment_gens,
        )?;

        let decomposed_message = decompose(&message, self.statement.chunk_bit_size)?
            .into_iter()
            .map(|m| E::Fr::from(m as u64))
            .collect::<Vec<_>>();

        let ck_com_ct = self.statement.encryption_key.commitment_key();
        let st_ciphertext = PedersenCommitment {
            bases: ck_com_ct,
            commitment: ciphertext.commitment,
        };
        let st_chunks = PedersenCommitment {
            bases: comm_chunks.1,
            commitment: comm_chunks.0,
        };
        let st_combined = PedersenCommitment {
            bases: vec![
                self.statement.chunked_commitment_gens.G,
                self.statement.chunked_commitment_gens.H,
            ],
            commitment: comm_combined,
        };

        // NOTE: value of id is dummy
        let mut sp_ciphertext = SchnorrProtocol::new(10000, st_ciphertext);
        let mut sp_chunks = SchnorrProtocol::new(10000, st_chunks);
        let mut sp_combined = SchnorrProtocol::new(10000, st_combined);

        let blindings_chunks = (0..decomposed_message.len())
            .map(|i| (i, E::Fr::rand(rng)))
            .collect::<BTreeMap<usize, E::Fr>>();
        let mut sp_ciphertext_wit = decomposed_message.clone();
        sp_ciphertext_wit.push(randomness_enc);
        sp_ciphertext.init(rng, blindings_chunks.clone(), sp_ciphertext_wit)?;

        let mut sp_chunks_wit = decomposed_message.clone();
        sp_chunks_wit.push(h_blinding);
        sp_chunks.init(rng, blindings_chunks, sp_chunks_wit)?;

        let mut blinding = BTreeMap::new();
        blinding.insert(0, blinding_combined_message);
        sp_combined.init(rng, blinding, vec![message, h_blinding])?;

        self.ciphertext = Some(ciphertext);
        self.randomness_enc = Some(randomness_enc);
        self.snark_proof = Some(proof);
        self.comm_chunks = Some(comm_chunks.0);
        self.comm_combined = Some(comm_combined);
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

    pub fn gen_proof_contribution<G: AffineCurve>(
        &mut self,
        challenge: &E::Fr,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.ciphertext.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        Ok(StatementProof::Saver(SaverProof {
            ciphertext: self.ciphertext.take().unwrap(),
            snark_proof: self.snark_proof.take().unwrap(),
            comm_chunks: self.comm_chunks.take().unwrap(),
            comm_combined: self.comm_combined.take().unwrap(),
            sp_ciphertext: self
                .sp_ciphertext
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
            sp_chunks: self
                .sp_chunks
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
            sp_combined: self
                .sp_combined
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    pub fn verify_proof_contribution<G: AffineCurve>(
        &self,
        challenge: &E::Fr,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match proof {
            StatementProof::Saver(proof) => {
                // Both commitments, one to chunks and the other to the combined message must be same
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

                let pvk = prepare_verifying_key(&self.statement.snark_proving_key.pk.vk);
                let pek = self.statement.encryption_key.prepare();
                let pgens = self.statement.encryption_gens.prepared();
                proof
                    .ciphertext
                    .verify_commitment_and_proof_given_prepared(
                        &proof.snark_proof,
                        &pvk,
                        &pek,
                        &pgens,
                    )?;

                let ck_com_ct = self.statement.encryption_key.commitment_key();
                let st_ciphertext = PedersenCommitment {
                    bases: ck_com_ct,
                    commitment: proof.ciphertext.commitment,
                };
                let st_chunks = PedersenCommitment {
                    bases: ChunkedCommitment::<E::G1Affine>::commitment_key(
                        &self.statement.chunked_commitment_gens,
                        self.statement.chunk_bit_size,
                    ),
                    commitment: proof.comm_chunks,
                };
                let st_combined = PedersenCommitment {
                    bases: vec![
                        self.statement.chunked_commitment_gens.G,
                        self.statement.chunked_commitment_gens.H,
                    ],
                    commitment: proof.comm_combined,
                };
                // NOTE: value of id is dummy
                let sp_ciphertext = SchnorrProtocol::new(10000, st_ciphertext);
                let sp_chunks = SchnorrProtocol::new(10000, st_chunks);
                let sp_combined = SchnorrProtocol::new(10000, st_combined);

                sp_ciphertext
                    .verify_proof_contribution_as_struct(challenge, &proof.sp_ciphertext)?;
                sp_chunks.verify_proof_contribution_as_struct(challenge, &proof.sp_chunks)?;
                sp_combined.verify_proof_contribution_as_struct(challenge, &proof.sp_combined)?;
                Ok(())
            }

            _ => Err(ProofSystemError::ProofIncompatibleWithProtocol(format!(
                "{:?}",
                self.statement
            ))),
        }
    }

    pub fn compute_challenge_contribution<W: Write>(
        stat: &statement::Saver<E>,
        proof: &SaverProof<E>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        stat.encryption_key
            .commitment_key()
            .serialize_unchecked(&mut writer)?;
        proof
            .ciphertext
            .commitment
            .serialize_unchecked(&mut writer)?;
        proof.sp_ciphertext.t.serialize_unchecked(&mut writer)?;

        ChunkedCommitment::<E::G1Affine>::commitment_key(
            &stat.chunked_commitment_gens,
            stat.chunk_bit_size,
        )
        .serialize_unchecked(&mut writer)?;
        proof.comm_chunks.serialize_unchecked(&mut writer)?;
        proof.sp_chunks.t.serialize_unchecked(&mut writer)?;

        vec![
            stat.chunked_commitment_gens.G,
            stat.chunked_commitment_gens.H,
        ]
        .serialize_unchecked(&mut writer)?;
        proof.comm_combined.serialize_unchecked(&mut writer)?;
        proof.sp_combined.t.serialize_unchecked(&mut writer)?;
        Ok(())
    }
}
