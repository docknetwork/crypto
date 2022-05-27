//! Encryption, decryption, verifying commitment and verifying decryption

use crate::circuit::BitsizeCheckCircuit;
use crate::error::SaverError;
use crate::keygen::{
    DecryptionKey, EncryptionKey, PreparedDecryptionKey, PreparedEncryptionKey, SecretKey,
};
use crate::saver_groth16;
use crate::saver_legogroth16;
use crate::setup::{EncryptionGens, PreparedEncryptionGens};
use crate::utils;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::ops::Add;
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
    ops::Neg,
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::utils::CHUNK_TYPE;
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use dock_crypto_utils::serde_utils::*;

/// Ciphertext used with Groth16
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Ciphertext<E: PairingEngine> {
    #[serde_as(as = "AffineGroupBytes")]
    pub X_r: E::G1Affine,
    #[serde_as(as = "Vec<AffineGroupBytes>")]
    pub enc_chunks: Vec<E::G1Affine>,
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: E::G1Affine,
}

/// Ciphertext used with LegoGroth16 and the slightly modified SAVER protocol. See `saver_legogroth16::protocol_2` for more
/// details.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CiphertextAlt<E: PairingEngine> {
    pub X_r: E::G1Affine,
    pub enc_chunks: Vec<E::G1Affine>,
    pub commitment: E::G1Affine,
    pub X_r_sum: E::G1Affine,
}

macro_rules! impl_enc_funcs {
    () => {
        /// Decrypt this ciphertext returning the plaintext and commitment to randomness
        pub fn decrypt(
            &self,
            sk: &SecretKey<E::Fr>,
            dk: &DecryptionKey<E>,
            g_i: &[E::G1Affine],
            chunk_bit_size: u8,
        ) -> crate::Result<(E::Fr, E::G1Affine)> {
            Encryption::decrypt(&self.X_r, &self.enc_chunks, sk, dk, g_i, chunk_bit_size)
        }

        /// Same as `Self::decrypt` but takes prepared decryption key for faster decryption
        pub fn decrypt_given_prepared(
            &self,
            sk: &SecretKey<E::Fr>,
            dk: &PreparedDecryptionKey<E>,
            g_i: &[E::G1Affine],
            chunk_bit_size: u8,
        ) -> crate::Result<(E::Fr, E::G1Affine)> {
            Encryption::decrypt_given_prepared(
                &self.X_r,
                &self.enc_chunks,
                sk,
                dk,
                g_i,
                chunk_bit_size,
            )
        }

        /// Same as `Self::decrypt` but takes prepared decryption key and pairing powers (see `PreparedDecryptionKey::pairing_powers`)
        /// that can be precomputed for even faster decryption
        pub fn decrypt_given_prepared_and_pairing_powers(
            &self,
            sk: &SecretKey<E::Fr>,
            dk: &PreparedDecryptionKey<E>,
            g_i: &[E::G1Affine],
            chunk_bit_size: u8,
            pairing_powers: &[Vec<E::Fqk>],
        ) -> crate::Result<(E::Fr, E::G1Affine)> {
            Encryption::decrypt_given_prepared_and_pairing_powers(
                &self.X_r,
                &self.enc_chunks,
                sk,
                dk,
                g_i,
                chunk_bit_size,
                pairing_powers,
            )
        }

        /// Verify that the ciphertext correctly commits to the message
        pub fn verify_commitment(
            &self,
            ek: &EncryptionKey<E>,
            gens: &EncryptionGens<E>,
        ) -> crate::Result<()> {
            Encryption::verify_ciphertext_commitment(
                &self.X_r,
                &self.enc_chunks,
                &self.commitment,
                ek,
                gens,
            )
        }

        /// Same as `Self::verify_commitment_given_prepared` but takes prepared parameters for faster verification.
        pub fn verify_commitment_given_prepared(
            &self,
            ek: &PreparedEncryptionKey<E>,
            gens: &PreparedEncryptionGens<E>,
        ) -> crate::Result<()> {
            Encryption::verify_ciphertext_commitment_given_prepared(
                &self.X_r,
                &self.enc_chunks,
                &self.commitment,
                ek,
                gens,
            )
        }

        /// Verify that the decrypted message corresponds to original plaintext in the ciphertext
        pub fn verify_decryption(
            &self,
            message: &E::Fr,
            nu: &E::G1Affine,
            chunk_bit_size: u8,
            dk: &DecryptionKey<E>,
            g_i: &[E::G1Affine],
            gens: &EncryptionGens<E>,
        ) -> crate::Result<()> {
            let decomposed = utils::decompose(message, chunk_bit_size)?;
            Encryption::verify_decryption(
                &decomposed,
                &self.X_r,
                &self.enc_chunks,
                nu,
                dk,
                g_i,
                gens,
            )
        }

        /// Same as `Self::verify_decryption` but uses prepared parameters
        pub fn verify_decryption_given_prepared(
            &self,
            message: &E::Fr,
            nu: &E::G1Affine,
            chunk_bit_size: u8,
            dk: &PreparedDecryptionKey<E>,
            g_i: &[E::G1Affine],
            gens: &PreparedEncryptionGens<E>,
        ) -> crate::Result<()> {
            let decomposed = utils::decompose(message, chunk_bit_size)?;
            Encryption::verify_decryption_given_prepared(
                &decomposed,
                &self.X_r,
                &self.enc_chunks,
                nu,
                dk,
                g_i,
                gens,
            )
        }
    };
}

pub struct Encryption<E: PairingEngine>(PhantomData<E>);

impl<E: PairingEngine> Encryption<E> {
    /// Encrypt a message `m` in exponent-Elgamal after breaking it into chunks of `chunk_bit_size` bits.
    /// Returns the ciphertext, commitment and randomness created for encryption. This is "Enc" from algorithm
    /// 2 in the paper
    /// Ciphertext vector contains commitment `psi` as the last element
    pub fn encrypt<R: RngCore>(
        rng: &mut R,
        message: &E::Fr,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::Fr)> {
        let decomposed = utils::decompose(message, chunk_bit_size)?;
        let (mut ct, r) = Self::encrypt_decomposed_message(rng, decomposed, ek, g_i)?;
        Ok((
            Ciphertext {
                X_r: ct.remove(0),
                commitment: ct.remove(ct.len() - 1),
                enc_chunks: ct,
            },
            r,
        ))
    }

    /// Return the encryption and Groth16 proof
    pub fn encrypt_with_proof<R: RngCore>(
        rng: &mut R,
        message: &E::Fr,
        ek: &EncryptionKey<E>,
        snark_pk: &saver_groth16::ProvingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::Fr, ark_groth16::Proof<E>)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_pk.pk.vk);
        let (ct, r) = Encryption::encrypt(rng, message, &ek, g_i, chunk_bit_size)?;
        let decomposed_message = utils::decompose(message, chunk_bit_size)?
            .into_iter()
            .map(|m| E::Fr::from(m as u64))
            .collect::<Vec<_>>();
        let circuit =
            BitsizeCheckCircuit::new(chunk_bit_size, None, Some(decomposed_message.clone()), true);
        let proof = saver_groth16::create_proof(circuit, &r, snark_pk, &ek, rng).unwrap();
        Ok((ct, r, proof))
    }

    /// Same as `Self::encrypt` but takes the SNARK verification key instead of the generators used for Elgamal encryption
    pub fn encrypt_given_snark_vk<R: RngCore>(
        rng: &mut R,
        message: &E::Fr,
        ek: &EncryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::Fr)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        Self::encrypt(rng, message, ek, g_i, chunk_bit_size)
    }

    /// Same as `Self::encrypt` but outputs sum `r*X_1 + r*X_2 + .. + r*X_n` as well
    // XXX: Is this secure?
    pub fn encrypt_alt<R: RngCore>(
        rng: &mut R,
        message: &E::Fr,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(CiphertextAlt<E>, E::Fr)> {
        let decomposed = utils::decompose(message, chunk_bit_size)?;
        let (mut ct, r) = Self::encrypt_decomposed_message(rng, decomposed, ek, g_i)?;
        let x_r_sum =
            ek.X.iter()
                .fold(E::G1Affine::zero(), |a, &b| a.add(b))
                .mul(r);
        Ok((
            CiphertextAlt {
                X_r: ct.remove(0),
                commitment: ct.remove(ct.len() - 1),
                enc_chunks: ct,
                X_r_sum: x_r_sum.into_affine(),
            },
            r,
        ))
    }

    /// Same as `Self::encrypt_alt` but takes the SNARK verification key instead of the generators used for Elgamal encryption
    pub fn encrypt_alt_given_snark_vk<R: RngCore>(
        rng: &mut R,
        message: &E::Fr,
        ek: &EncryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(CiphertextAlt<E>, E::Fr)> {
        let g_i = saver_legogroth16::get_gs_for_encryption(&snark_vk);
        Self::encrypt_alt(rng, message, ek, g_i, chunk_bit_size)
    }

    /// Decrypt the given ciphertext and return the message and a "commitment" to randomness to help in
    /// verifying the decryption without knowledge of secret key. This is "Dec" from algorithm 2 in the paper
    pub fn decrypt(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let (chunks, nu) = Self::decrypt_to_chunks(c_0, c, sk, dk, g_i, chunk_bit_size)?;
        Ok((utils::compose(&chunks, chunk_bit_size)?, nu))
    }

    /// Same as `Self::decrypt` but expects the prepared decryption key for faster decryption
    pub fn decrypt_given_prepared(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let (chunks, nu) =
            Self::decrypt_to_chunks_given_prepared(c_0, c, sk, dk, g_i, chunk_bit_size)?;
        Ok((utils::compose(&chunks, chunk_bit_size)?, nu))
    }

    /// Same as `Self::decrypt_given_prepared` but expects pairing powers (see `PreparedDecryptionKey::pairing_powers`)
    /// that can be precomputed for even faster decryption
    pub fn decrypt_given_prepared_and_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
        pairing_powers: &[Vec<E::Fqk>],
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let (chunks, nu) = Self::decrypt_to_chunks_given_pairing_powers(
            c_0,
            c,
            sk,
            dk,
            g_i,
            chunk_bit_size,
            pairing_powers,
        )?;
        Ok((utils::compose(&chunks, chunk_bit_size)?, nu))
    }

    /// Same as `Self::decrypt` but takes Groth16's verification key instead of the generators used for Elgamal encryption
    pub fn decrypt_given_groth16_vk(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        Self::decrypt(c_0, c, sk, dk, g_i, chunk_bit_size)
    }

    /// Same as `Self::decrypt` but takes Groth16's verification key and prepared decryption key
    pub fn decrypt_given_groth16_vk_and_prepared(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        Self::decrypt_given_prepared(c_0, c, sk, dk, g_i, chunk_bit_size)
    }

    /// Same as `Self::decrypt` but takes Groth16's verification key, prepared decryption key and the
    /// precomputed pairing powers
    pub fn decrypt_given_groth16_vk_and_prepared_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
        pairing_powers: &[Vec<E::Fqk>],
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        Self::decrypt_given_prepared_and_pairing_powers(
            c_0,
            c,
            sk,
            dk,
            g_i,
            chunk_bit_size,
            pairing_powers,
        )
    }

    /// Same as `Self::decrypt` but takes LegoGroth16's verification key instead of the generators used for Elgamal encryption
    pub fn decrypt_given_legogroth16_vk(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_legogroth16::get_gs_for_encryption(&snark_vk);
        Self::decrypt(c_0, c, sk, dk, g_i, chunk_bit_size)
    }

    /// Verify that commitment created during encryption opens to the message chunk
    /// Check `e(c_0, Z_0) * e(c_1, Z_1) * ... * e(c_n, Z_n)` mentioned in "Verify_Enc" in algorithm 2
    pub fn verify_ciphertext_commitment(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        commitment: &E::G1Affine,
        ek: &EncryptionKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        Self::verify_ciphertext_commitment_given_prepared(
            c_0,
            c,
            commitment,
            &ek.prepared(),
            &gens.prepared(),
        )
    }

    /// Same as `Self::verify_ciphertext_commitment` but takes prepared encryption key and prepared
    /// generators for faster verification
    pub fn verify_ciphertext_commitment_given_prepared(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        commitment: &E::G1Affine,
        ek: &PreparedEncryptionKey<E>,
        gens: &PreparedEncryptionGens<E>,
    ) -> crate::Result<()> {
        if c.len() != ek.supported_chunks_count()? as usize {
            return Err(SaverError::IncompatibleEncryptionKey(
                c.len(),
                ek.supported_chunks_count()? as usize,
            ));
        }
        let mut product = vec![];
        product.push(((*c_0).into(), ek.Z[0].clone()));
        for i in 1..ek.Z.len() {
            product.push((c[i - 1].into(), ek.Z[i].clone()));
        }
        product.push((commitment.neg().into(), gens.H.clone()));
        if E::product_of_pairings(&product).is_one() {
            Ok(())
        } else {
            return Err(SaverError::InvalidCommitment);
        }
    }

    /// Verify that ciphertext can be correctly decrypted to the given message chunks. This is "Verify_Dec" from algorithm 2 in the paper.
    pub fn verify_decryption(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        Self::verify_decryption_given_prepared(
            messages,
            c_0,
            c,
            nu,
            &dk.prepared(),
            g_i,
            &gens.prepared(),
        )
    }

    /// Same as `Self::verify_decryption` but takes prepared decryption key and prepared
    /// generators for faster verification
    pub fn verify_decryption_given_prepared(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        gens: &PreparedEncryptionGens<E>,
    ) -> crate::Result<()> {
        if messages.len() != dk.supported_chunks_count()? as usize {
            return Err(SaverError::IncompatibleDecryptionKey(
                messages.len(),
                dk.supported_chunks_count()? as usize,
            ));
        }
        if messages.len() > g_i.len() {
            return Err(SaverError::VectorShorterThanExpected(
                messages.len(),
                g_i.len(),
            ));
        }

        let nu_prepared = E::G1Prepared::from(*nu);
        let minus_nu_prepared = E::G1Prepared::from(nu.neg());
        if !E::product_of_pairings(&[
            (minus_nu_prepared, gens.H.clone()),
            ((*c_0).into(), dk.V_0.clone()),
        ])
        .is_one()
        {
            return Err(SaverError::InvalidDecryption);
        }
        for i in 0..messages.len() {
            let g_i_m_i = g_i[i].mul(E::Fr::from(messages[i] as u64));
            // e(g_i * m_i, dk.V_2_i) * e(-c_i, dk.V_2_i) = e(g_i * m_i - c_i, dk.V_2_i)
            let g_i_m_i_c_i = g_i_m_i.add_mixed(&c[i].neg());
            if !E::product_of_pairings(&[
                (g_i_m_i_c_i.into_affine().into(), dk.V_2[i].clone()),
                (nu_prepared.clone(), dk.V_1[i].clone()),
            ])
            .is_one()
            {
                return Err(SaverError::InvalidDecryption);
            }
        }
        Ok(())
    }

    /// Same as `Self::verify_decryption` but takes Groth16's verification key instead of the generators used for Elgamal encryption
    pub fn verify_decryption_given_groth16_vk(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        Self::verify_decryption(messages, c_0, c, nu, dk, g_i, gens)
    }

    /// Same as `Self::verify_decryption` but takes LegoGroth16's verification key instead of the generators used for Elgamal encryption
    pub fn verify_decryption_given_legogroth16_vk(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        let g_i = saver_legogroth16::get_gs_for_encryption(&snark_vk);
        Self::verify_decryption(messages, c_0, c, nu, dk, g_i, gens)
    }

    /// Decrypt the ciphertext and return each chunk and "commitment" to the randomness
    pub fn decrypt_to_chunks(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        Self::decrypt_to_chunks_given_prepared(c_0, c, sk, &dk.prepared(), g_i, chunk_bit_size)
    }

    /// Same as `Self::decrypt_to_chunks` but takes prepared decryption key
    pub fn decrypt_to_chunks_given_prepared(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        Self::decrypt_to_chunks_given_prepared_and_pairing_powers(
            c_0,
            c,
            sk,
            dk,
            g_i,
            chunk_bit_size,
            None,
        )
    }

    /// Same as `Self::decrypt_to_chunks` but takes prepared decryption key and precomputed pairing
    /// powers
    pub fn decrypt_to_chunks_given_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
        pairing_powers: &[Vec<E::Fqk>],
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        Self::decrypt_to_chunks_given_prepared_and_pairing_powers(
            c_0,
            c,
            sk,
            dk,
            g_i,
            chunk_bit_size,
            Some(pairing_powers),
        )
    }

    /// Decrypt the ciphertext and return each chunk and "commitment" to the randomness
    pub fn decrypt_to_chunks_given_prepared_and_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
        pairing_powers: Option<&[Vec<E::Fqk>]>,
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        let n = c.len();
        if n != dk.supported_chunks_count()? as usize {
            return Err(SaverError::IncompatibleDecryptionKey(
                n,
                dk.supported_chunks_count()? as usize,
            ));
        }
        if n > g_i.len() {
            return Err(SaverError::VectorShorterThanExpected(n, g_i.len()));
        }
        // c_0 * -rho
        let c_0_rho = c_0.mul((-sk.0).into_repr());
        let c_0_rho_prepared = E::G1Prepared::from(c_0_rho.into_affine());
        let mut decrypted_chunks = vec![];
        let chunk_max_val: u32 = (1 << chunk_bit_size) - 1;
        let pairing_powers = if let Some(p) = pairing_powers { p } else { &[] };
        for i in 0..n {
            let p = E::product_of_pairings(&[
                (c[i].into(), dk.V_2[i].clone()),
                (c_0_rho_prepared.clone(), dk.V_1[i].clone()),
            ]);
            if p.is_one() {
                decrypted_chunks.push(0);
                continue;
            }

            if pairing_powers.len() == 0 {
                // Precomputed powers are not provided, compute the necessary pairings
                let g_i_v_i = E::product_of_pairings(core::iter::once(&(
                    E::G1Prepared::from(g_i[i]),
                    dk.V_2[i].clone(),
                )));
                decrypted_chunks.push(Self::solve_discrete_log(
                    chunk_max_val as CHUNK_TYPE,
                    g_i_v_i,
                    p,
                )?);
            } else {
                decrypted_chunks.push(Self::solve_discrete_log_using_pairing_powers(
                    i,
                    chunk_max_val as CHUNK_TYPE,
                    p,
                    pairing_powers,
                )?);
            }
        }
        Ok((decrypted_chunks, (-c_0_rho).into_affine()))
    }

    /// Encrypt once the message has been broken into chunks
    pub fn encrypt_decomposed_message<R: RngCore>(
        rng: &mut R,
        message_chunks: Vec<CHUNK_TYPE>,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
    ) -> crate::Result<(Vec<E::G1Affine>, E::Fr)> {
        if message_chunks.len() != ek.supported_chunks_count()? as usize {
            return Err(SaverError::IncompatibleEncryptionKey(
                message_chunks.len(),
                ek.supported_chunks_count()? as usize,
            ));
        }
        if message_chunks.len() > g_i.len() {
            return Err(SaverError::VectorShorterThanExpected(
                message_chunks.len(),
                g_i.len(),
            ));
        }
        let r = E::Fr::rand(rng);
        let r_repr = r.into_repr();
        let mut ct = vec![];
        ct.push(ek.X_0.mul(r_repr));
        let mut m = message_chunks
            .into_iter()
            .map(|m_i| <E::Fr as PrimeField>::BigInt::from(m_i as u64))
            .collect::<Vec<_>>();
        for i in 0..ek.X.len() {
            ct.push(ek.X[i].mul(r_repr).add(g_i[i].mul(m[i])));
        }

        // Commit to the message chunks with randomness `r`
        m.push(r.into_repr());
        let psi = VariableBaseMSM::multi_scalar_mul(&ek.commitment_key(), &m);

        ct.push(psi);
        Ok((batch_normalize_projective_into_affine(ct), r))
    }

    /// Does not use precomputation
    fn solve_discrete_log(
        chunk_max_val: CHUNK_TYPE,
        g_i_v_i: E::Fqk,
        p: E::Fqk,
    ) -> crate::Result<CHUNK_TYPE> {
        if p == g_i_v_i {
            return Ok(1);
        }
        let mut cur = g_i_v_i.clone();
        for j in 2..=chunk_max_val {
            cur = cur * g_i_v_i;
            if cur == p {
                return Ok(j);
            }
        }
        Err(SaverError::CouldNotFindDiscreteLog)
    }

    /// Relies on precomputation
    fn solve_discrete_log_using_pairing_powers(
        chunk_index: usize,
        chunk_max_val: CHUNK_TYPE,
        p: E::Fqk,
        pairing_powers: &[Vec<E::Fqk>],
    ) -> crate::Result<CHUNK_TYPE> {
        if pairing_powers.len() < chunk_index {
            return Err(SaverError::InvalidPairingPowers);
        }
        for j in 1..=chunk_max_val {
            let j = j as usize - 1;
            if pairing_powers[chunk_index].len() < j {
                return Err(SaverError::InvalidPairingPowers);
            }
            if pairing_powers[chunk_index][j] == p {
                return Ok(j as CHUNK_TYPE + 1);
            }
        }
        Err(SaverError::CouldNotFindDiscreteLog)
    }
}

impl<E: PairingEngine> Ciphertext<E> {
    impl_enc_funcs!();

    /// Verify ciphertext commitment and snark proof
    pub fn verify_commitment_and_proof(
        &self,
        proof: &ark_groth16::Proof<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        ek: &EncryptionKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        self.verify_commitment(ek, gens)?;
        if saver_groth16::verify_proof(&ark_groth16::prepare_verifying_key(&snark_vk), proof, self)?
        {
            Ok(())
        } else {
            Err(SaverError::InvalidProof)
        }
    }

    /// Same as `Self::verify_commitment_and_proof` but takes prepared encryption key and generators
    /// for faster verification
    pub fn verify_commitment_and_proof_given_prepared(
        &self,
        proof: &ark_groth16::Proof<E>,
        snark_vk: &ark_groth16::PreparedVerifyingKey<E>,
        ek: &PreparedEncryptionKey<E>,
        gens: &PreparedEncryptionGens<E>,
    ) -> crate::Result<()> {
        self.verify_commitment_given_prepared(ek, gens)?;
        if saver_groth16::verify_proof(snark_vk, proof, self)? {
            Ok(())
        } else {
            Err(SaverError::InvalidProof)
        }
    }

    pub fn decrypt_given_groth16_vk(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        self.decrypt(sk, dk, g_i, chunk_bit_size)
    }

    pub fn decrypt_given_groth16_vk_and_prepared_key(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        self.decrypt_given_prepared(sk, dk, g_i, chunk_bit_size)
    }

    pub fn decrypt_given_groth16_vk_and_prepared_key_and_pairing_powers(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &PreparedDecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
        pairing_powers: &[Vec<E::Fqk>],
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        self.decrypt_given_prepared_and_pairing_powers(sk, dk, g_i, chunk_bit_size, pairing_powers)
    }

    pub fn verify_decryption_given_groth16_vk(
        &self,
        message: &E::Fr,
        nu: &E::G1Affine,
        chunk_bit_size: u8,
        dk: &DecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        self.verify_decryption(message, nu, chunk_bit_size, dk, g_i, gens)
    }

    pub fn verify_decryption_given_groth16_vk_and_prepared(
        &self,
        message: &E::Fr,
        nu: &E::G1Affine,
        chunk_bit_size: u8,
        dk: &PreparedDecryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        gens: &PreparedEncryptionGens<E>,
    ) -> crate::Result<()> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
        self.verify_decryption_given_prepared(message, nu, chunk_bit_size, dk, g_i, gens)
    }
}

impl<E: PairingEngine> CiphertextAlt<E> {
    impl_enc_funcs!();

    pub fn decrypt_given_legogroth16_vk(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::Fr, E::G1Affine)> {
        Encryption::decrypt_given_legogroth16_vk(
            &self.X_r,
            &self.enc_chunks,
            sk,
            dk,
            snark_vk,
            chunk_bit_size,
        )
    }

    pub fn verify_decryption_given_legogroth16_vk(
        &self,
        message: &E::Fr,
        chunk_bit_size: u8,
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        gens: &EncryptionGens<E>,
    ) -> crate::Result<()> {
        let decomposed = utils::decompose(message, chunk_bit_size)?;
        Encryption::verify_decryption_given_legogroth16_vk(
            &decomposed,
            &self.X_r,
            &self.enc_chunks,
            nu,
            dk,
            snark_vk,
            gens,
        )
    }
}

// TODO: Add function to rerandomize

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::keygen::keygen;
    use crate::utils::{chunks_count, decompose};
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    pub fn enc_setup<R: RngCore>(
        chunk_bit_size: u8,
        rng: &mut R,
    ) -> (
        EncryptionGens<Bls12_381>,
        Vec<<Bls12_381 as PairingEngine>::G1Affine>,
        SecretKey<<Bls12_381 as PairingEngine>::Fr>,
        EncryptionKey<Bls12_381>,
        DecryptionKey<Bls12_381>,
    ) {
        let n = chunks_count::<Fr>(chunk_bit_size) as usize;
        let gens = EncryptionGens::<Bls12_381>::new_using_rng(rng);
        let g_i = (0..n)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let delta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let g_delta = gens.G.mul(delta.into_repr()).into_affine();
        let g_gamma = gens.G.mul(gamma.into_repr()).into_affine();
        let (sk, ek, dk) = keygen(rng, chunk_bit_size, &gens, &g_i, &g_delta, &g_gamma).unwrap();
        (gens, g_i, sk, ek, dk)
    }

    pub fn gen_messages<R: RngCore>(
        rng: &mut R,
        count: usize,
        chunk_bit_size: u8,
    ) -> Vec<CHUNK_TYPE> {
        (0..count)
            .map(|_| (u32::rand(rng) & ((1 << chunk_bit_size) - 1)) as CHUNK_TYPE)
            .collect()
    }

    #[test]
    fn encrypt_decrypt() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let n = chunks_count::<Fr>(chunk_bit_size) as usize;
            // Get random numbers that are of chunk_bit_size at most
            let m = gen_messages(&mut rng, n, chunk_bit_size);
            let (gens, g_i, sk, ek, dk) = enc_setup(chunk_bit_size, &mut rng);

            let prepared_gens = gens.prepared();
            let prepared_ek = ek.prepared();
            let prepared_dk = dk.prepared();

            let start = Instant::now();
            let (ct, _) =
                Encryption::encrypt_decomposed_message(&mut rng, m.clone(), &ek, &g_i).unwrap();
            println!(
                "Time taken to encrypt {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            assert_eq!(ct.len(), m.len() + 2);
            let start = Instant::now();
            Encryption::verify_ciphertext_commitment(
                &ct[0],
                &ct[1..m.len() + 1],
                &ct[m.len() + 1],
                &ek,
                &gens,
            )
            .unwrap();
            println!(
                "Time taken to verify commitment of {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            Encryption::verify_ciphertext_commitment_given_prepared(
                &ct[0],
                &ct[1..m.len() + 1],
                &ct[m.len() + 1],
                &prepared_ek,
                &prepared_gens,
            )
            .unwrap();
            println!(
                "Time taken to verify commitment of {}-bit chunks using prepared parameters {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            let (m_, _) = Encryption::decrypt_to_chunks(
                &ct[0],
                &ct[1..m.len() + 1],
                &sk,
                &dk,
                &g_i,
                chunk_bit_size,
            )
            .unwrap();
            println!(
                "Time taken to decrypt {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );
            assert_eq!(m_, m);

            let start = Instant::now();
            let (m_, _) = Encryption::decrypt_to_chunks_given_prepared(
                &ct[0],
                &ct[1..m.len() + 1],
                &sk,
                &prepared_dk,
                &g_i,
                chunk_bit_size,
            )
            .unwrap();
            println!(
                "Time taken to decrypt {}-bit chunks using prepared parameters {:?}",
                chunk_bit_size,
                start.elapsed()
            );
            assert_eq!(m_, m);

            let pairing_powers = prepared_dk.pairing_powers(chunk_bit_size, &g_i).unwrap();
            let start = Instant::now();
            let (m_, nu) = Encryption::decrypt_to_chunks_given_prepared_and_pairing_powers(
                &ct[0],
                &ct[1..m.len() + 1],
                &sk,
                &prepared_dk,
                &g_i,
                chunk_bit_size,
                Some(&pairing_powers),
            )
            .unwrap();
            println!(
                "Time taken to decrypt {}-bit chunks using prepared parameters and pairing powers {:?}",
                chunk_bit_size,
                start.elapsed()
            );
            assert_eq!(m_, m);

            let start = Instant::now();
            Encryption::verify_decryption(&m_, &ct[0], &ct[1..m.len() + 1], &nu, &dk, &g_i, &gens)
                .unwrap();
            println!(
                "Time taken to verify decryption of {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            Encryption::verify_decryption_given_prepared(
                &m_,
                &ct[0],
                &ct[1..m.len() + 1],
                &nu,
                &prepared_dk,
                &g_i,
                &prepared_gens,
            )
            .unwrap();
            println!(
                "Time taken to verify decryption of {}-bit chunks using prepared parameters {:?}",
                chunk_bit_size,
                start.elapsed()
            );
        }

        check(4);
        check(8);
        check(16);
    }

    #[test]
    fn encrypt_decrypt_timing() {
        fn check(chunk_bit_size: u8, count: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (gens, g_i, sk, ek, dk) = enc_setup(chunk_bit_size, &mut rng);
            let prepared_ek = ek.prepared();
            let prepared_dk = dk.prepared();
            let prepared_gens = gens.prepared();
            let pairing_powers = prepared_dk.pairing_powers(chunk_bit_size, &g_i).unwrap();

            let mut total_enc = Duration::default();
            let mut total_ver_com = Duration::default();
            let mut total_ver_com_prep = Duration::default();
            let mut total_dec = Duration::default();
            let mut total_dec_prep = Duration::default();
            let mut total_dec_prep_powers = Duration::default();
            let mut total_ver_dec = Duration::default();
            let mut total_ver_dec_prep = Duration::default();

            for _ in 0..count {
                let m = Fr::rand(&mut rng);

                let start = Instant::now();
                let (ct, _) = Encryption::encrypt(&mut rng, &m, &ek, &g_i, chunk_bit_size).unwrap();
                total_enc += start.elapsed();

                let start = Instant::now();
                ct.verify_commitment(&ek, &gens).unwrap();
                total_ver_com += start.elapsed();

                let start = Instant::now();
                ct.verify_commitment_given_prepared(&prepared_ek, &prepared_gens)
                    .unwrap();
                total_ver_com_prep += start.elapsed();

                let (chunks, nu) = Encryption::decrypt_to_chunks(
                    &ct.X_r,
                    &ct.enc_chunks,
                    &sk,
                    &dk,
                    &g_i,
                    chunk_bit_size,
                )
                .unwrap();

                let decomposed = decompose(&m, chunk_bit_size).unwrap();
                assert_eq!(decomposed, chunks);

                let start = Instant::now();
                let (m_, nu_) = ct.decrypt(&sk, &dk, &g_i, chunk_bit_size).unwrap();
                total_dec += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                let (m_, nu_) = ct
                    .decrypt_given_prepared(&sk, &prepared_dk, &g_i, chunk_bit_size)
                    .unwrap();
                total_dec_prep += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                let (m_, nu_) = ct
                    .decrypt_given_prepared_and_pairing_powers(
                        &sk,
                        &prepared_dk,
                        &g_i,
                        chunk_bit_size,
                        &pairing_powers,
                    )
                    .unwrap();
                total_dec_prep_powers += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                ct.verify_decryption(&m, &nu, chunk_bit_size, &dk, &g_i, &gens)
                    .unwrap();
                total_ver_dec += start.elapsed();

                let start = Instant::now();
                ct.verify_decryption_given_prepared(
                    &m,
                    &nu,
                    chunk_bit_size,
                    &prepared_dk,
                    &g_i,
                    &prepared_gens,
                )
                .unwrap();
                total_ver_dec_prep += start.elapsed();
            }

            println!(
                "Time taken for {} iterations and {} chunk size:",
                count, chunk_bit_size
            );
            println!("Encryption {:?}", total_enc);
            println!("Verifying commitment {:?}", total_ver_com);
            println!(
                "Verifying commitment using prepared {:?}",
                total_ver_com_prep
            );
            println!("Decryption {:?}", total_dec);
            println!("Decryption using prepared {:?}", total_dec_prep);
            println!(
                "Decryption using prepared and pairing powers {:?}",
                total_dec_prep_powers
            );
            println!("Verifying decryption {:?}", total_ver_dec);
            println!(
                "Verifying decryption using prepared {:?}",
                total_ver_dec_prep
            );
        }
        check(4, 10);
        check(8, 10);
        check(16, 10);
    }
}
