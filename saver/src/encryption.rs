//! Encryption, decryption, verifying commitment and verifying decryption

use crate::{
    circuit::BitsizeCheckCircuit,
    error::SaverError,
    keygen::{EncryptionKey, PreparedDecryptionKey, PreparedEncryptionKey, SecretKey},
    saver_groth16, saver_legogroth16,
    setup::PreparedEncryptionGens,
    utils,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter,
    marker::PhantomData,
    ops::{Add, Mul, Neg, Sub},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::utils::CHUNK_TYPE;
use dock_crypto_utils::{ff::non_zero_random, serde_utils::*};

use dock_crypto_utils::solve_discrete_log::solve_discrete_log_bsgs_alt;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Ciphertext used with Groth16
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Ciphertext<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub X_r: E::G1Affine,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub enc_chunks: Vec<E::G1Affine>,
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: E::G1Affine,
}

/// Ciphertext used with LegoGroth16 and the slightly modified SAVER protocol. See `saver_legogroth16::protocol_2` for more
/// details.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CiphertextAlt<E: Pairing> {
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
            sk: &SecretKey<E::ScalarField>,
            dk: impl Into<PreparedDecryptionKey<E>>,
            g_i: &[E::G1Affine],
            chunk_bit_size: u8,
        ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
            Encryption::decrypt(&self.X_r, &self.enc_chunks, sk, dk, g_i, chunk_bit_size)
        }

        /// Same as `Self::decrypt` but takes pairing powers (see `PreparedDecryptionKey::pairing_powers`)
        /// that can be precomputed for faster decryption
        pub fn decrypt_given_pairing_powers(
            &self,
            sk: &SecretKey<E::ScalarField>,
            dk: impl Into<PreparedDecryptionKey<E>>,
            g_i: &[E::G1Affine],
            chunk_bit_size: u8,
            pairing_powers: &[Vec<PairingOutput<E>>],
        ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
            Encryption::decrypt_given_pairing_powers(
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
            ek: impl Into<PreparedEncryptionKey<E>>,
            gens: impl Into<PreparedEncryptionGens<E>>,
        ) -> crate::Result<()> {
            Encryption::verify_ciphertext_commitment(
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
            message: &E::ScalarField,
            nu: &E::G1Affine,
            chunk_bit_size: u8,
            dk: impl Into<PreparedDecryptionKey<E>>,
            g_i: &[E::G1Affine],
            gens: impl Into<PreparedEncryptionGens<E>>,
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
    };
}

pub struct Encryption<E: Pairing>(PhantomData<E>);

impl<E: Pairing> Encryption<E> {
    /// Encrypt a message `m` in exponent-Elgamal after breaking it into chunks of `chunk_bit_size` bits.
    /// Returns the ciphertext, commitment and randomness created for encryption. This is "Enc" from algorithm
    /// 2 in the paper
    /// Ciphertext vector contains commitment `psi` as the last element
    pub fn encrypt<R: RngCore>(
        rng: &mut R,
        message: &E::ScalarField,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::ScalarField)> {
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
        message: &E::ScalarField,
        ek: &EncryptionKey<E>,
        snark_pk: &saver_groth16::ProvingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::ScalarField, ark_groth16::Proof<E>)> {
        let g_i = saver_groth16::get_gs_for_encryption(&snark_pk.pk.vk);
        let (ct, r) = Encryption::encrypt(rng, message, ek, g_i, chunk_bit_size)?;
        let decomposed_message = utils::decompose(message, chunk_bit_size)?
            .into_iter()
            .map(|m| E::ScalarField::from(m as u64))
            .collect::<Vec<_>>();
        let circuit =
            BitsizeCheckCircuit::new(chunk_bit_size, None, Some(decomposed_message), true);
        let proof = saver_groth16::create_proof(circuit, &r, snark_pk, ek, rng)?;
        Ok((ct, r, proof))
    }

    pub fn rerandomize_ciphertext_and_proof<R: RngCore>(
        ciphertext: Ciphertext<E>,
        proof: ark_groth16::Proof<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        ek: &EncryptionKey<E>,
        rng: &mut R,
    ) -> crate::Result<(Ciphertext<E>, E::ScalarField, ark_groth16::Proof<E>)> {
        let r_prime = non_zero_random::<E::ScalarField, R>(rng);
        let r_prime_repr = r_prime.into_bigint();
        let xr = ek
            .X_0
            .mul_bigint(r_prime_repr)
            .add(&ciphertext.X_r)
            .into_affine();
        let enc = cfg_into_iter!(ciphertext.enc_chunks)
            .zip(cfg_iter!(ek.X))
            .map(|(c, x)| x.mul_bigint(r_prime_repr).add(&c))
            .collect::<Vec<_>>();
        let comm = ek
            .P_1
            .mul_bigint(r_prime_repr)
            .add(&ciphertext.commitment)
            .into_affine();
        let proof = saver_groth16::randomize_proof(proof, &r_prime, snark_vk, ek, rng)?;
        let ct = Ciphertext {
            X_r: xr,
            commitment: comm,
            enc_chunks: E::G1::normalize_batch(&enc),
        };
        Ok((ct, r_prime, proof))
    }

    /// Same as `Self::encrypt` but takes the SNARK verification key instead of the generators used for Elgamal encryption
    pub fn encrypt_given_snark_vk<R: RngCore>(
        rng: &mut R,
        message: &E::ScalarField,
        ek: &EncryptionKey<E>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(Ciphertext<E>, E::ScalarField)> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        Self::encrypt(rng, message, ek, g_i, chunk_bit_size)
    }

    /// Same as `Self::encrypt` but outputs sum `r*X_1 + r*X_2 + .. + r*X_n` as well
    // XXX: Is this secure?
    pub fn encrypt_alt<R: RngCore>(
        rng: &mut R,
        message: &E::ScalarField,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(CiphertextAlt<E>, E::ScalarField)> {
        let decomposed = utils::decompose(message, chunk_bit_size)?;
        let (mut ct, r) = Self::encrypt_decomposed_message(rng, decomposed, ek, g_i)?;
        let x_r_sum = ek.X.iter().fold(E::G1::zero(), |a, &b| a.add(b)).mul(r);
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
        message: &E::ScalarField,
        ek: &EncryptionKey<E>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(CiphertextAlt<E>, E::ScalarField)> {
        let g_i = saver_legogroth16::get_gs_for_encryption(snark_vk);
        Self::encrypt_alt(rng, message, ek, g_i, chunk_bit_size)
    }

    /// Decrypt the given ciphertext and return the message and a "commitment" to randomness to help in
    /// verifying the decryption without knowledge of secret key. This is "Dec" from algorithm 2 in the paper
    pub fn decrypt(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let (chunks, nu) = Self::decrypt_to_chunks(c_0, c, sk, dk, g_i, chunk_bit_size)?;
        Ok((utils::compose(&chunks, chunk_bit_size)?, nu))
    }

    /// Same as `Self::decrypt` but expects pairing powers (see `PreparedDecryptionKey::pairing_powers`)
    /// that can be precomputed for even faster decryption
    pub fn decrypt_given_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
        pairing_powers: &[Vec<PairingOutput<E>>],
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let (chunks, nu) = Self::decrypt_to_chunks_given_pairing_powers(
            c_0,
            c,
            sk,
            dk,
            g_i,
            chunk_bit_size,
            Some(pairing_powers),
        )?;
        Ok((utils::compose(&chunks, chunk_bit_size)?, nu))
    }

    /// Same as `Self::decrypt` but takes Groth16's verification key instead of the generators used for Elgamal encryption
    pub fn decrypt_given_groth16_vk(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        Self::decrypt(c_0, c, sk, dk, g_i, chunk_bit_size)
    }

    /// Same as `Self::decrypt` but takes Groth16's verification key and the
    /// precomputed pairing powers
    pub fn decrypt_given_groth16_vk_and_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
        pairing_powers: &[Vec<PairingOutput<E>>],
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        Self::decrypt_given_pairing_powers(c_0, c, sk, dk, g_i, chunk_bit_size, pairing_powers)
    }

    /// Same as `Self::decrypt` but takes LegoGroth16's verification key instead of the generators used for Elgamal encryption
    pub fn decrypt_given_legogroth16_vk(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let g_i = saver_legogroth16::get_gs_for_encryption(snark_vk);
        Self::decrypt(c_0, c, sk, dk, g_i, chunk_bit_size)
    }

    /// Verify that commitment created during encryption opens to the message chunk
    /// Check `e(c_0, Z_0) * e(c_1, Z_1) * ... * e(c_n, Z_n)` mentioned in "Verify_Enc" in algorithm 2
    pub fn verify_ciphertext_commitment(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        commitment: &E::G1Affine,
        ek: impl Into<PreparedEncryptionKey<E>>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        let ek = ek.into();
        let gens = gens.into();
        let expected_count = ek.supported_chunks_count()? as usize;
        if c.len() != expected_count {
            return Err(SaverError::IncompatibleEncryptionKey(
                c.len(),
                expected_count,
            ));
        }

        let (a, b) = (
            Self::get_g1_for_ciphertext_commitment_pairing_checks(c_0, c, commitment),
            Self::get_g2_for_ciphertext_commitment_pairing_checks(&ek, &gens),
        );
        if E::multi_pairing(a, b).is_zero() {
            Ok(())
        } else {
            Err(SaverError::InvalidCommitment)
        }
    }

    pub fn verify_commitments_in_batch(
        ciphertexts: &[Ciphertext<E>],
        r_powers: &[E::ScalarField],
        ek: impl Into<PreparedEncryptionKey<E>>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        assert_eq!(r_powers.len(), ciphertexts.len());
        let ek = ek.into();
        let gens = gens.into();
        let expected_count = ek.supported_chunks_count()? as usize;
        for c in ciphertexts {
            if c.enc_chunks.len() != expected_count {
                return Err(SaverError::IncompatibleEncryptionKey(
                    c.enc_chunks.len(),
                    expected_count,
                ));
            }
        }

        let a =
            Self::get_g1_for_ciphertext_commitments_in_batch_pairing_checks(ciphertexts, r_powers);
        let b = Self::get_g2_for_ciphertext_commitment_pairing_checks(&ek, &gens);
        if E::multi_pairing(a, b).is_zero() {
            Ok(())
        } else {
            Err(SaverError::InvalidCommitment)
        }
    }

    /// Verify that ciphertext can be correctly decrypted to the given message chunks. This is "Verify_Dec" from algorithm 2 in the paper.
    pub fn verify_decryption(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: impl Into<PreparedDecryptionKey<E>>,
        g_i: &[E::G1Affine],
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        let dk = dk.into();
        let gens = gens.into();
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
        let minus_nu_prepared = E::G1Prepared::from(nu.into_group().neg());
        if !E::multi_pairing([minus_nu_prepared, (*c_0).into()], [gens.H, dk.V_0.clone()]).is_zero()
        {
            return Err(SaverError::InvalidDecryption);
        }
        for i in 0..messages.len() {
            let g_i_m_i = g_i[i].mul(E::ScalarField::from(messages[i] as u64));
            // e(g_i * m_i, dk.V_2_i) * e(-c_i, dk.V_2_i) = e(g_i * m_i - c_i, dk.V_2_i)
            let g_i_m_i_c_i = g_i_m_i.sub(&c[i]);
            if !E::multi_pairing(
                [g_i_m_i_c_i.into_affine().into(), nu_prepared.clone()],
                [dk.V_2[i].clone(), dk.V_1[i].clone()],
            )
            .is_zero()
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
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        Self::verify_decryption(messages, c_0, c, nu, dk, g_i, gens)
    }

    /// Same as `Self::verify_decryption` but takes LegoGroth16's verification key instead of the generators used for Elgamal encryption
    pub fn verify_decryption_given_legogroth16_vk(
        messages: &[CHUNK_TYPE],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        let g_i = saver_legogroth16::get_gs_for_encryption(snark_vk);
        Self::verify_decryption(messages, c_0, c, nu, dk, g_i, gens)
    }

    /// Decrypt the ciphertext and return each chunk and "commitment" to the randomness
    pub fn decrypt_to_chunks(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        Self::decrypt_to_chunks_given_pairing_powers(c_0, c, sk, dk, g_i, chunk_bit_size, None)
    }

    /// Decrypt the ciphertext and return each chunk and "commitment" to the randomness.
    /// Same as `Self::decrypt_to_chunks` but takes decryption key and precomputed pairing
    /// powers
    pub fn decrypt_to_chunks_given_pairing_powers(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
        pairing_powers: Option<&[Vec<PairingOutput<E>>]>,
    ) -> crate::Result<(Vec<CHUNK_TYPE>, E::G1Affine)> {
        let dk = dk.into();
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
        let c_0_rho = c_0.mul_bigint((-sk.0).into_bigint());
        let c_0_rho_prepared = E::G1Prepared::from(c_0_rho.into_affine());
        let mut decrypted_chunks = vec![];
        // chunk_max_val = 2^chunk_bit_size - 1
        let chunk_max_val: u32 = (1 << chunk_bit_size) - 1;
        let pairing_powers = if let Some(p) = pairing_powers { p } else { &[] };
        for i in 0..n {
            let p = E::multi_pairing(
                [c[i].into(), c_0_rho_prepared.clone()],
                [dk.V_2[i].clone(), dk.V_1[i].clone()],
            );
            if p.is_zero() {
                decrypted_chunks.push(0);
                continue;
            }

            if pairing_powers.is_empty() {
                // Precomputed powers are not provided, compute the necessary pairings
                let g_i_v_i = E::pairing(E::G1Prepared::from(g_i[i]), dk.V_2[i].clone());
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
    ) -> crate::Result<(Vec<E::G1Affine>, E::ScalarField)> {
        let expected_count = ek.supported_chunks_count()? as usize;
        if message_chunks.len() != expected_count {
            return Err(SaverError::IncompatibleEncryptionKey(
                message_chunks.len(),
                expected_count,
            ));
        }
        if message_chunks.len() > g_i.len() {
            return Err(SaverError::VectorShorterThanExpected(
                message_chunks.len(),
                g_i.len(),
            ));
        }
        let r = E::ScalarField::rand(rng);
        let r_repr = r.into_bigint();
        let mut ct = vec![];
        ct.push(ek.X_0.mul_bigint(r_repr));
        let mut m = cfg_into_iter!(message_chunks)
            .map(|m_i| <E::ScalarField as PrimeField>::BigInt::from(m_i as u64))
            .collect::<Vec<_>>();
        for i in 0..ek.X.len() {
            ct.push(ek.X[i].mul_bigint(r_repr).add(g_i[i].mul_bigint(m[i])));
        }

        // Commit to the message chunks with randomness `r`
        m.push(r.into_bigint());
        let psi = E::G1::msm_bigint(&ek.commitment_key(), &m);

        ct.push(psi);
        Ok((E::G1::normalize_batch(&ct), r))
    }

    /// Does not use precomputation
    fn solve_discrete_log(
        chunk_max_val: CHUNK_TYPE,
        g_i_v_i: PairingOutput<E>,
        p: PairingOutput<E>,
    ) -> crate::Result<CHUNK_TYPE> {
        solve_discrete_log_bsgs_alt(chunk_max_val, g_i_v_i, p)
            .ok_or(SaverError::CouldNotFindDiscreteLog)
    }

    /// Relies on precomputation
    fn solve_discrete_log_using_pairing_powers(
        chunk_index: usize,
        chunk_max_val: CHUNK_TYPE,
        p: PairingOutput<E>,
        pairing_powers: &[Vec<PairingOutput<E>>],
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

    pub fn get_g1_for_ciphertext_commitment_pairing_checks(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        commitment: &E::G1Affine,
    ) -> Vec<E::G1Affine> {
        let mut a = Vec::with_capacity(c.len() + 2);
        a.push(*c_0);
        a.extend_from_slice(c);
        a.push(commitment.into_group().neg().into_affine());
        a
    }

    pub fn get_g1_for_ciphertext_commitments_in_batch_pairing_checks(
        ciphertexts: &[Ciphertext<E>],
        r_powers: &[E::ScalarField],
    ) -> Vec<E::G1Affine> {
        let mut a = Vec::with_capacity(ciphertexts[0].enc_chunks.len() + 2);
        let num = r_powers.len();
        let r_powers_repr = cfg_iter!(r_powers)
            .map(|r| r.into_bigint())
            .collect::<Vec<_>>();

        let mut bases = vec![];
        for i in 0..num {
            bases.push(ciphertexts[i].X_r);
        }
        a.push(E::G1::msm_bigint(&bases, &r_powers_repr));

        for j in 0..ciphertexts[0].enc_chunks.len() {
            let mut bases = vec![];
            for i in 0..num {
                bases.push(ciphertexts[i].enc_chunks[j]);
            }
            a.push(E::G1::msm_bigint(&bases, &r_powers_repr));
        }

        let mut bases = vec![];
        for i in 0..num {
            bases.push(ciphertexts[i].commitment);
        }
        a.push(E::G1::msm_bigint(&bases, &r_powers_repr).neg());
        E::G1::normalize_batch(&a)
    }

    pub fn get_g2_for_ciphertext_commitment_pairing_checks(
        ek: &PreparedEncryptionKey<E>,
        gens: &PreparedEncryptionGens<E>,
    ) -> Vec<E::G2Prepared> {
        let mut b = Vec::with_capacity(ek.Z.len() + 1);
        b.push(ek.Z[0].clone());
        for i in 1..ek.Z.len() {
            b.push(ek.Z[i].clone());
        }
        b.push(gens.H.clone());
        b
    }
}

impl<E: Pairing> Ciphertext<E> {
    impl_enc_funcs!();

    /// Verify ciphertext commitment and snark proof
    pub fn verify_commitment_and_proof(
        &self,
        proof: &ark_groth16::Proof<E>,
        snark_vk: &ark_groth16::PreparedVerifyingKey<E>,
        ek: impl Into<PreparedEncryptionKey<E>>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        self.verify_commitment(ek, gens)?;
        saver_groth16::verify_proof(snark_vk, proof, self)
    }

    pub fn decrypt_given_groth16_vk(
        &self,
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        self.decrypt(sk, dk, g_i, chunk_bit_size)
    }

    pub fn decrypt_given_groth16_vk_and_pairing_powers(
        &self,
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        chunk_bit_size: u8,
        pairing_powers: &[Vec<PairingOutput<E>>],
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        self.decrypt_given_pairing_powers(sk, dk, g_i, chunk_bit_size, pairing_powers)
    }

    pub fn verify_decryption_given_groth16_vk(
        &self,
        message: &E::ScalarField,
        nu: &E::G1Affine,
        chunk_bit_size: u8,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &ark_groth16::VerifyingKey<E>,
        gens: impl Into<PreparedEncryptionGens<E>>,
    ) -> crate::Result<()> {
        let g_i = saver_groth16::get_gs_for_encryption(snark_vk);
        self.verify_decryption(message, nu, chunk_bit_size, dk, g_i, gens)
    }
}

impl<E: Pairing> CiphertextAlt<E> {
    impl_enc_funcs!();

    pub fn decrypt_given_legogroth16_vk(
        &self,
        sk: &SecretKey<E::ScalarField>,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        chunk_bit_size: u8,
    ) -> crate::Result<(E::ScalarField, E::G1Affine)> {
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
        message: &E::ScalarField,
        chunk_bit_size: u8,
        nu: &E::G1Affine,
        dk: impl Into<PreparedDecryptionKey<E>>,
        snark_vk: &legogroth16::VerifyingKey<E>,
        gens: impl Into<PreparedEncryptionGens<E>>,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::{
        keygen::{keygen, DecryptionKey},
        setup::EncryptionGens,
        utils::{chunks_count, decompose},
    };
    use ark_bls12_381::Bls12_381;
    use ark_ff::One;
    use ark_std::rand::{prelude::StdRng, SeedableRng};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    pub fn enc_setup<R: RngCore>(
        chunk_bit_size: u8,
        rng: &mut R,
    ) -> (
        EncryptionGens<Bls12_381>,
        Vec<<Bls12_381 as Pairing>::G1Affine>,
        SecretKey<<Bls12_381 as Pairing>::ScalarField>,
        EncryptionKey<Bls12_381>,
        DecryptionKey<Bls12_381>,
    ) {
        let n = chunks_count::<Fr>(chunk_bit_size) as usize;
        let gens = EncryptionGens::<Bls12_381>::new_using_rng(rng);
        let g_i = (0..n)
            .map(|_| <Bls12_381 as Pairing>::G1Affine::rand(rng))
            .collect::<Vec<_>>();
        let delta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let g_delta = gens.G.mul_bigint(delta.into_bigint()).into_affine();
        let g_gamma = gens.G.mul_bigint(gamma.into_bigint()).into_affine();
        let (sk, ek, dk) = keygen(rng, chunk_bit_size, &gens, &g_i, &g_delta, &g_gamma).unwrap();
        (gens, g_i, sk, ek, dk)
    }

    pub fn gen_messages<R: RngCore>(
        rng: &mut R,
        count: u32,
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
            let n = chunks_count::<Fr>(chunk_bit_size) as u32;
            // Get random numbers that are of chunk_bit_size at most
            let m = gen_messages(&mut rng, n, chunk_bit_size);
            let (gens, g_i, sk, ek, dk) = enc_setup(chunk_bit_size, &mut rng);

            let prepared_gens = PreparedEncryptionGens::from(gens.clone());
            let prepared_ek = PreparedEncryptionKey::from(ek.clone());
            let prepared_dk = PreparedDecryptionKey::from(dk.clone());

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
                ek.clone(),
                gens.clone(),
            )
            .unwrap();
            println!(
                "Time taken to verify commitment of {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            Encryption::verify_ciphertext_commitment(
                &ct[0],
                &ct[1..m.len() + 1],
                &ct[m.len() + 1],
                prepared_ek,
                prepared_gens.clone(),
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
                dk.clone(),
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
            let (m_, _) = Encryption::decrypt_to_chunks(
                &ct[0],
                &ct[1..m.len() + 1],
                &sk,
                prepared_dk.clone(),
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
            let (m_, nu) = Encryption::decrypt_to_chunks_given_pairing_powers(
                &ct[0],
                &ct[1..m.len() + 1],
                &sk,
                prepared_dk.clone(),
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
            Encryption::verify_decryption(&m_, &ct[0], &ct[1..m.len() + 1], &nu, dk, &g_i, gens)
                .unwrap();
            println!(
                "Time taken to verify decryption of {}-bit chunks {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            Encryption::verify_decryption(
                &m_,
                &ct[0],
                &ct[1..m.len() + 1],
                &nu,
                prepared_dk,
                &g_i,
                prepared_gens,
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
            let prepared_gens = PreparedEncryptionGens::from(gens.clone());
            let prepared_ek = PreparedEncryptionKey::from(ek.clone());
            let prepared_dk = PreparedDecryptionKey::from(dk.clone());
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
                ct.verify_commitment(ek.clone(), gens.clone()).unwrap();
                total_ver_com += start.elapsed();

                let start = Instant::now();
                ct.verify_commitment(prepared_ek.clone(), prepared_gens.clone())
                    .unwrap();
                total_ver_com_prep += start.elapsed();

                let (chunks, nu) = Encryption::decrypt_to_chunks(
                    &ct.X_r,
                    &ct.enc_chunks,
                    &sk,
                    dk.clone(),
                    &g_i,
                    chunk_bit_size,
                )
                .unwrap();

                let decomposed = decompose(&m, chunk_bit_size).unwrap();
                assert_eq!(decomposed, chunks);

                let start = Instant::now();
                let (m_, nu_) = ct.decrypt(&sk, dk.clone(), &g_i, chunk_bit_size).unwrap();
                total_dec += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                let (m_, nu_) = ct
                    .decrypt(&sk, prepared_dk.clone(), &g_i, chunk_bit_size)
                    .unwrap();
                total_dec_prep += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                let (m_, nu_) = ct
                    .decrypt_given_pairing_powers(
                        &sk,
                        prepared_dk.clone(),
                        &g_i,
                        chunk_bit_size,
                        &pairing_powers,
                    )
                    .unwrap();
                total_dec_prep_powers += start.elapsed();
                assert_eq!(m, m_);
                assert_eq!(nu, nu_);

                let start = Instant::now();
                ct.verify_decryption(&m, &nu, chunk_bit_size, dk.clone(), &g_i, gens.clone())
                    .unwrap();
                total_ver_dec += start.elapsed();

                let start = Instant::now();
                ct.verify_decryption(
                    &m,
                    &nu,
                    chunk_bit_size,
                    prepared_dk.clone(),
                    &g_i,
                    prepared_gens.clone(),
                )
                .unwrap();
                total_ver_dec_prep += start.elapsed();
            }

            println!(
                "Time taken for {} iterations and {}-bit chunk size:",
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
        check(16, 4);
    }

    #[test]
    fn batch_commitment_verification() {
        fn check(chunk_bit_size: u8, count: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let (gens, g_i, _, ek, _) = enc_setup(chunk_bit_size, &mut rng);

            let mut cts = vec![];

            let mut total_ver_com = Duration::default();

            for _ in 0..count {
                let m = Fr::rand(&mut rng);
                let (ct, _) = Encryption::encrypt(&mut rng, &m, &ek, &g_i, chunk_bit_size).unwrap();

                let start = Instant::now();
                ct.verify_commitment(ek.clone(), gens.clone()).unwrap();
                total_ver_com += start.elapsed();

                cts.push(ct);
            }

            let r = Fr::rand(&mut rng);
            let mut r_powers = vec![Fr::one(); count as usize];
            for i in 1..count as usize {
                r_powers[i] = r_powers[i - 1] * &r;
            }

            let start = Instant::now();
            Encryption::verify_commitments_in_batch(&cts, &r_powers, ek.clone(), gens).unwrap();
            let t = start.elapsed();

            println!(
                "Time taken for {} iterations and {}-bit chunk size:",
                count, chunk_bit_size
            );
            println!("Verifying commitment {:?}", total_ver_com);
            println!("Verifying commitments in batch {:?}", t);
        }

        check(4, 10);
        check(8, 10);
        check(16, 10);
    }
}
