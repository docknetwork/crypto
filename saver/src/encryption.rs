//! Encryption, decryption, verifying commitment and verifying decryption

use crate::keygen::{DecryptionKey, EncryptionKey, Generators, SecretKey};
use crate::utils;
use ark_ec::bls12::Bls12;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_groth16::Proof;
use ark_std::ops::{Add, AddAssign};
use ark_std::{marker::PhantomData, rand::RngCore, vec, vec::Vec, UniformRand};
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;

pub struct Ciphertext<E: PairingEngine> {
    pub X_r: E::G1Affine,
    pub enc_chunks: Vec<E::G1Affine>,
    pub commitment: E::G1Affine,
}

pub struct CiphertextAlt<E: PairingEngine> {
    pub X_r: E::G1Affine,
    pub enc_chunks: Vec<E::G1Affine>,
    pub commitment: E::G1Affine,
    pub X_r_sum: E::G1Affine,
}

pub struct Encryption<E: PairingEngine>(PhantomData<E>);

impl<E: PairingEngine> Encryption<E> {
    /// Encrypt a message `m` in exponent-Elgamal after breaking it into chunks of `chunk_bit_size` bits.
    /// Returns the ciphertext, commitment and randomness created for encryption. This is "Enc" from algorithm
    /// 2 in the paper
    /// Ciphertext vector contains commitment `psi` as the last element
    pub fn encrypt<R: RngCore>(
        rng: &mut R,
        m: &E::Fr,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> (Ciphertext<E>, E::Fr) {
        let decomposed = utils::decompose(m, chunk_bit_size);
        // Self::encrypt_decomposed_message(rng, decomposed, ek, g_i)
        let (mut ct, r) = Self::encrypt_decomposed_message(rng, decomposed, ek, g_i);
        (
            Ciphertext {
                X_r: ct.remove(0),
                commitment: ct.remove(ct.len() - 1),
                enc_chunks: ct,
            },
            r,
        )
    }

    /// Same as encrypt but outputs sum `r*X_1 + r*X_2 + .. + r*X_n` as well
    // XXX: Is this secure?
    pub fn encrypt_alt<R: RngCore>(
        rng: &mut R,
        m: &E::Fr,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> (CiphertextAlt<E>, E::Fr) {
        let decomposed = utils::decompose(m, chunk_bit_size);
        let (mut ct, r) = Self::encrypt_decomposed_message(rng, decomposed, ek, g_i);
        let x_r_sum =
            ek.X.iter()
                .fold(E::G1Affine::zero(), |a, &b| a.add(b))
                .mul(r);
        (
            CiphertextAlt {
                X_r: ct.remove(0),
                commitment: ct.remove(ct.len() - 1),
                enc_chunks: ct,
                X_r_sum: x_r_sum.into_affine(),
            },
            r,
        )
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
    ) -> (E::Fr, E::G1Affine) {
        let (chunks, nu) = Self::decrypt_to_chunks(c_0, c, sk, dk, g_i, chunk_bit_size);
        (utils::compose(&chunks, chunk_bit_size), nu)
    }

    /// Verify that commitment created during encryption opens to the message chunk
    /// Check `e(c_0, Z_0) * e(c_1, Z_1) * ... * e(c_n, Z_n)` mentioned in "Verify_Enc" in algorithm 2
    pub fn verify_ciphertext_commitment(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        psi: &E::G1Affine,
        ek: &EncryptionKey<E>,
        gens: &Generators<E>,
    ) -> bool {
        let mut product = vec![];
        product.push(((*c_0).into(), ek.Z[0].into()));
        for i in 1..ek.Z.len() {
            product.push((c[i - 1].into(), ek.Z[i].into()));
        }
        product.push(((*psi).into(), (-gens.H).into()));
        E::product_of_pairings(&product).is_one()
    }

    /// Verify that ciphertext can be correctly decrypted to the given message chunks. This is "Verify_Dec" from algorithm 2 in the paper.
    pub fn verify_decryption(
        messages: &[u8],
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        gens: &Generators<E>,
    ) -> bool {
        let nu_prepared = E::G1Prepared::from(*nu);
        if !E::product_of_pairings(&[
            (nu_prepared.clone(), (-gens.H).into()),
            ((*c_0).into(), dk.V_0.into()),
        ])
        .is_one()
        {
            return false;
        }
        for i in 0..messages.len() {
            let g_i_m_i = g_i[i].mul(E::Fr::from(messages[i] as u64)).into_affine();
            let v_2_i = E::G2Prepared::from(dk.V_2[i]);
            let neg_c_i = -c[i];
            if !E::product_of_pairings(&[
                (g_i_m_i.into(), v_2_i.clone()),
                (nu_prepared.clone(), dk.V_1[i].into()),
                (neg_c_i.into(), v_2_i.clone()),
            ])
            .is_one()
            {
                return false;
            }
        }
        true
    }

    /// Decrypt the ciphertext and return each chunk and "commitment" to the randomness
    pub fn decrypt_to_chunks(
        c_0: &E::G1Affine,
        c: &[E::G1Affine],
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> (Vec<u8>, E::G1Affine) {
        let n = c.len();
        assert_eq!(n, dk.V_1.len());
        assert_eq!(n, dk.V_2.len());
        assert!(g_i.len() >= n);
        // c_0 * -rho
        let c_0_rho = c_0.mul((-sk.0).into_repr());
        let c_0_rho_prepared = E::G1Prepared::from(c_0_rho.into_affine());
        let mut pt = vec![];
        for i in 0..n {
            let p = E::product_of_pairings(&[
                (c[i].into(), dk.V_2[i].into()),
                (c_0_rho_prepared.clone(), dk.V_1[i].into()),
            ]);
            // TODO: Use prepared version
            let g_i_v_i = E::pairing(g_i[i], dk.V_2[i]);
            let max = 1 << chunk_bit_size;

            let mut powers_of_2 = Vec::with_capacity(max as usize);
            powers_of_2.push(g_i_v_i);
            for i in 1..max {
                powers_of_2.push(powers_of_2[i - 1].square());
            }
            for j in 0..max {
                /*if g_i_v_i.pow(&[j]) == p {
                    pt.push(j as u8);
                    break;
                }*/
                if E::Fqk::pow_with_table(&powers_of_2, &[j as u64]).unwrap() == p {
                    pt.push(j as u8);
                    break;
                }
            }
        }
        (pt, (-c_0_rho).into_affine())
    }

    /// Encrypt once the message has been broken into chunks
    pub fn encrypt_decomposed_message<R: RngCore>(
        rng: &mut R,
        m: Vec<u8>,
        ek: &EncryptionKey<E>,
        g_i: &[E::G1Affine],
    ) -> (Vec<E::G1Affine>, E::Fr) {
        assert_eq!(m.len(), ek.X.len());
        assert!(g_i.len() >= ek.X.len());
        let r = E::Fr::rand(rng);
        let r_repr = r.into_repr();
        let mut ct = vec![];
        ct.push(ek.X_0.mul(r_repr));
        let m = m
            .into_iter()
            .map(|m_i| <E::Fr as PrimeField>::BigInt::from(m_i as u64))
            .collect::<Vec<_>>();
        for i in 0..ek.X.len() {
            ct.push(ek.X[i].mul(r_repr).add(g_i[i].mul(m[i])));
        }
        let mut psi = ek.P_1.mul(r);
        psi.add_assign(VariableBaseMSM::multi_scalar_mul(&ek.Y, &m));
        ct.push(psi);
        (batch_normalize_projective_into_affine(ct), r)
    }
}

impl<E: PairingEngine> Ciphertext<E> {
    pub fn decrypt(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> (E::Fr, E::G1Affine) {
        Encryption::decrypt(&self.X_r, &self.enc_chunks, sk, dk, g_i, chunk_bit_size)
    }

    pub fn verify_commitment(&self, ek: &EncryptionKey<E>, gens: &Generators<E>) -> bool {
        Encryption::verify_ciphertext_commitment(
            &self.X_r,
            &self.enc_chunks,
            &self.commitment,
            ek,
            gens,
        )
    }

    pub fn verify_decryption(
        &self,
        message: &E::Fr,
        chunk_bit_size: u8,
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        gens: &Generators<E>,
    ) -> bool {
        let decomposed = utils::decompose(message, chunk_bit_size);
        Encryption::verify_decryption(&decomposed, &self.X_r, &self.enc_chunks, nu, dk, g_i, gens)
    }
}

impl<E: PairingEngine> CiphertextAlt<E> {
    pub fn decrypt(
        &self,
        sk: &SecretKey<E::Fr>,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        chunk_bit_size: u8,
    ) -> (E::Fr, E::G1Affine) {
        Encryption::decrypt(&self.X_r, &self.enc_chunks, sk, dk, g_i, chunk_bit_size)
    }

    pub fn verify_commitment(&self, ek: &EncryptionKey<E>, gens: &Generators<E>) -> bool {
        Encryption::verify_ciphertext_commitment(
            &self.X_r,
            &self.enc_chunks,
            &self.commitment,
            ek,
            gens,
        )
    }

    pub fn verify_decryption(
        &self,
        message: &E::Fr,
        chunk_bit_size: u8,
        nu: &E::G1Affine,
        dk: &DecryptionKey<E>,
        g_i: &[E::G1Affine],
        gens: &Generators<E>,
    ) -> bool {
        let decomposed = utils::decompose(message, chunk_bit_size);
        Encryption::verify_decryption(&decomposed, &self.X_r, &self.enc_chunks, nu, dk, g_i, gens)
    }
}

// TODO: Add function to rerandomize

/*fn find_discrete_log<E: PairingEngine>(g_i_v_i: &E::Fqk, max_bits: u8) -> u8 {
    let max = 1 << max_bits;
    let mut powers_of_2 = Vec::with_capacity(max as usize);
    powers_of_2.push(g_i_v_i);
    for i in 1..max {
        powers_of_2.push(powers_of_2[i-1].square());
    }
    for j in 0..max {
        /*// TODO: Use pow_with_table
        if g_i_v_i.pow(&[j]) == p {
            pt.push(j as u8);
            break;
        }*/
        if E::Fqk::pow_with_table(&powers_of_2, &[j]).unwrap() == p {
            return j;
        }
    }
}*/

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::keygen::keygen;
    use crate::utils::decompose;
    use ark_bls12_381::Bls12_381;
    use ark_ec::group::Group;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{Rng, SeedableRng};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    pub fn enc_setup<R: RngCore>(
        n: u8,
        rng: &mut R,
    ) -> (
        Generators<Bls12_381>,
        Vec<<Bls12_381 as PairingEngine>::G1Affine>,
        SecretKey<<Bls12_381 as PairingEngine>::Fr>,
        EncryptionKey<Bls12_381>,
        DecryptionKey<Bls12_381>,
    ) {
        let gens = Generators::<Bls12_381>::new_using_rng(rng);
        let g_i = (0..n)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let delta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let g_delta = gens.G.mul(delta.into_repr()).into_affine();
        let g_gamma = gens.G.mul(gamma.into_repr()).into_affine();
        let (sk, ek, dk) = keygen(rng, n, &gens, &g_i, &g_delta, &g_gamma);
        (gens, g_i, sk, ek, dk)
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let n = 4;
        let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);
        let g_i = (0..n)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let delta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);
        let g_delta = gens.G.mul(delta.into_repr()).into_affine();
        let g_gamma = gens.G.mul(gamma.into_repr()).into_affine();
        let (sk, ek, dk) = keygen(&mut rng, n, &gens, &g_i, &g_delta, &g_gamma);

        let m = vec![2, 47, 239, 155];

        let start = Instant::now();
        let (ct, _) = Encryption::encrypt_decomposed_message(&mut rng, m.clone(), &ek, &g_i);
        println!("Time taken to encrypt {:?}", start.elapsed());

        let start = Instant::now();
        assert_eq!(ct.len(), m.len() + 2);
        assert!(Encryption::verify_ciphertext_commitment(
            &ct[0],
            &ct[1..m.len() + 1],
            &ct[m.len() + 1],
            &ek,
            &gens
        ));
        println!("Time taken to verify commitment {:?}", start.elapsed());

        let start = Instant::now();
        let (m_, nu) =
            Encryption::decrypt_to_chunks(&ct[0], &ct[1..m.len() + 1], &sk, &dk, &g_i, 8);
        println!("Time taken to decrypt {:?}", start.elapsed());

        assert_eq!(m_, m);

        let start = Instant::now();
        assert!(Encryption::verify_decryption(
            &m_,
            &ct[0],
            &ct[1..m.len() + 1],
            &nu,
            &dk,
            &g_i,
            &gens
        ));
        println!("Time taken to verify decryption {:?}", start.elapsed());
    }

    #[test]
    fn encrypt_decrypt_timing() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let chunk_bit_size = 8u8;
        let n = 32;
        let (gens, g_i, sk, ek, dk) = enc_setup(n, &mut rng);

        let count = 100;
        let mut total_enc = Duration::default();
        let mut total_ver_com = Duration::default();
        let mut total_dec = Duration::default();
        let mut total_ver_dec = Duration::default();
        for _ in 0..count {
            let m = Fr::rand(&mut rng);

            let start = Instant::now();
            let (ct, _) = Encryption::encrypt(&mut rng, &m, &ek, &g_i, chunk_bit_size);
            total_enc += start.elapsed();

            let start = Instant::now();
            assert!(ct.verify_commitment(&ek, &gens));
            total_ver_com += start.elapsed();

            let (chunks, nu) = Encryption::decrypt_to_chunks(
                &ct.X_r,
                &ct.enc_chunks,
                &sk,
                &dk,
                &g_i,
                chunk_bit_size,
            );

            let decomposed = decompose(&m, chunk_bit_size);
            assert_eq!(decomposed, chunks);

            let start = Instant::now();
            let (m_, nu_) = ct.decrypt(&sk, &dk, &g_i, chunk_bit_size);
            total_dec += start.elapsed();
            assert_eq!(m, m_);
            assert_eq!(nu, nu_);

            let start = Instant::now();
            assert!(ct.verify_decryption(&m, chunk_bit_size, &nu, &dk, &g_i, &gens));
            total_ver_dec += start.elapsed();
        }

        println!(
            "Time taken for {} iterations and {} chunk size:",
            count, chunk_bit_size
        );
        println!("Encryption {:?}", total_enc);
        println!("Verifying commitment {:?}", total_ver_com);
        println!("Decryption {:?}", total_dec);
        println!("Verifying decryption {:?}", total_ver_dec);
    }
}
