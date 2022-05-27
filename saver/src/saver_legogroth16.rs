//! Using SAVER with LegoGroth16

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::ops::AddAssign;
use ark_std::{
    io::{Read, Write},
    rand::{Rng, RngCore},
    UniformRand,
};
use legogroth16::{
    create_random_proof, generate_parameters_with_qap, verify_qap_proof, LibsnarkReduction,
    PreparedVerifyingKey, Proof, VerifyingKey,
};

use crate::keygen::EncryptionKey;
use crate::setup::EncryptionGens;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: PairingEngine> {
    /// LegoGroth16's proving key
    pub pk: legogroth16::ProvingKey<E>,
    /// The element `-gamma * G` in `E::G1`.
    pub gamma_g1: E::G1Affine,
}

/// These parameters are needed for setting up keys for encryption/decryption
pub fn get_gs_for_encryption<E: PairingEngine>(vk: &VerifyingKey<E>) -> &[E::G1Affine] {
    &vk.gamma_abc_g1[1..]
}

pub fn generate_srs<E: PairingEngine, R: RngCore, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
    gens: &EncryptionGens<E>,
    bit_blocks_count: u8,
    rng: &mut R,
) -> crate::Result<ProvingKey<E>> {
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let gamma = E::Fr::rand(rng);
    let delta = E::Fr::rand(rng);
    let eta = E::Fr::rand(rng);

    let g1_generator = gens.G.into_projective();
    let neg_gamma_g1 = g1_generator.mul((-gamma).into_repr());

    let pk = generate_parameters_with_qap::<E, C, R, LibsnarkReduction>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        eta,
        g1_generator,
        gens.H.into_projective(),
        bit_blocks_count as usize,
        rng,
    )?;

    Ok(ProvingKey {
        pk,
        gamma_g1: neg_gamma_g1.into_affine(),
    })
}

/// This keeps the encryption algorithm same as mentioned in the paper but the proof contains an extra
/// group element which also changes the hiding property of the commitment from information theoretic to
/// computational.
mod protocol_1 {
    use super::*;
    use crate::encryption::Ciphertext;

    #[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
    pub struct Proof<E: PairingEngine> {
        pub proof: legogroth16::Proof<E>,
        pub v_eta_gamma_inv: E::G1Affine,
    }

    /// `r` is the randomness used during the encryption
    #[allow(dead_code)]
    pub fn create_proof<E, C, R>(
        circuit: C,
        v: E::Fr,
        r: &E::Fr,
        pk: &ProvingKey<E>,
        encryption_key: &EncryptionKey<E>,
        rng: &mut R,
    ) -> crate::Result<Proof<E>>
    where
        E: PairingEngine,
        C: ConstraintSynthesizer<E::Fr>,
        R: Rng,
    {
        let mut proof = create_random_proof(circuit, v, &pk.pk, rng)?;

        // proof.c = proof.c + r * P_2
        let mut c = proof.c.into_projective();
        c.add_assign(encryption_key.P_2.mul(r.into_repr()));
        proof.c = c.into_affine();

        let proof = Proof {
            proof,
            v_eta_gamma_inv: pk.pk.vk.eta_gamma_inv_g1.mul(v).into_affine(),
        };
        Ok(proof)
    }

    #[allow(dead_code)]
    pub fn verify_proof<E: PairingEngine>(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        ciphertext: &Ciphertext<E>,
    ) -> crate::Result<()> {
        // verify_link_proof(&pvk.vk, &proof.proof)?;

        let mut d = ciphertext.X_r.into_projective();
        for c in ciphertext.enc_chunks.iter() {
            d.add_assign(c.into_projective())
        }
        d.add_assign_mixed(&pvk.vk.gamma_abc_g1[0]);
        d.add_assign_mixed(&proof.v_eta_gamma_inv);

        verify_qap_proof(
            pvk,
            proof.proof.a,
            proof.proof.b,
            proof.proof.c,
            d.into_affine(),
        )
        .map_err(|e| e.into())
    }
}

/// This modifies the encryption algorithm from the paper by also outputting `r*X_1 + r*X_2 + .. + r*X_n`
/// as well in encryption, i.e. uses `encrypt_alt`
mod protocol_2 {
    use super::*;
    use crate::encryption::CiphertextAlt;

    /// `r` is the randomness used during the encryption
    #[allow(dead_code)]
    pub fn create_proof<E, C, R>(
        circuit: C,
        v: E::Fr,
        r: &E::Fr,
        pk: &ProvingKey<E>,
        encryption_key: &EncryptionKey<E>,
        rng: &mut R,
    ) -> crate::Result<Proof<E>>
    where
        E: PairingEngine,
        C: ConstraintSynthesizer<E::Fr>,
        R: Rng,
    {
        let mut proof = create_random_proof(circuit, v, &pk.pk, rng)?;

        // proof.c = proof.c + r * P_2
        let mut c = proof.c.into_projective();
        c.add_assign(encryption_key.P_2.mul(r.into_repr()));
        proof.c = c.into_affine();

        Ok(proof)
    }

    #[allow(dead_code)]
    pub fn verify_proof<E: PairingEngine>(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        ciphertext: &CiphertextAlt<E>,
    ) -> crate::Result<()> {
        // verify_link_proof(&pvk.vk, &proof)?;
        // d = G[0] + r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n] + r * X_0 + v * (eta/gamma)*G
        let mut d = proof.d.into_projective().add_mixed(&ciphertext.X_r_sum);
        d.add_assign_mixed(&pvk.vk.gamma_abc_g1[0]);
        d.add_assign_mixed(&ciphertext.X_r);
        verify_qap_proof(pvk, proof.a, proof.b, proof.c, d.into_affine()).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;
    use std::time::Instant;

    use crate::circuit::BitsizeCheckCircuit;
    use crate::encryption::{tests::gen_messages, Ciphertext, CiphertextAlt, Encryption};
    use crate::keygen::keygen;
    use crate::utils::chunks_count;
    use ark_bls12_381::Bls12_381;
    use ark_ff::Zero;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use legogroth16::prepare_verifying_key;
    use legogroth16::prover::verify_witness_commitment;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn encrypt_and_snark_verification() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let n = chunks_count::<Fr>(chunk_bit_size);
            let gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

            // Get random numbers that are of chunk_bit_size at most
            let msgs = gen_messages(&mut rng, n as usize, chunk_bit_size);
            let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

            let circuit = BitsizeCheckCircuit::new(chunk_bit_size, Some(n), None, false);
            let snark_srs = generate_srs::<Bls12_381, _, _>(circuit, &gens, n, &mut rng).unwrap();

            let g_i = &get_gs_for_encryption(&snark_srs.pk.vk);
            let (sk, ek, dk) = keygen(
                &mut rng,
                chunk_bit_size,
                &gens,
                g_i,
                &snark_srs.pk.common.delta_g1,
                &snark_srs.gamma_g1,
            )
            .unwrap();

            // Using the version of encrypt that outputs the sum X_i^r as well
            let (ct, r) =
                Encryption::encrypt_decomposed_message(&mut rng, msgs.clone(), &ek, &g_i).unwrap();
            let x_r_sum =
                ek.X.iter()
                    .fold(<Bls12_381 as PairingEngine>::G1Affine::zero(), |a, &b| {
                        a.add(b)
                    })
                    .mul(r)
                    .into_affine();

            let (m_, _) = Encryption::decrypt_to_chunks(
                &ct[0],
                &ct[1..n as usize + 1],
                &sk,
                &dk,
                &g_i,
                chunk_bit_size,
            )
            .unwrap();

            assert_eq!(m_, msgs);

            // Create commitment randomness
            let v = Fr::rand(&mut rng);

            let circuit = BitsizeCheckCircuit::new(
                chunk_bit_size,
                Some(n),
                Some(msgs_as_field_elems.clone()),
                false,
            );

            let start = Instant::now();
            let proof_2 =
                protocol_2::create_proof(circuit.clone(), v.clone(), &r, &snark_srs, &ek, &mut rng)
                    .unwrap();
            println!(
                "Time taken to create LegoGroth16 proof with chunk_bit_size {} as per protocol 2 {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
            Encryption::verify_ciphertext_commitment(
                &ct[0],
                &ct[1..n as usize + 1],
                &ct[n as usize + 1],
                &ek,
                &gens,
            )
            .unwrap();
            let ct2 = CiphertextAlt {
                X_r: ct[0].clone(),
                enc_chunks: ct[1..n as usize + 1].to_vec().clone(),
                commitment: ct[n as usize + 1].clone(),
                X_r_sum: x_r_sum,
            };
            protocol_2::verify_proof(&pvk, &proof_2, &ct2).unwrap();
            println!(
                "Time taken to verify LegoGroth16 proof with chunk_bit_size {} as per protocol 2 {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            verify_witness_commitment(&pvk.vk, &proof_2, 0, &msgs_as_field_elems, &v).unwrap();

            let start = Instant::now();
            let proof_1 =
                protocol_1::create_proof(circuit, v, &r, &snark_srs, &ek, &mut rng).unwrap();
            println!(
                "Time taken to create LegoGroth16 proof with chunk_bit_size {} as per protocol 1 {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
            Encryption::verify_ciphertext_commitment(
                &ct[0],
                &ct[1..n as usize + 1],
                &ct[n as usize + 1],
                &ek,
                &gens,
            )
            .unwrap();
            let ct1 = Ciphertext {
                X_r: ct[0].clone(),
                enc_chunks: ct[1..n as usize + 1].to_vec().clone(),
                commitment: ct[n as usize + 1].clone(),
            };
            protocol_1::verify_proof(&pvk, &proof_1, &ct1).unwrap();
            println!(
                "Time taken to verify LegoGroth16 proof with chunk_bit_size {} as per protocol 1 {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            verify_witness_commitment(&pvk.vk, &proof_1.proof, 0, &msgs_as_field_elems, &v)
                .unwrap();
        }
        check(4);
        check(8);
        check(16);
    }
}
