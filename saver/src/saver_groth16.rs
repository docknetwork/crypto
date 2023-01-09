//! Using SAVER with Groth16

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    rand::{Rng, RngCore},
    UniformRand,
};

use dock_crypto_utils::impl_for_groth16_struct;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::encryption::Ciphertext;
pub use ark_groth16::{
    create_random_proof, generate_parameters, prepare_verifying_key, PreparedVerifyingKey, Proof,
    ProvingKey as Groth16ProvingKey, VerifyingKey,
};
use ark_std::ops::AddAssign;

use crate::error::SaverError;
use dock_crypto_utils::serde_utils::*;

use crate::keygen::EncryptionKey;
use crate::setup::EncryptionGens;

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProvingKey<E: PairingEngine> {
    /// Groth16's proving key
    #[serde_as(as = "Groth16ProvingKeyBytes")]
    pub pk: Groth16ProvingKey<E>,
    /// The element `-gamma * G` in `E::G1`.
    #[serde_as(as = "AffineGroupBytes")]
    pub gamma_g1: E::G1Affine,
}

impl_for_groth16_struct!(Groth16ProvingKeyBytes);
impl_for_groth16_struct!(Groth16VerifyingKeyBytes);

/// These parameters are needed for setting up keys for encryption/decryption
pub fn get_gs_for_encryption<E: PairingEngine>(vk: &VerifyingKey<E>) -> &[E::G1Affine] {
    &vk.gamma_abc_g1[1..]
}

/// Generate Groth16 SRS
pub fn generate_srs<E: PairingEngine, R: RngCore, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
    gens: &EncryptionGens<E>,
    rng: &mut R,
) -> Result<ProvingKey<E>, SaverError> {
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let gamma = E::Fr::rand(rng);
    let delta = E::Fr::rand(rng);

    let g1_generator = gens.G.into_projective();
    let neg_gamma_g1 = g1_generator.mul((-gamma).into_repr());

    let pk = generate_parameters::<E, C, R>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        g1_generator,
        gens.H.into_projective(),
        rng,
    )?;

    Ok(ProvingKey {
        pk,
        gamma_g1: neg_gamma_g1.into_affine(),
    })
}

/// `r` is the randomness used during the encryption
pub fn create_proof<E, C, R>(
    circuit: C,
    r: &E::Fr,
    pk: &ProvingKey<E>,
    encryption_key: &EncryptionKey<E>,
    rng: &mut R,
) -> Result<Proof<E>, SaverError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut proof = create_random_proof(circuit, &pk.pk, rng)?;

    // proof.c = proof.c + r * P_2
    let mut c = proof.c.into_projective();
    c.add_assign(encryption_key.P_2.mul(r.into_repr()));
    proof.c = c.into_affine();

    Ok(proof)
}

pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    ciphertext: &Ciphertext<E>,
) -> Result<(), SaverError> {
    let mut d = ciphertext.X_r.into_projective();
    for c in ciphertext.enc_chunks.iter() {
        d.add_assign(c.into_projective())
    }

    d.add_assign_mixed(&pvk.vk.gamma_abc_g1[0]);

    let qap = E::miller_loop(
        [
            (proof.a.into(), proof.b.into()),
            (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
            (d.into_affine().into(), pvk.gamma_g2_neg_pc.clone()),
        ]
        .iter(),
    );

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;
    if test == pvk.alpha_g1_beta_g2 {
        Ok(())
    } else {
        Err(SaverError::PairingCheckFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::BitsizeCheckCircuit;
    use crate::encryption::{tests::gen_messages, Encryption};
    use crate::keygen::keygen;
    use crate::utils::chunks_count;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn encrypt_and_snark_verification() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let n = chunks_count::<Fr>(chunk_bit_size);
            // Get random numbers that are of chunk_bit_size at most
            let msgs = gen_messages(&mut rng, n as usize, chunk_bit_size);
            let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

            let circuit = BitsizeCheckCircuit::new(chunk_bit_size, Some(n), None, true);
            let snark_srs = generate_srs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();

            println!(
                "For chunk_bit_size {}, Snark SRS has compressed size {} and uncompressed size {}",
                chunk_bit_size,
                snark_srs.serialized_size(),
                snark_srs.uncompressed_size()
            );

            let g_i = get_gs_for_encryption(&snark_srs.pk.vk);
            let (sk, ek, dk) = keygen(
                &mut rng,
                chunk_bit_size,
                &gens,
                g_i,
                &snark_srs.pk.delta_g1,
                &snark_srs.gamma_g1,
            )
            .unwrap();

            println!("For chunk_bit_size {}, encryption key has compressed size {} and uncompressed size {}", chunk_bit_size, ek.serialized_size(), ek.uncompressed_size());

            let (ct, r) =
                Encryption::encrypt_decomposed_message(&mut rng, msgs.clone(), &ek, &g_i).unwrap();

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

            let circuit = BitsizeCheckCircuit::new(
                chunk_bit_size,
                Some(n),
                Some(msgs_as_field_elems.clone()),
                true,
            );

            let start = Instant::now();
            let proof = create_proof(circuit, &r, &snark_srs, &ek, &mut rng).unwrap();
            println!(
                "Time taken to create Groth16 proof with chunk_bit_size {}: {:?}",
                chunk_bit_size,
                start.elapsed()
            );

            let start = Instant::now();
            Encryption::verify_ciphertext_commitment(
                &ct[0],
                &ct[1..n as usize + 1],
                &ct[n as usize + 1],
                &ek,
                &gens,
            )
            .unwrap();
            let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

            let ct = Ciphertext {
                X_r: ct[0].clone(),
                enc_chunks: ct[1..n as usize + 1].to_vec().clone(),
                commitment: ct[n as usize + 1].clone(),
            };
            verify_proof(&pvk, &proof, &ct).unwrap();
            println!(
                "Time taken to verify Groth16 proof with chunk_bit_size {}: {:?}",
                chunk_bit_size,
                start.elapsed()
            );
        }
        check(4);
        check(8);
        check(16);
    }
}
