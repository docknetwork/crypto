//! Using SAVER with Groth16

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ec::msm::VariableBaseMSM;
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    fmt,
    io::{Read, Write},
    marker::PhantomData,
    rand::{Rng, RngCore},
    vec,
    vec::Vec,
    UniformRand,
};

use dock_crypto_utils::impl_for_groth16_struct;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use legogroth16::aggregation::{srs::VerifierSRS, transcript::Transcript, pairing_check::PairingCheck, groth16::AggregateProof};

use crate::encryption::Ciphertext;
pub use ark_groth16::{
    create_random_proof, generate_parameters, prepare_verifying_key, PreparedVerifyingKey, Proof,
    ProvingKey as Groth16ProvingKey, VerifyingKey,
};
use ark_std::ops::AddAssign;
use dock_crypto_utils::ff::non_zero_random;

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

impl_for_groth16_struct!(
    Groth16ProvingKeyBytes,
    Groth16ProvingKey,
    "expected Groth16ProvingKey"
);
impl_for_groth16_struct!(
    Groth16VerifyingKeyBytes,
    VerifyingKey,
    "expected Groth16VerifyingKey"
);

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

/// Randomize the Groth16 proof as per algorithm 2 of the paper. Can alternatively use
/// `rerandomize_proof` from `ark_groth16`
pub fn randomize_proof<E, R>(
    mut proof: Proof<E>,
    r_prime: &E::Fr,
    vk: &VerifyingKey<E>,
    encryption_key: &EncryptionKey<E>,
    rng: &mut R,
) -> Result<Proof<E>, SaverError>
    where
        E: PairingEngine,
        R: Rng,
{
    let (z1, z2) = (non_zero_random::<E::Fr, R>(rng), non_zero_random::<E::Fr, R>(rng));
    let z1_inv = z1.inverse().unwrap();
    let z1z2 = z1 * z2;

    // proof.c = proof.c + proof.A * z1z2 + r' * P_2
    let mut c = proof.c.into_projective();
    c.add_assign(proof.a.mul(z1z2.into_repr()));
    c.add_assign(encryption_key.P_2.mul(r_prime.into_repr()));
    proof.c = c.into_affine();

    let mut b = proof.b.mul(z1_inv.into_repr());
    b.add_assign(vk.delta_g2.mul(z2));
    proof.b = b.into_affine();

    proof.a = proof.a.mul(z1.into_repr()).into_affine();

    Ok(proof)
}

pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    ciphertext: &Ciphertext<E>,
) -> Result<(), SaverError> {
    verify_qap_proof(pvk, proof.a, proof.b, proof.c, calculate_d(pvk, ciphertext)?)
}

pub fn calculate_d<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    ciphertext: &Ciphertext<E>,
) -> Result<E::G1Affine, SaverError> {
    let mut d = ciphertext.X_r.into_projective();
    for c in ciphertext.enc_chunks.iter() {
        d.add_assign(c.into_projective())
    }
    d.add_assign_mixed(&pvk.vk.gamma_abc_g1[0]);
    Ok(d.into_affine())
}

pub fn verify_qap_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    a: E::G1Affine,
    b: E::G2Affine,
    c: E::G1Affine,
    d: E::G1Affine,
) -> crate::Result<()> {
    let qap = E::miller_loop(
        [
            (a.into(), b.into()),
            (c.into(), pvk.delta_g2_neg_pc.clone()),
            (d.into(), pvk.gamma_g2_neg_pc.clone()),
        ]
            .iter(),
    );

    if E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?
        != pvk.alpha_g1_beta_g2
    {
        return Err(SaverError::PairingCheckFailed);
    }
    Ok(())
}

pub fn verify_aggregate_proof<E: PairingEngine, R: Rng, T: Transcript>(
    ip_verifier_srs: &VerifierSRS<E>,
    pvk: &PreparedVerifyingKey<E>,
    proof: &AggregateProof<E>,
    ciphertexts: &[Ciphertext<E>],
    mut rng: R,
    mut transcript: &mut T,
    pairing_check: Option<&mut PairingCheck<E>>,
) -> Result<(), SaverError> {
    use legogroth16::aggregation::{groth16::verifier::verify_tipp_mipp, utils::{powers, sum_of_powers}, error::AggregationError};

    let n = proof.tmipp.gipa.nproofs as usize;
    assert_eq!(ciphertexts.len(), n);

    if ciphertexts.len() != proof.tmipp.gipa.nproofs as usize {
        return Err(SaverError::LegoGroth16Error(AggregationError::InvalidProof(
            "ciphertexts len != number of proofs".to_string(),
        ).into()));
    }

    // Random linear combination of proofs
    transcript.append(b"AB-commitment", &proof.com_ab);
    transcript.append(b"C-commitment", &proof.com_c);

    let r = transcript.challenge_scalar::<E::Fr>(b"r-random-fiatshamir");

    let mut c = PairingCheck::new(&mut rng);
    let mut checker = pairing_check.unwrap_or_else(|| &mut c);

    let ver_srs_proj = ip_verifier_srs.to_projective();
    verify_tipp_mipp::<E, T>(
        &ver_srs_proj,
        proof,
        &r, // we give the extra r as it's not part of the proof itself - it is simply used on top for the groth16 aggregation
        &mut transcript,
        &mut checker,
    ).map_err(|e| SaverError::LegoGroth16Error(e.into()))?;

    let r_powers = powers(n, &r);
    let r_sum = sum_of_powers::<E::Fr>(n, &r);

    let mut source1 = Vec::with_capacity(3);
    let mut source2 = Vec::with_capacity(3);

    let alpha_g1_r_sum = &pvk.vk.alpha_g1.mul(r_sum);
    source1.push(alpha_g1_r_sum.into_affine());
    source2.push(pvk.vk.beta_g2);

    source1.push(proof.z_c);
    source2.push(pvk.vk.delta_g2);

    let mut bases = vec![pvk.vk.gamma_abc_g1[0]];
    let mut scalars = vec![r_sum.into_repr()];
    for (i, p) in r_powers.into_iter().enumerate() {
        let mut d = ciphertexts[i].X_r.into_projective();
        for c in ciphertexts[i].enc_chunks.iter() {
            d.add_assign(c.into_projective())
        }
        bases.push(d.into_affine());
        scalars.push(p.into_repr());
    }

    source1.push(VariableBaseMSM::multi_scalar_mul(&bases, &scalars).into_affine());
    source2.push(pvk.vk.gamma_g2);

    checker.add_sources_and_target(&source1, &source2, &proof.z_ab, true);

    match checker.verify() {
        true => Ok(()),
        false => Err(SaverError::LegoGroth16Error(AggregationError::InvalidProof(
            "Proof Verification Failed due to pairing checks".to_string(),
        ).into()))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::BitsizeCheckCircuit;
    use crate::encryption::{tests::gen_messages, Encryption};
    use crate::keygen::keygen;
    use crate::utils::chunks_count;
    use crate::setup::setup_for_groth16;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use std::time::Instant;
    use legogroth16::aggregation::{transcript::new_merlin_transcript, srs};

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

    #[test]
    fn rerandomize_encryption() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let n = chunks_count::<Fr>(chunk_bit_size);
            let msg = Fr::rand(&mut rng);

            let circuit = BitsizeCheckCircuit::new(chunk_bit_size, Some(n), None, true);
            let snark_srs = generate_srs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();
            let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

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

            let start = Instant::now();
            let (ct, _, proof) = Encryption::encrypt_with_proof(&mut rng, &msg, &ek, &snark_srs, chunk_bit_size).unwrap();
            let enc_time = start.elapsed();

            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                &ek,
                &gens,
            )
                .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(&sk, &dk, &snark_srs.pk.vk, chunk_bit_size)
                .unwrap();
            assert_eq!(decrypted_message, msg);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                &dk,
                &snark_srs.pk.vk,
                &gens,
            )
                .unwrap();

            let start = Instant::now();
            let (ct, _, proof) = Encryption::rerandomize_ciphertext_and_proof(ct, proof, &snark_srs.pk.vk, &ek, &mut rng).unwrap();
            let re_rand_time = start.elapsed();

            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                &ek,
                &gens,
            )
                .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(&sk, &dk, &snark_srs.pk.vk, chunk_bit_size)
                .unwrap();
            assert_eq!(decrypted_message, msg);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                &dk,
                &snark_srs.pk.vk,
                &gens,
            )
                .unwrap();

            println!("For {}-bit chunks, encryption time={:?}, re-randomization time={:?}", chunk_bit_size, enc_time, re_rand_time);
        }

        check(4);
        check(8);
        check(16);
    }

    #[test]
    fn proof_aggregation() {
        let chunk_bit_size = 16;
        let mut rng = StdRng::seed_from_u64(0u64);
        let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);

        let (snark_srs, _, ek, _) =
            setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

        let msg_count = 8;
        let msgs = (0..msg_count).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let mut cts = vec![];
        let mut proofs = vec![];
        for i in 0..msg_count {
            let (ct, _, proof) = Encryption::encrypt_with_proof(&mut rng, &msgs[i], &ek, &snark_srs, chunk_bit_size).unwrap();
            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                &ek,
                &enc_gens,
            )
                .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            cts.push(ct);
            proofs.push(proof);
        }

        let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, msg_count);
        let (prover_srs, ver_srs) = srs.specialize(msg_count);

        let mut prover_transcript = new_merlin_transcript(b"test aggregation");
        let aggregate_proof = legogroth16::aggregation::groth16::aggregate_proofs(&prover_srs, &mut prover_transcript, &proofs)
            .expect("error in aggregation");

        let mut ver_transcript = new_merlin_transcript(b"test aggregation");
        verify_aggregate_proof(
            &ver_srs,
            &pvk,
            &aggregate_proof,
            &cts,
            &mut rng,
            &mut ver_transcript,
            None,
        )
            .expect("error in verification");
    }
}
