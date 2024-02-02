//! Using SAVER with Groth16
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{AddAssign, Mul},
    rand::{Rng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    UniformRand,
};

use legogroth16::aggregation::{groth16::AggregateProof, srs::VerifierSRS};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::encryption::Ciphertext;
pub use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey as Groth16ProvingKey,
    VerifyingKey,
};
use dock_crypto_utils::{
    ff::{non_zero_random, powers, sum_of_powers},
    randomized_pairing_check::RandomizedPairingChecker,
};

use crate::error::SaverError;
use dock_crypto_utils::{serde_utils::*, transcript::Transcript};

use crate::{keygen::EncryptionKey, setup::EncryptionGens};

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ProvingKey<E: Pairing> {
    /// Groth16's proving key
    #[serde_as(as = "ArkObjectBytes")]
    pub pk: Groth16ProvingKey<E>,
    /// The element `-gamma * G` in `E::G1`.
    #[serde_as(as = "ArkObjectBytes")]
    pub gamma_g1: E::G1Affine,
}

/// These parameters are needed for setting up keys for encryption/decryption
pub fn get_gs_for_encryption<E: Pairing>(vk: &VerifyingKey<E>) -> &[E::G1Affine] {
    &vk.gamma_abc_g1[1..]
}

/// Generate Groth16 SRS
pub fn generate_srs<E: Pairing, R: RngCore, C: ConstraintSynthesizer<E::ScalarField>>(
    circuit: C,
    gens: &EncryptionGens<E>,
    rng: &mut R,
) -> Result<ProvingKey<E>, SaverError> {
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);
    let delta = E::ScalarField::rand(rng);

    let g1_generator = gens.G.into_group();
    let neg_gamma_g1 = g1_generator.mul_bigint((-gamma).into_bigint());

    let pk = Groth16::<E>::generate_parameters_with_qap::<C>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        g1_generator,
        gens.H.into_group(),
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
    r: &E::ScalarField,
    pk: &ProvingKey<E>,
    encryption_key: &EncryptionKey<E>,
    rng: &mut R,
) -> Result<Proof<E>, SaverError>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: Rng,
{
    let t = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);
    let mut proof = Groth16::<E>::create_proof_with_reduction(circuit, &pk.pk, t, s)?;

    // proof.c = proof.c + r * P_2
    let mut c = proof.c.into_group();
    c.add_assign(encryption_key.P_2.mul_bigint(r.into_bigint()));
    proof.c = c.into_affine();

    Ok(proof)
}

/// Randomize the Groth16 proof as per algorithm 2 of the paper. Can alternatively use
/// `rerandomize_proof` from `ark_groth16`
pub fn randomize_proof<E: Pairing, R: Rng>(
    mut proof: Proof<E>,
    r_prime: &E::ScalarField,
    vk: &VerifyingKey<E>,
    encryption_key: &EncryptionKey<E>,
    rng: &mut R,
) -> Result<Proof<E>, SaverError> {
    let (z1, z2) = (
        non_zero_random::<E::ScalarField, R>(rng),
        non_zero_random::<E::ScalarField, R>(rng),
    );
    let z1_inv = z1.inverse().unwrap();
    let z1z2 = z1 * z2;

    // proof.c = proof.c + proof.A * z1z2 + r' * P_2
    let mut c = proof.c.into_group();
    c.add_assign(proof.a.mul_bigint(z1z2.into_bigint()));
    c.add_assign(encryption_key.P_2.mul_bigint(r_prime.into_bigint()));
    proof.c = c.into_affine();

    let mut b = proof.b.mul_bigint(z1_inv.into_bigint());
    b.add_assign(vk.delta_g2.mul(z2));
    proof.b = b.into_affine();

    proof.a = proof.a.mul_bigint(z1.into_bigint()).into_affine();

    Ok(proof)
}

pub fn verify_proof<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    ciphertext: &Ciphertext<E>,
) -> Result<(), SaverError> {
    verify_qap_proof(
        pvk,
        proof.a,
        proof.b,
        proof.c,
        calculate_d(pvk, ciphertext)?,
    )
}

pub fn calculate_d<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    ciphertext: &Ciphertext<E>,
) -> Result<E::G1Affine, SaverError> {
    let mut d = ciphertext.X_r.into_group();
    for c in ciphertext.enc_chunks.iter() {
        d.add_assign(c.into_group())
    }
    d.add_assign(&pvk.vk.gamma_abc_g1[0]);
    Ok(d.into_affine())
}

pub fn verify_qap_proof<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    a: E::G1Affine,
    b: E::G2Affine,
    c: E::G1Affine,
    d: E::G1Affine,
) -> crate::Result<()> {
    let qap = E::multi_miller_loop(
        [a, c, d],
        [
            b.into(),
            pvk.delta_g2_neg_pc.clone(),
            pvk.gamma_g2_neg_pc.clone(),
        ],
    );

    if E::final_exponentiation(qap)
        .ok_or(SynthesisError::UnexpectedIdentity)?
        .0
        != pvk.alpha_g1_beta_g2
    {
        return Err(SaverError::PairingCheckFailed);
    }
    Ok(())
}

pub fn verify_aggregate_proof<E: Pairing, R: Rng, T: Transcript>(
    ip_verifier_srs: &VerifierSRS<E>,
    pvk: &PreparedVerifyingKey<E>,
    proof: &AggregateProof<E>,
    ciphertexts: &[Ciphertext<E>],
    rng: &mut R,
    transcript: &mut T,
    pairing_check: Option<&mut RandomizedPairingChecker<E>>,
) -> Result<(), SaverError> {
    use legogroth16::aggregation::{error::AggregationError, groth16::verifier::verify_tipp_mipp};

    let n = proof.tmipp.gipa.nproofs;
    assert_eq!(ciphertexts.len(), n as usize);

    if ciphertexts.len() != proof.tmipp.gipa.nproofs as usize {
        return Err(SaverError::LegoGroth16Error(
            AggregationError::InvalidProof("ciphertexts len != number of proofs".to_string())
                .into(),
        ));
    }

    // Random linear combination of proofs
    transcript.append(b"AB-commitment", &proof.com_ab);
    transcript.append(b"C-commitment", &proof.com_c);

    let r = transcript.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

    let mut c = RandomizedPairingChecker::new_using_rng(rng, true);
    let checker = pairing_check.unwrap_or(&mut c);

    let ver_srs_proj = ip_verifier_srs.to_projective();
    verify_tipp_mipp::<E, T>(
        &ver_srs_proj,
        proof,
        &r, // we give the extra r as it's not part of the proof itself - it is simply used on top for the groth16 aggregation
        transcript,
        checker,
    )
    .map_err(|e| SaverError::LegoGroth16Error(e.into()))?;

    let r_powers = powers(&r, n);
    let r_sum = sum_of_powers::<E::ScalarField>(&r, n);

    let mut source1 = Vec::with_capacity(3);
    let mut source2 = Vec::with_capacity(3);

    let alpha_g1_r_sum = &pvk.vk.alpha_g1.mul(r_sum);
    source1.push(alpha_g1_r_sum.into_affine());
    source2.push(pvk.vk.beta_g2);

    source1.push(proof.z_c);
    source2.push(pvk.vk.delta_g2);

    let mut bases = vec![pvk.vk.gamma_abc_g1[0]];
    let mut scalars = vec![r_sum.into_bigint()];
    for (i, p) in r_powers.into_iter().enumerate() {
        let mut d = ciphertexts[i].X_r.into_group();
        for c in ciphertexts[i].enc_chunks.iter() {
            d.add_assign(c.into_group())
        }
        bases.push(d.into_affine());
        scalars.push(p.into_bigint());
    }

    source1.push(E::G1::msm_bigint(&bases, &scalars).into_affine());
    source2.push(pvk.vk.gamma_g2);

    checker.add_multiple_sources_and_target(&source1, &source2, &proof.z_ab);

    match checker.verify() {
        true => Ok(()),
        false => Err(SaverError::LegoGroth16Error(
            AggregationError::InvalidProof(
                "Proof Verification Failed due to pairing checks".to_string(),
            )
            .into(),
        ))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::BitsizeCheckCircuit,
        encryption::{tests::gen_messages, Encryption},
        keygen::keygen,
        setup::setup_for_groth16,
        utils::chunks_count,
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use dock_crypto_utils::transcript::new_merlin_transcript;
    use legogroth16::aggregation::srs;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn encrypt_and_snark_verification() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let n = chunks_count::<Fr>(chunk_bit_size);
            // Get random numbers that are of chunk_bit_size at most
            let msgs = gen_messages(&mut rng, n as u32, chunk_bit_size);
            let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

            let circuit = BitsizeCheckCircuit::new(chunk_bit_size, Some(n), None, true);
            let snark_srs = generate_srs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();

            println!(
                "For chunk_bit_size {}, Snark SRS has compressed size {} and uncompressed size {}",
                chunk_bit_size,
                snark_srs.compressed_size(),
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

            println!("For chunk_bit_size {}, encryption key has compressed size {} and uncompressed size {}", chunk_bit_size, ek.compressed_size(), ek.uncompressed_size());

            let (ct, r) =
                Encryption::encrypt_decomposed_message(&mut rng, msgs.clone(), &ek, g_i).unwrap();

            let (m_, _) = Encryption::decrypt_to_chunks(
                &ct[0],
                &ct[1..n as usize + 1],
                &sk,
                dk,
                g_i,
                chunk_bit_size,
            )
            .unwrap();

            assert_eq!(m_, msgs);

            let circuit =
                BitsizeCheckCircuit::new(chunk_bit_size, Some(n), Some(msgs_as_field_elems), true);

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
                ek.clone(),
                gens.clone(),
            )
            .unwrap();
            let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

            let ct = Ciphertext {
                X_r: ct[0],
                enc_chunks: ct[1..n as usize + 1].to_vec(),
                commitment: ct[n as usize + 1],
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
            let (ct, _, proof) =
                Encryption::encrypt_with_proof(&mut rng, &msg, &ek, &snark_srs, chunk_bit_size)
                    .unwrap();
            let enc_time = start.elapsed();

            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                ek.clone(),
                gens.clone(),
            )
            .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(&sk, dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
                .unwrap();
            assert_eq!(decrypted_message, msg);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                dk.clone(),
                &snark_srs.pk.vk,
                gens.clone(),
            )
            .unwrap();

            let start = Instant::now();
            let (ct, _, proof) = Encryption::rerandomize_ciphertext_and_proof(
                ct,
                proof,
                &snark_srs.pk.vk,
                &ek,
                &mut rng,
            )
            .unwrap();
            let re_rand_time = start.elapsed();

            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                ek.clone(),
                gens.clone(),
            )
            .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            let (decrypted_message, nu) = ct
                .decrypt_given_groth16_vk(&sk, dk.clone(), &snark_srs.pk.vk, chunk_bit_size)
                .unwrap();
            assert_eq!(decrypted_message, msg);
            ct.verify_decryption_given_groth16_vk(
                &decrypted_message,
                &nu,
                chunk_bit_size,
                dk,
                &snark_srs.pk.vk,
                gens.clone(),
            )
            .unwrap();

            println!(
                "For {}-bit chunks, encryption time={:?}, re-randomization time={:?}",
                chunk_bit_size, enc_time, re_rand_time
            );
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

        let (snark_srs, _, ek, _) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);

        let msg_count = 8;
        let msgs = (0..msg_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut cts = vec![];
        let mut proofs = vec![];
        for i in 0..msg_count as usize {
            let (ct, _, proof) =
                Encryption::encrypt_with_proof(&mut rng, &msgs[i], &ek, &snark_srs, chunk_bit_size)
                    .unwrap();
            Encryption::verify_ciphertext_commitment(
                &ct.X_r,
                &ct.enc_chunks,
                &ct.commitment,
                ek.clone(),
                enc_gens.clone(),
            )
            .unwrap();

            verify_proof(&pvk, &proof, &ct).unwrap();

            cts.push(ct);
            proofs.push(proof);
        }

        let srs = srs::setup_fake_srs::<Bls12_381, _>(&mut rng, msg_count);
        let (prover_srs, ver_srs) = srs.specialize(msg_count);

        let mut prover_transcript = new_merlin_transcript(b"test aggregation");
        let aggregate_proof = legogroth16::aggregation::groth16::aggregate_proofs(
            prover_srs,
            &mut prover_transcript,
            &proofs,
        )
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
