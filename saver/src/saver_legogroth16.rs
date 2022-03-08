//! Using SAVER with LegoGroth16

use crate::circuit::BitsizeCheckCircuit;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, Boolean, EqGadget};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::ops::{AddAssign, Sub};
use ark_std::{
    io::{Read, Write},
    rand::{Rng, RngCore},
    vec::Vec,
    UniformRand,
};
use legogroth16::{
    create_random_proof, generate_parameters_with_qap, verify_link_proof, LibsnarkReduction,
    LinkPublicGenerators, PreparedVerifyingKey, Proof, VerifyingKey,
};

use crate::error::Error;
use crate::keygen::{EncryptionKey, Generators};

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
    gens: &Generators<E>,
    link_gens: LinkPublicGenerators<E>,
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
        link_gens,
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
    pub fn create_proof<E, C, R>(
        circuit: C,
        v: E::Fr,
        link_v: E::Fr,
        r: E::Fr,
        pk: &ProvingKey<E>,
        encryption_key: &EncryptionKey<E>,
        rng: &mut R,
    ) -> crate::Result<Proof<E>>
    where
        E: PairingEngine,
        C: ConstraintSynthesizer<E::Fr>,
        R: Rng,
    {
        let mut proof = create_random_proof(circuit, v, link_v, &pk.pk, rng)?;

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

    pub fn verify_proof<E: PairingEngine>(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        ciphertext: &Ciphertext<E>,
    ) -> crate::Result<()> {
        verify_link_proof(&pvk.vk, &proof.proof)?;

        let mut d = ciphertext.X_r.into_projective();
        for c in ciphertext.enc_chunks.iter() {
            d.add_assign(c.into_projective())
        }
        d.add_assign_mixed(&pvk.vk.gamma_abc_g1[0]);
        d.add_assign_mixed(&proof.v_eta_gamma_inv);

        let qap = E::miller_loop(
            [
                (proof.proof.a.into(), proof.proof.b.into()),
                (proof.proof.c.into(), pvk.delta_g2_neg_pc.clone()),
                (d.into_affine().into(), pvk.gamma_g2_neg_pc.clone()),
            ]
            .iter(),
        );

        if E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?
            != pvk.alpha_g1_beta_g2
        {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
}

/// This modifies the encryption algorithm from the paper by also outputting `r*X_1 + r*X_2 + .. + r*X_n`
/// as well, i.e. uses encrypt_alt
mod protocol_2 {
    use super::*;
    use crate::encryption::{Ciphertext, CiphertextAlt};

    /// `r` is the randomness used during the encryption
    pub fn create_proof<E, C, R>(
        circuit: C,
        v: E::Fr,
        link_v: E::Fr,
        r: E::Fr,
        pk: &ProvingKey<E>,
        encryption_key: &EncryptionKey<E>,
        rng: &mut R,
    ) -> crate::Result<Proof<E>>
    where
        E: PairingEngine,
        C: ConstraintSynthesizer<E::Fr>,
        R: Rng,
    {
        let mut proof = create_random_proof(circuit, v, link_v, &pk.pk, rng)?;

        // proof.c = proof.c + r * P_2
        let mut c = proof.c.into_projective();
        c.add_assign(encryption_key.P_2.mul(r.into_repr()));
        proof.c = c.into_affine();

        Ok(proof)
    }

    pub fn verify_proof<E: PairingEngine>(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        ciphertext: &CiphertextAlt<E>,
    ) -> crate::Result<()> {
        verify_link_proof(&pvk.vk, &proof)?;

        // Get v * (eta/gamma)*G
        // proof.d = G[0] + m1*G[1] + m2*G[2] + ... + v * (eta/gamma)*G
        // ct_sum = r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n]
        let mut ct_sum = ciphertext.enc_chunks[0].into_projective();
        for c in ciphertext.enc_chunks[1..].iter() {
            ct_sum.add_assign_mixed(c)
        }
        // ct_sum_plus_g_0 = ct_sum + G[0]
        let ct_sum_plus_g_0 = ct_sum.add_mixed(&pvk.vk.gamma_abc_g1[0]);
        // ct_sum_plus_g_0_minus_X_r_sum = ct_sum + G[0] - X_r_sum
        // = r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n] + G[0] - (r*X_1 + r*X_2 + .. + r*X_n)
        // = G[0] + m1*G[1] + m2*G[2] + ... + mn*G[n]
        let ct_sum_plus_g_0_minus_x_r_sum =
            ct_sum_plus_g_0.sub(ciphertext.X_r_sum.into_projective());

        // proof.d - ct_sum_plus_g_0_minus_x_r_sum
        // = G[0] + m1*G[1] + m2*G[2] + ... + v * (eta/gamma)*G - (G[0] + m1*G[1] + m2*G[2] + ... + mn*G[n])
        // = v * (eta/gamma)*G
        let v_eta_gamma_inv = proof
            .d
            .into_projective()
            .sub(&ct_sum_plus_g_0_minus_x_r_sum);

        // d = G[0] + r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n] + r * X_0 + v * (eta/gamma)*G
        let mut d = ct_sum_plus_g_0;
        d.add_assign_mixed(&ciphertext.X_r);
        d.add_assign(&v_eta_gamma_inv);

        let qap = E::miller_loop(
            [
                (proof.a.into(), proof.b.into()),
                (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
                (d.into_affine().into(), pvk.gamma_g2_neg_pc.clone()),
            ]
            .iter(),
        );

        if E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?
            != pvk.alpha_g1_beta_g2
        {
            return Err(Error::InvalidProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;
    use std::time::Instant;

    use crate::encryption::{Ciphertext, CiphertextAlt, Encryption};
    use crate::keygen::keygen;
    use ark_bls12_381::Bls12_381;
    use ark_ff::Zero;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use legogroth16::prepare_verifying_key;
    use legogroth16::prover::{verify_commitment, verify_link_commitment};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    pub fn get_link_public_gens<R: RngCore, E: PairingEngine>(
        rng: &mut R,
        count: usize,
    ) -> LinkPublicGenerators<E> {
        let pedersen_gens = (0..count)
            .map(|_| E::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let g1 = E::G1Projective::rand(rng).into_affine();
        let g2 = E::G2Projective::rand(rng).into_affine();
        LinkPublicGenerators {
            pedersen_gens,
            g1,
            g2,
        }
    }

    #[test]
    fn encrypt_and_snark_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let n = 4;
        let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);
        let link_gens = get_link_public_gens(&mut rng, n + 2);

        let msgs = vec![2, 47, 239, 155];
        let n = msgs.len() as u8;
        let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

        let circuit = BitsizeCheckCircuit::new(8, Some(4), None, false);
        let snark_srs =
            generate_srs::<Bls12_381, _, _>(circuit, &gens, link_gens.clone(), n, &mut rng)
                .unwrap();

        let g_i = &snark_srs.pk.vk.gamma_abc_g1[1..];
        let (sk, ek, dk) = keygen(
            &mut rng,
            4,
            &gens,
            g_i,
            &snark_srs.pk.delta_g1,
            &snark_srs.gamma_g1,
        );

        // Using the version of encrypt that outputs the sum X_i^r as well
        let (ct, r) = Encryption::encrypt_decomposed_message(&mut rng, msgs.clone(), &ek, &g_i);
        let x_r_sum =
            ek.X.iter()
                .fold(<Bls12_381 as PairingEngine>::G1Affine::zero(), |a, &b| {
                    a.add(b)
                })
                .mul(r)
                .into_affine();

        let (m_, nu) =
            Encryption::decrypt_to_chunks(&ct[0], &ct[1..n as usize + 1], &sk, &dk, &g_i, 8);

        assert_eq!(m_, msgs);

        // Create commitment randomness
        let v = Fr::rand(&mut rng);
        let link_v = Fr::rand(&mut rng);

        let circuit =
            BitsizeCheckCircuit::new(8, Some(4), Some(msgs_as_field_elems.clone()), false);

        let start = Instant::now();
        let proof_2 = protocol_2::create_proof(
            circuit.clone(),
            v.clone(),
            link_v.clone(),
            r.clone(),
            &snark_srs,
            &ek,
            &mut rng,
        )
        .unwrap();
        println!(
            "Time taken to create LegoGroth16 proof as per protocol 2 {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
        assert!(Encryption::verify_ciphertext_commitment(
            &ct[0],
            &ct[1..n as usize + 1],
            &ct[n as usize + 1],
            &ek,
            &gens
        ));
        let ct1 = CiphertextAlt {
            X_r: ct[0].clone(),
            enc_chunks: ct[1..n as usize + 1].to_vec().clone(),
            commitment: ct[n as usize + 1].clone(),
            X_r_sum: x_r_sum,
        };
        protocol_2::verify_proof(&pvk, &proof_2, &ct1).unwrap();
        println!(
            "Time taken to verify LegoGroth16 proof as per protocol 2 {:?}",
            start.elapsed()
        );

        verify_link_commitment(
            &pvk.vk.link_bases,
            &proof_2,
            &[],
            &msgs_as_field_elems,
            &link_v,
        )
        .unwrap();
        verify_commitment(&pvk.vk, &proof_2, &[], &msgs_as_field_elems, &v, &link_v).unwrap();

        let start = Instant::now();
        let proof_1 =
            protocol_1::create_proof(circuit, v, link_v, r, &snark_srs, &ek, &mut rng).unwrap();
        println!(
            "Time taken to create LegoGroth16 proof as per protocol 1 {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        let pvk = prepare_verifying_key::<Bls12_381>(&snark_srs.pk.vk);
        assert!(Encryption::verify_ciphertext_commitment(
            &ct[0],
            &ct[1..n as usize + 1],
            &ct[n as usize + 1],
            &ek,
            &gens
        ));
        let ct2 = Ciphertext {
            X_r: ct[0].clone(),
            enc_chunks: ct[1..n as usize + 1].to_vec().clone(),
            commitment: ct[n as usize + 1].clone(),
        };
        protocol_1::verify_proof(&pvk, &proof_1, &ct2).unwrap();
        println!(
            "Time taken to verify LegoGroth16 proof as per protocol 1 {:?}",
            start.elapsed()
        );

        verify_link_commitment(
            &pvk.vk.link_bases,
            &proof_1.proof,
            &[],
            &msgs_as_field_elems,
            &link_v,
        )
        .unwrap();
        verify_commitment(
            &pvk.vk,
            &proof_1.proof,
            &[],
            &msgs_as_field_elems,
            &v,
            &link_v,
        )
        .unwrap();
    }
}
