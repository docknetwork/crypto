//! Using SAVER with LegoGroth16

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, Boolean, EqGadget};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::ops::{AddAssign, Sub};
use ark_std::{
    io::{Read, Write},
    rand::{Rng, RngCore},
    vec::Vec,
    UniformRand,
};
use legogroth16::{
    create_random_proof, generate_parameters, verify_link_proof, PreparedVerifyingKey, Proof,
    VerifyingKey,
};

use crate::setup::{EncryptionKey, Generators};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: PairingEngine> {
    /// LegoGroth16's proving key
    pub pk: legogroth16::ProvingKey<E>,
    /// The element `-gamma * G` in `E::G1`.
    pub gamma_g1: E::G1Affine,
}

/*#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub proof: legogro16::Proof<E>,
    pub v_eta_gamma_inv: E::G1Affine,
}*/

/// These parameters are needed for setting up keys for encryption/decryption
pub fn get_gs_for_encryption<E: PairingEngine>(vk: &VerifyingKey<E>) -> &[E::G1Affine] {
    &vk.gamma_abc_g1[1..]
}

pub fn generate_crs<E: PairingEngine, R: RngCore, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
    gens: &Generators<E>,
    pedersen_bases: Vec<E::G1Affine>,
    bit_blocks_count: u8,
    rng: &mut R,
) -> R1CSResult<ProvingKey<E>> {
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let gamma = E::Fr::rand(rng);
    let delta = E::Fr::rand(rng);
    let eta = E::Fr::rand(rng);

    let g1_generator = gens.G.into_projective();
    let neg_gamma_g1 = g1_generator.mul((-gamma).into_repr());

    let pk = generate_parameters::<E, C, R>(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        eta,
        g1_generator,
        gens.H.into_projective(),
        pedersen_bases,
        bit_blocks_count as usize,
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
    v: E::Fr,
    link_v: E::Fr,
    r: E::Fr,
    pk: &ProvingKey<E>,
    encryption_key: &EncryptionKey<E>,
    rng: &mut R,
) -> R1CSResult<Proof<E>>
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

    /*
    let new_proof = Proof {
        proof,
        v_eta_gamma_inv: pk.pk.vk.eta_gamma_inv_g1.mul(v).into_affine(),
    };*/
    Ok(proof)
}

/*pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    ciphertext: &[E::G1Affine],
) -> R1CSResult<bool> {
    // TODO: Return error indicating what failed rather than a boolean
    let link_verified = verify_link_proof(&pvk.vk, &proof.proof);
    if !link_verified {
        return Ok(false);
    }
    let mut d = ciphertext[0].into_projective();
    for c in ciphertext[1..ciphertext.len() - 1].iter() {
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

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_g1_beta_g2)
}*/

pub fn verify_proof_1<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    ciphertext: &[E::G1Affine],
    x_r_sum: &E::G1Affine, // r*X_1 + r*X_2 + .. + r*X_n
) -> R1CSResult<bool> {
    // TODO: Return error indicating what failed rather than a boolean
    let link_verified = verify_link_proof(&pvk.vk, &proof);
    if !link_verified {
        return Ok(false);
    }

    // Get v * (eta/gamma)*G
    // proof.d = G[0] + m1*G[1] + m2*G[2] + ... + v * (eta/gamma)*G
    // ct_sum = r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n]
    let mut ct_sum = ciphertext[1].into_projective();
    for c in ciphertext[2..ciphertext.len() - 1].iter() {
        ct_sum.add_assign_mixed(c)
    }
    // ct_sum_plus_g_0 = ct_sum + G[0]
    let ct_sum_plus_g_0 = ct_sum.add_mixed(&pvk.vk.gamma_abc_g1[0]);
    // ct_sum_plus_g_0_minus_x_r_sum = ct_sum + G[0] - x_r_sum
    // = r*X_1 + m1*G[1] + r*X_2 + m2*G[2] + .. + r*X_n + mn*G[n] + G[0] - (r*X_1 + r*X_2 + .. + r*X_n)
    // = G[0] + m1*G[1] + m2*G[2] + ... + mn*G[n]
    let ct_sum_plus_g_0_minus_x_r_sum = ct_sum_plus_g_0.sub(x_r_sum.into_projective());

    // proof.d - ct_sum_plus_g_0_minus_x_r_sum
    // = G[0] + m1*G[1] + m2*G[2] + ... + v * (eta/gamma)*G - (G[0] + m1*G[1] + m2*G[2] + ... + mn*G[n])
    // = v * (eta/gamma)*G
    let v_eta_gamma_inv = proof
        .d
        .into_projective()
        .sub(&ct_sum_plus_g_0_minus_x_r_sum);

    let mut d = ct_sum_plus_g_0;
    d.add_assign_mixed(&ciphertext[0]);
    d.add_assign(&v_eta_gamma_inv);

    let qap = E::miller_loop(
        [
            (proof.a.into(), proof.b.into()),
            (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
            (d.into_affine().into(), pvk.gamma_g2_neg_pc.clone()),
        ]
        .iter(),
    );

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_g1_beta_g2)
}

#[derive(Clone)]
pub struct BitsizeCheckCircuit<F: PrimeField> {
    pub required_bit_size: u8,
    // TODO: Make it fixed
    pub values_count: u8,
    pub values: Option<Vec<F>>,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for BitsizeCheckCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let values = match self.values {
            Some(vals) => vals.into_iter().map(|v| Some(v)).collect::<Vec<_>>(),
            _ => (0..self.values_count).map(|_| None).collect::<Vec<_>>(),
        };

        // Allocate variables for main witnesses (`values`) first as they need to be in the commitment
        let mut vars = Vec::with_capacity(values.len());
        for value in values {
            vars.push(FpVar::new_variable(
                cs.clone(),
                || value.ok_or(SynthesisError::AssignmentMissing),
                AllocationMode::Witness,
            )?);
        }

        // For each variable, ensure that only last `self.required_bit_size` _may_ be set, rest *must* be unset
        for v in vars {
            let bits = v.to_bits_be()?;
            let modulus_bits = ConstraintF::size_in_bits();
            let zero_bits = modulus_bits - self.required_bit_size as usize;
            for b in bits[..zero_bits].iter() {
                b.enforce_equal(&Boolean::constant(false))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use crate::encryption::{
        decrypt_to_chunks, encrypt_decomposed_message_alt, verify_ciphertext_commitment,
    };
    use crate::setup::keygen;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use legogroth16::prepare_verifying_key;
    use legogroth16::prover::{verify_commitment, verify_link_commitment};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn encrypt_and_snark_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let n = 4;
        let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);

        let pedersen_bases = (0..n + 2)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let msgs = vec![2, 47, 239, 155];
        let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

        let circuit = BitsizeCheckCircuit {
            required_bit_size: 8,
            values_count: 4,
            values: None,
        };
        let params =
            generate_crs::<Bls12_381, _, _>(circuit, &gens, pedersen_bases.clone(), n, &mut rng)
                .unwrap();

        let g_i = &params.pk.vk.gamma_abc_g1[1..];
        let (sk, ek, dk) = keygen(
            &mut rng,
            4,
            &gens,
            g_i,
            &params.pk.delta_g1,
            &params.gamma_g1,
        );

        // Using the version of encrypt that outputs the sum X_i^r as well
        let (ct, x_r_sum, r) = encrypt_decomposed_message_alt(&mut rng, msgs.clone(), &ek, &g_i);
        assert_eq!(ct.len(), msgs.len() + 2);

        let (m_, nu) = decrypt_to_chunks(&ct, &sk, &dk, &g_i, 8);

        assert_eq!(m_, msgs);

        // Create commitment randomness
        let v = Fr::rand(&mut rng);
        let link_v = Fr::rand(&mut rng);

        let circuit = BitsizeCheckCircuit {
            required_bit_size: 8,
            values_count: 4,
            values: Some(msgs_as_field_elems.clone()),
        };

        let start = Instant::now();
        let proof = create_proof(circuit, v, link_v, r, &params, &ek, &mut rng).unwrap();
        println!(
            "Time taken to create LegoGroth16 proof {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        let pvk = prepare_verifying_key::<Bls12_381>(&params.pk.vk);
        assert!(verify_ciphertext_commitment(&ct, &ek, &gens));
        // assert!(verify_proof(&pvk, &proof, &ct).unwrap());
        assert!(verify_proof_1(&pvk, &proof, &ct, &x_r_sum).unwrap());
        println!(
            "Time taken to verify LegoGroth16 proof {:?}",
            start.elapsed()
        );

        assert!(verify_link_commitment(
            &pvk.vk.link_bases,
            &proof,
            &[],
            &msgs_as_field_elems,
            &link_v
        )
        .unwrap());
        assert!(
            verify_commitment(&pvk.vk, &proof, &[], &msgs_as_field_elems, &v, &link_v).unwrap()
        );
    }
}
