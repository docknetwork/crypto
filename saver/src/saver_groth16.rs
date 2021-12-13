use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar, Boolean, EqGadget};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    format,
    io::{Read, Write},
    rand::{Rng, RngCore},
    vec,
    vec::Vec,
    UniformRand,
};

use ark_groth16::{
    create_random_proof, generate_parameters, PreparedVerifyingKey, Proof, VerifyingKey,
};
use std::ops::AddAssign;

use crate::setup::{EncryptionKey, Generators};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: PairingEngine> {
    /// Groth16's proving key
    pub pk: ark_groth16::ProvingKey<E>,
    /// The element `-gamma * G` in `E::G1`.
    pub gamma_g1: E::G1Affine,
}

pub fn get_gs_for_encryption<E: PairingEngine>(vk: &VerifyingKey<E>) -> &[E::G1Affine] {
    &vk.gamma_abc_g1[1..]
}

pub fn generate_crs<E: PairingEngine, R: RngCore, C: ConstraintSynthesizer<E::Fr>>(
    circuit: C,
    gens: &Generators<E>,
    rng: &mut R,
) -> R1CSResult<ProvingKey<E>> {
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

pub fn create_proof<E, C, R>(
    circuit: C,
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
    ciphertext: &[E::G1Affine],
) -> R1CSResult<bool> {
    let mut d = ciphertext[0].into_projective();
    for c in ciphertext[1..ciphertext.len() - 1].iter() {
        d.add_assign(c.into_projective())
    }
    // TODO: CRS should only contain one element in `gamma_abc_g1` i.e. `gamma_abc_g1[0]` as the
    // rest of the values are not needed.

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
                AllocationMode::Input,
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
    use crate::encryption::{decrypt_to_chunks, encrypt_decomposed_message, ver_enc};
    use crate::setup::keygen;
    use ark_bls12_381::Bls12_381;
    use ark_ec::group::Group;
    use ark_groth16::prepare_verifying_key;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn encrypt_and_snark_verification() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let n = 4;
        let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);

        let msgs = vec![2, 47, 239, 155];
        let msgs_as_field_elems = msgs.iter().map(|m| Fr::from(*m as u64)).collect::<Vec<_>>();

        let circuit = BitsizeCheckCircuit {
            required_bit_size: 8,
            values_count: 4,
            values: None,
        };
        let params = generate_crs::<Bls12_381, _, _>(circuit, &gens, &mut rng).unwrap();

        let g_i = &params.pk.vk.gamma_abc_g1[1..];
        let (sk, ek, dk) = keygen(
            &mut rng,
            4,
            &gens,
            g_i,
            &params.pk.delta_g1,
            &params.gamma_g1,
        );

        let (ct, r) = encrypt_decomposed_message(&mut rng, msgs.clone(), &ek, &g_i);
        assert_eq!(ct.len(), msgs.len() + 2);

        let (m_, nu) = decrypt_to_chunks(&ct, &sk, &dk, &g_i, 8);

        assert_eq!(m_, msgs);

        let circuit = BitsizeCheckCircuit {
            required_bit_size: 8,
            values_count: 4,
            values: Some(msgs_as_field_elems.clone()),
        };

        let start = Instant::now();
        let proof = create_proof(circuit, r, &params, &ek, &mut rng).unwrap();
        println!("Time taken to create Groth16 proof {:?}", start.elapsed());

        let start = Instant::now();
        assert!(ver_enc(&ct, &ek, &gens));
        let pvk = prepare_verifying_key::<Bls12_381>(&params.pk.vk);
        assert!(verify_proof(&pvk, &proof, &ct).unwrap());
        println!("Time taken to verify Groth16 proof {:?}", start.elapsed());
    }
}
