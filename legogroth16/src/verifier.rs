use crate::link::{PESubspaceSnark, SubspaceSnark};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField};

use super::{PreparedVerifyingKey, ProofWithLink, VerifyingKeyWithLink};

use ark_relations::r1cs::SynthesisError;

use crate::{error::Error, Proof, VerifyingKey};
use ark_ec::VariableBaseMSM;
use ark_std::{cfg_iter, vec, vec::Vec};
use core::ops::{AddAssign, Neg};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2),
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

/// Prepare proof inputs for use with [`verify_proof`], wrt the prepared
/// verification key `pvk` and instance public inputs.
pub fn prepare_inputs<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[E::ScalarField],
) -> crate::Result<E::G1> {
    if (public_inputs.len() + 1) > pvk.vk.gamma_abc_g1.len() {
        return Err(SynthesisError::MalformedVerifyingKey).map_err(|e| e.into());
    }

    if public_inputs.len() > 2 {
        let mut inp = Vec::with_capacity(1 + public_inputs.len());
        inp.push(E::ScalarField::one());
        inp.extend_from_slice(public_inputs);
        let inp = cfg_iter!(inp).map(|a| a.into_bigint()).collect::<Vec<_>>();
        Ok(E::G1::msm_bigint(&pvk.vk.gamma_abc_g1, &inp))
    } else {
        let mut d = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
            d.add_assign(&b.mul_bigint(i.into_bigint()));
        }
        Ok(d)
    }
}

/// Verify the proof of the Subspace Snark on the equality of openings of cp_link and proof.d
pub fn verify_link_proof<E: Pairing>(
    vk: &VerifyingKeyWithLink<E>,
    proof: &ProofWithLink<E>,
) -> crate::Result<()> {
    let commitments = vec![proof.link_d.clone(), proof.groth16_proof.d.clone()];
    PESubspaceSnark::<E>::verify(&vk.link_pp, &vk.link_vk, &commitments, &proof.link_pi)
        .map_err(|e| e.into())
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

    if E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?
        != pvk.alpha_g1_beta_g2
    {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

/// Verify a LegoGroth16 proof `proof` against the prepared verification key `pvk`
pub fn verify_proof<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::ScalarField],
) -> crate::Result<()> {
    verify_qap_proof(
        pvk,
        proof.a,
        proof.b,
        proof.c,
        calculate_d(pvk, proof, public_inputs)?,
    )
}

pub fn calculate_d<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::ScalarField],
) -> crate::Result<E::G1Affine> {
    let mut d = prepare_inputs(pvk, public_inputs)?;
    d += proof.d;
    Ok(d.into_affine())
}

/// Verify a LegoGroth16 proof `proof` against the prepared verification key `pvk`
pub fn verify_proof_incl_cp_link<E: Pairing>(
    pvk: &PreparedVerifyingKey<E>,
    vk: &VerifyingKeyWithLink<E>,
    proof: &ProofWithLink<E>,
    public_inputs: &[E::ScalarField],
) -> crate::Result<()> {
    verify_link_proof(vk, proof)?;
    verify_proof(pvk, &proof.groth16_proof, public_inputs)
}
