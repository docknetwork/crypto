use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_groth16::Proof;
use ark_std::{cfg_iter, format, ops::Mul, rand::Rng, string::ToString, vec::Vec};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    aggregation::{
        error::AggregationError,
        groth16::{
            aggregate_proofs as g16_aggregate_proofs, verifier::verify_tipp_mipp, AggregateProof,
        },
        srs::{PreparedProverSRS, VerifierSRS},
        utils::aggregate_public_inputs,
    },
    PreparedVerifyingKey, Proof as LegoProof,
};
use dock_crypto_utils::{
    ff::{powers, sum_of_powers},
    transcript::Transcript,
};

/// Since `proof.D` (commitment to witnesses) is needed for doing a Schnorr proof of knowledge and equality
/// when not using CP_link Snark, `proof.D` does not need to be used in an IPA and thus aggregation protocol
/// for Groth16 can be used with slight modification.
pub fn aggregate_proofs<E: Pairing, T: Transcript>(
    srs: impl Into<PreparedProverSRS<E>>,
    transcript: &mut T,
    proofs: &[LegoProof<E>],
) -> Result<(AggregateProof<E>, Vec<E::G1Affine>), AggregationError> {
    let mut g16_proofs = Vec::with_capacity(proofs.len());
    let mut d = Vec::with_capacity(proofs.len());
    for i in 0..proofs.len() {
        g16_proofs.push(Proof {
            a: proofs[i].a,
            b: proofs[i].b,
            c: proofs[i].c,
        });
        d.push(proofs[i].d);
    }
    Ok((g16_aggregate_proofs(srs, transcript, &g16_proofs)?, d))
}

pub fn verify_aggregate_proof<E: Pairing, R: Rng, T: Transcript>(
    ip_verifier_srs: &VerifierSRS<E>,
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    proof: &AggregateProof<E>,
    d: &[E::G1Affine],
    rng: &mut R,
    mut transcript: &mut T,
    pairing_check: Option<&mut RandomizedPairingChecker<E>>,
) -> Result<(), AggregationError> {
    proof.parsing_check()?;
    for pub_input in public_inputs {
        if (pub_input.len() + 1) > pvk.vk.gamma_abc_g1.len() {
            return Err(AggregationError::MalformedVerifyingKey);
        }
    }

    if public_inputs.len() != proof.tmipp.gipa.nproofs as usize {
        return Err(AggregationError::InvalidProof(format!(
            "public inputs len {} != number of proofs {}",
            public_inputs.len(),
            proof.tmipp.gipa.nproofs
        )));
    }

    // Random linear combination of proofs
    transcript.append(b"AB-commitment", &proof.com_ab);
    transcript.append(b"C-commitment", &proof.com_c);

    let r = transcript.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

    let mut c = RandomizedPairingChecker::new_using_rng(rng, true);
    let mut checker = pairing_check.unwrap_or_else(|| &mut c);

    let ver_srs_proj = ip_verifier_srs.to_projective();
    verify_tipp_mipp::<E, T>(
        &ver_srs_proj,
        proof,
        &r, // we give the extra r as it's not part of the proof itself - it is simply used on top for the groth16 aggregation
        &mut transcript,
        &mut checker,
    )?;

    let mut source1 = Vec::with_capacity(3);
    let mut source2 = Vec::with_capacity(3);
    let public_inputs_len = public_inputs
        .len()
        .try_into()
        .map_err(|_| AggregationError::PublicInputsTooLarge(public_inputs.len()))?;

    let r_powers = powers(&r, public_inputs_len);
    let r_sum = sum_of_powers::<E::ScalarField>(&r, public_inputs_len);

    // Check aggregate pairing product equation

    let alpha_g1_r_sum = pvk.vk.alpha_g1.mul(r_sum);
    source1.push(alpha_g1_r_sum.into_affine());
    source2.push(pvk.vk.beta_g2);

    let inp = aggregate_public_inputs(public_inputs, &r_powers, r_sum, &pvk.vk.gamma_abc_g1);
    let d_r = E::G1::msm_bigint(
        &d,
        &(cfg_iter!(r_powers)
            .map(|r| r.into_bigint())
            .collect::<Vec<_>>()),
    );

    source1.push((d_r + inp).into_affine());
    source2.push(pvk.vk.gamma_g2);

    source1.push(proof.z_c);
    source2.push(pvk.vk.delta_g2);

    checker.add_multiple_sources_and_target(&source1, &source2, &proof.z_ab);

    match checker.verify() {
        true => Ok(()),
        false => Err(AggregationError::InvalidProof(
            "Proof Verification Failed due to pairing checks".to_string(),
        )),
    }
}
