use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{batch_inversion, Field, PrimeField};
use ark_std::{
    cfg_iter, cfg_iter_mut, format,
    ops::{AddAssign, MulAssign},
    string::ToString,
    vec::Vec,
    Zero,
};

use ark_groth16::Proof;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::aggregation::{
    commitment::PairCommitment,
    error::AggregationError,
    key::{PreparedVKey, VKey, WKey},
};

use super::proof::{AggregateProof, GipaProof, TippMippProof};
use crate::aggregation::{
    srs::{PreparedProverSRS, ProverSRS},
    utils::{
        compress, inner_product_and_double_commitments, inner_product_and_single_commitments,
        prove_commitments,
    },
};
use dock_crypto_utils::{ff::powers, transcript::Transcript};

/// Aggregate `n` zkSnark proofs, where `n` must be a power of two.
/// WARNING: transcript_include represents everything that should be included in
/// the transcript from outside the boundary of this function. This is especially
/// relevant for ALL public inputs of ALL individual proofs. In the regular case,
/// one should input ALL public inputs from ALL proofs aggregated. However, IF ALL the
/// public inputs are **fixed, and public before the aggregation time**, then there is
/// no need to hash those. The reason we specify this extra assumption is because hashing
/// the public inputs from the decoded form can take quite some time depending on the
/// number of proofs and public inputs (+100ms in our case). In the case of Filecoin, the only
/// non-fixed part of the public inputs are the challenges derived from a seed. Even though this
/// seed comes from a random beacon, we are hashing this as a safety precaution.
pub fn aggregate_proofs<E: Pairing, T: Transcript>(
    srs: impl Into<PreparedProverSRS<E>>,
    transcript: &mut T,
    proofs: &[Proof<E>],
) -> Result<AggregateProof<E>, AggregationError> {
    if proofs.len() < 2 {
        return Err(AggregationError::InvalidProof(
            "invalid proof size < 2".to_string(),
        ));
    }
    if !proofs.len().is_power_of_two() {
        return Err(AggregationError::InvalidProof(
            "invalid proof size: not power of two".to_string(),
        ));
    }

    let srs = srs.into();
    if !srs.has_correct_len(proofs.len()) {
        return Err(AggregationError::InvalidSRS(
            format!("SRS len {} != proofs len {}", srs.len(), proofs.len()).to_string(),
        ));
    }
    // We first commit to A B and C - these commitments are what the verifier
    // will use later to verify the TIPP and MIPP proofs
    let a = proofs.iter().map(|proof| proof.a).collect::<Vec<_>>();
    let b = proofs.iter().map(|proof| proof.b).collect::<Vec<_>>();
    let c = proofs.iter().map(|proof| proof.c).collect::<Vec<_>>();

    let (vkey_prep, srs) = srs.extract_prepared();
    let b_prep = cfg_iter!(b)
        .map(|e| E::G2Prepared::from(*e))
        .collect::<Vec<_>>();

    // A and B are committed together in this scheme
    // T_AB, U_AB
    let com_ab = PairCommitment::<E>::double(vkey_prep.clone(), &srs.wkey, &a, b_prep)?;
    // T_C, U_C
    let com_c = PairCommitment::<E>::single(vkey_prep, &c)?;

    // Derive a random scalar to perform a linear combination of proofs
    transcript.append(b"AB-commitment", &com_ab);
    transcript.append(b"C-commitment", &com_c);
    let r = transcript.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

    // 1,r, r^2, r^3, r^4 ...
    let r_vec: Vec<E::ScalarField> = powers(
        &r,
        proofs
            .len()
            .try_into()
            .map_err(|_| AggregationError::TooManyProofs(proofs.len()))?,
    );
    // 1,r^-1, r^-2, r^-3
    let mut r_inv = r_vec.clone();
    batch_inversion(&mut r_inv);

    let r_repr = cfg_iter!(r_vec)
        .map(|r| r.into_bigint())
        .collect::<Vec<_>>();

    // B^{r}
    let b_r_proj = cfg_iter!(b)
        .zip(cfg_iter!(r_repr))
        .map(|(bi, ri)| bi.mul_bigint(*ri))
        .collect::<Vec<_>>();
    let b_r = E::G2::normalize_batch(&b_r_proj);

    // compute A * B^r for the verifier
    let z_ab = E::multi_pairing(&a, &b_r);
    // compute C^r for the verifier
    let z_c = E::G1::msm_bigint(&c, &r_repr).into_affine();

    // w^{r^{-1}}
    let wkey_r_inv = srs.wkey.scale(&r_inv)?;

    // we prove tipp and mipp using the same recursive loop
    let proof = prove_tipp_mipp(
        &srs,
        transcript,
        &a,
        &b_r,
        &c,
        &wkey_r_inv,
        &r_vec,
        &z_ab,
        &z_c,
    )?;

    Ok(AggregateProof {
        com_ab,
        com_c,
        z_ab,
        z_c,
        tmipp: proof,
    })
}

/// Proves a TIPP relation between A and B as well as a MIPP relation with C and
/// r. Commitment keys must be of size of A, B and C. In the context of Groth16
/// aggregation, we have that B = B^r and wkey is scaled by r^{-1}. The
/// commitment key v is used to commit to A and C recursively in GIPA such that
/// only one KZG proof is needed for v. In the original paper version, since the
/// challenges of GIPA would be different, two KZG proofs would be needed.
fn prove_tipp_mipp<E: Pairing, T: Transcript>(
    srs: &ProverSRS<E>,
    transcript: &mut T,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
    c: &[E::G1Affine],
    wkey: &WKey<E>, // scaled key w^r^-1
    r_vec: &[E::ScalarField],
    z_ab: &PairingOutput<E>,
    z_c: &E::G1Affine,
) -> Result<TippMippProof<E>, AggregationError> {
    let r_shift = r_vec[1].clone();
    // Run GIPA
    let (proof, mut challenges, mut challenges_inv) =
        gipa_tipp_mipp(transcript, a, b, c, &srs.vkey, &wkey, r_vec, z_ab, z_c)?;

    // Prove final commitment keys are wellformed
    // we reverse the transcript so the polynomial in kzg opening is constructed
    // correctly - the formula indicates x_{l-j}. Also for deriving KZG
    // challenge point, input must be the last challenge.
    challenges.reverse();
    challenges_inv.reverse();
    let r_inverse = r_shift.inverse().unwrap();

    // KZG challenge point
    transcript.append(b"kzg-challenge", &challenges[0]);
    transcript.append(b"vkey0", &proof.final_vkey.0);
    transcript.append(b"vkey1", &proof.final_vkey.1);
    transcript.append(b"wkey0", &proof.final_wkey.0);
    transcript.append(b"wkey1", &proof.final_wkey.1);
    let z = transcript.challenge_scalar::<E::ScalarField>(b"z-challenge");

    // Complete KZG proofs
    let (vkey_opening, wkey_opening) = prove_commitments::<E>(
        &srs.h_alpha_powers_table,
        &srs.h_beta_powers_table,
        &srs.g_alpha_powers_table,
        &srs.g_beta_powers_table,
        &challenges,
        &challenges_inv,
        &r_inverse,
        &z,
    )?;

    Ok(TippMippProof {
        gipa: proof,
        vkey_opening,
        wkey_opening,
    })
}

/// gipa_tipp_mipp performs the recursion of the GIPA protocol for TIPP and MIPP.
/// It returns a proof containing all intermediate committed values, as well as
/// the challenges generated necessary to do the polynomial commitment proof
/// later in TIPP.
fn gipa_tipp_mipp<E: Pairing>(
    transcript: &mut impl Transcript,
    a: &[E::G1Affine],
    b: &[E::G2Affine],
    c: &[E::G1Affine],
    vkey: &VKey<E>,
    wkey: &WKey<E>, // scaled key w^r^-1
    r: &[E::ScalarField],
    ip_ab: &PairingOutput<E>,
    agg_c: &E::G1Affine,
) -> Result<(GipaProof<E>, Vec<E::ScalarField>, Vec<E::ScalarField>), AggregationError> {
    // the values of vectors A and B rescaled at each step of the loop
    let (mut m_a, mut m_b) = (a.to_vec(), b.to_vec());

    // the values of vector C is rescaled at each step of the loop
    let mut m_c = c.to_vec();
    // the values of vector r is rescaled at each step of the loop
    let mut m_r = r.to_vec();

    // the values of the commitment keys rescaled at each step of the loop
    let (mut vkey, mut wkey) = (vkey.clone(), wkey.clone());

    // storing the values for including in the proof
    let mut comms_ab = Vec::new();
    let mut comms_c = Vec::new();
    let mut z_ab = Vec::new();
    let mut z_c = Vec::new();
    let mut challenges: Vec<E::ScalarField> = Vec::new();
    let mut challenges_inv: Vec<E::ScalarField> = Vec::new();

    transcript.append(b"inner-product-ab", ip_ab);
    transcript.append(b"comm-c", agg_c);
    let mut c_inv: E::ScalarField =
        transcript.challenge_scalar::<E::ScalarField>(b"first-challenge");
    let mut c = c_inv.inverse().unwrap();

    let mut i = 0;

    while m_a.len() > 1 {
        // recursive step
        // Recurse with problem of half size
        let split = m_a.len() / 2;

        // TIPP
        let (a_left, a_right) = m_a.split_at_mut(split);
        let (b_left, b_right) = m_b.split_at_mut(split);

        // MIPP
        // c[:n']   c[n':]
        let (c_left, c_right) = m_c.split_at_mut(split);

        // r[:n']   r[:n']
        let (r_left, r_right) = m_r.split_at_mut(split);

        let (vk_left, vk_right) = vkey.split(split);
        let (wk_left, wk_right) = wkey.split(split);

        let vk_left_prep = PreparedVKey::from(&vk_left);
        let vk_right_prep = PreparedVKey::from(&vk_right);

        let b_left_prep = cfg_iter!(b_left)
            .map(|e| E::G2Prepared::from(*e))
            .collect::<Vec<_>>();
        let b_right_prep = cfg_iter!(b_right)
            .map(|e| E::G2Prepared::from(*e))
            .collect::<Vec<_>>();

        let r_left_bi = cfg_iter!(r_left)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let r_right_bi = cfg_iter!(r_right)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        // See section 3.3 for paper version with equivalent names

        // TIPP part
        let (zab_l, zab_r, tab_l, tab_r) = inner_product_and_double_commitments(
            &a_left,
            &a_right,
            b_left_prep,
            b_right_prep,
            &wk_left,
            &wk_right,
            vk_left_prep.clone(),
            vk_right_prep.clone(),
        );

        // MIPP part for C
        let (zc_l, zc_r, tuc_l, tuc_r) = inner_product_and_single_commitments(
            &c_left,
            &c_right,
            &r_left_bi,
            &r_right_bi,
            vk_left_prep.clone(),
            vk_right_prep.clone(),
        );

        // Fiat-Shamir challenge
        // combine both TIPP and MIPP transcript
        if i == 0 {
            // already generated c_inv and c outside of the loop
        } else {
            transcript.append(b"c_inv", &c_inv);
            transcript.append(b"zab_l", &zab_l);
            transcript.append(b"zab_r", &zab_r);
            transcript.append(b"zc_l", &zc_l);
            transcript.append(b"zc_r", &zc_r);
            transcript.append(b"tab_l", &tab_l);
            transcript.append(b"tab_r", &tab_r);
            transcript.append(b"tuc_l", &tuc_l);
            transcript.append(b"tuc_r", &tuc_r);
            c_inv = transcript.challenge_scalar::<E::ScalarField>(b"challenge_i");

            // Optimization for multiexponentiation to rescale G2 elements with
            // 128-bit challenge Swap 'c' and 'c_inv' since can't control bit size
            // of c_inv
            c = c_inv.inverse().unwrap();
        }

        // Set up values for next step of recursion
        // A[:n'] + A[n':] ^ x
        compress(&mut m_a, split, &c);
        // B[:n'] + B[n':] ^ x^-1
        compress(&mut m_b, split, &c_inv);

        // c[:n'] + c[n':]^x
        compress(&mut m_c, split, &c);

        cfg_iter_mut!(r_left)
            .zip(cfg_iter_mut!(r_right))
            .for_each(|(r_l, r_r)| {
                // r[:n'] + r[n':]^x^-1
                r_r.mul_assign(&c_inv);
                r_l.add_assign(r_r.clone());
            });
        let len = r_left.len();
        m_r.resize(len, E::ScalarField::zero()); // shrink to new size

        // v_left + v_right^x^-1
        vkey = vk_left.compress(&vk_right, &c_inv)?;
        // w_left + w_right^x
        wkey = wk_left.compress(&wk_right, &c)?;

        comms_ab.push((tab_l, tab_r));
        comms_c.push((tuc_l, tuc_r));
        z_ab.push((zab_l, zab_r));
        z_c.push((zc_l, zc_r));
        challenges.push(c);
        challenges_inv.push(c_inv);

        i += 1;
    }

    assert!(m_a.len() == 1 && m_b.len() == 1);
    assert!(m_c.len() == 1 && m_r.len() == 1);
    assert!(vkey.a.len() == 1 && vkey.b.len() == 1);
    assert!(wkey.a.len() == 1 && wkey.b.len() == 1);

    let (final_a, final_b, final_c) = (m_a[0], m_b[0], m_c[0]);
    let (final_vkey, final_wkey) = (vkey.first(), wkey.first());

    Ok((
        GipaProof {
            nproofs: a.len() as u32, // TODO: ensure u32
            comms_ab,
            comms_c,
            z_ab,
            z_c,
            final_a,
            final_b,
            final_c,
            final_vkey,
            final_wkey,
        },
        challenges,
        challenges_inv,
    ))
}
