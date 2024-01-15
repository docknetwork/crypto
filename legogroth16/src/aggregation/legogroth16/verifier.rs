use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, Group, VariableBaseMSM,
};
use ark_ff::{Field, PrimeField};
use ark_std::{
    cfg_iter, format,
    ops::{AddAssign, Mul},
    rand::Rng,
    vec,
    vec::Vec,
    One, Zero,
};
use dock_crypto_utils::randomized_pairing_check::RandomizedPairingChecker;

use crate::PreparedVerifyingKey;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::aggregation::{
    srs::{VerifierSRS, VerifierSRSProjective},
    utils::{final_verification_check, verify_kzg},
};

use crate::aggregation::{
    commitment::PairCommitment, error::AggregationError,
    kzg::polynomial_evaluation_product_form_from_transcript,
};
use dock_crypto_utils::transcript::Transcript;

use super::proof::AggregateLegoProof;

/// Verifies the aggregated proofs thanks to the LegoGroth16 verifying key, the
/// verifier SRS from the aggregation scheme, all the public inputs of the
/// proofs and the aggregated proof.
///
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
pub fn verify_aggregate_proof<E: Pairing, R: Rng, T: Transcript>(
    ip_verifier_srs: &VerifierSRS<E>,
    pvk: &PreparedVerifyingKey<E>,
    public_inputs: &[Vec<E::ScalarField>],
    proof: &AggregateLegoProof<E>,
    mut rng: R,
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
    transcript.append(b"D-commitment", &proof.com_d);

    let r = transcript.challenge_scalar::<E::ScalarField>(b"r-random-fiatshamir");

    let mut c = RandomizedPairingChecker::new_using_rng(&mut rng, true);
    let mut checker = pairing_check.unwrap_or_else(|| &mut c);

    let ver_srs_proj = ip_verifier_srs.to_projective();
    verify_tipp_mipp::<E, T>(
        &ver_srs_proj,
        proof,
        &r, // we give the extra r as it's not part of the proof itself - it is simply used on top for the groth16 aggregation
        &mut transcript,
        &mut checker,
    )?;

    let mut source1 = Vec::with_capacity(4);
    let mut source2 = Vec::with_capacity(4);

    source1.push(proof.z_d);
    source2.push(pvk.vk.gamma_g2);

    final_verification_check(
        source1,
        source2,
        proof.z_c.clone(),
        &proof.z_ab,
        &r,
        public_inputs,
        &pvk.vk.alpha_g1,
        pvk.vk.beta_g2,
        pvk.vk.gamma_g2,
        pvk.vk.delta_g2,
        &pvk.vk.gamma_abc_g1,
        &mut checker,
    )
}

/// verify_tipp_mipp returns a pairing equation to check the tipp proof.  $r$ is
/// the randomness used to produce a random linear combination of A and B and
/// used in the MIPP part with C
pub fn verify_tipp_mipp<E: Pairing, T: Transcript>(
    v_srs: &VerifierSRSProjective<E>,
    proof: &AggregateLegoProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut T,
    pairing_checker: &mut RandomizedPairingChecker<E>,
) -> Result<(), AggregationError> {
    // (T,U), Z for TIPP and MIPP  and all challenges
    let (final_res, final_r, challenges, challenges_inv) =
        gipa_verify_tipp_mipp(&proof, r_shift, transcript);

    // KZG challenge point
    transcript.append(b"kzg-challenge", &challenges[0]);
    transcript.append(b"vkey0", &proof.tmipp.gipa.final_vkey.0);
    transcript.append(b"vkey1", &proof.tmipp.gipa.final_vkey.1);
    transcript.append(b"wkey0", &proof.tmipp.gipa.final_wkey.0);
    transcript.append(b"wkey1", &proof.tmipp.gipa.final_wkey.1);
    let c = transcript.challenge_scalar::<E::ScalarField>(b"z-challenge");

    verify_kzg(
        v_srs,
        &proof.tmipp.gipa.final_vkey,
        &proof.tmipp.vkey_opening,
        &proof.tmipp.gipa.final_wkey,
        &proof.tmipp.wkey_opening,
        &challenges,
        &challenges_inv,
        &r_shift.inverse().unwrap(),
        &c,
        pairing_checker,
    );

    // We create a sequence of pairing tuple that we aggregate together at
    // the end to perform only once the final exponentiation.

    let b_prep = E::G2Prepared::from(proof.tmipp.gipa.final_b);
    let v_0_prep = E::G2Prepared::from(proof.tmipp.gipa.final_vkey.0);
    let v_1_prep = E::G2Prepared::from(proof.tmipp.gipa.final_vkey.1);

    // TIPP
    // z = e(A,B)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_a],
        [b_prep.clone()],
        &final_res.zab,
    );
    //  final_aB.0 = T = e(A,v1)e(w1,B)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_a, proof.tmipp.gipa.final_wkey.0],
        [v_0_prep.clone(), b_prep.clone()],
        &final_res.tab,
    );

    //  final_aB.1 = U = e(A,v2)e(w2,B)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_a, proof.tmipp.gipa.final_wkey.1],
        [v_1_prep.clone(), b_prep],
        &final_res.uab,
    );

    // MIPP for C
    // Verify base inner product commitment
    // Z ==  c ^ r
    let final_zc = proof.tmipp.gipa.final_c.mul(final_r);
    // Check commitment correctness
    // T = e(C,v1)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_c],
        [v_0_prep.clone()],
        &final_res.tc,
    );
    // U = e(C,v2)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_c],
        [v_1_prep.clone()],
        &final_res.uc,
    );

    // MIPP for D
    // Verify base inner product commitment
    // Z ==  D ^ r
    let final_zd = proof.tmipp.gipa.final_d.mul(final_r);
    // Check commitment correctness
    // T = e(D,v1)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_d],
        [v_0_prep],
        &final_res.td,
    );
    // U = e(D,v2)
    pairing_checker.add_multiple_sources_and_target(
        &[proof.tmipp.gipa.final_d],
        [v_1_prep],
        &final_res.ud,
    );

    if final_zc != final_res.zc {
        return Err(AggregationError::InvalidProof(format!(
            "tipp verify: INVALID final_z check for C {} vs {}",
            final_zc, final_res.zc
        )));
    }
    if final_zd != final_res.zd {
        return Err(AggregationError::InvalidProof(format!(
            "tipp verify: INVALID final_z check for D {} vs {}",
            final_zd, final_res.zd
        )));
    }
    Ok(())
}

/// gipa_verify_tipp_mipp recurse on the proof and statement and produces the final
/// values to be checked by TIPP and MIPP verifier, namely, for TIPP for example:
/// * T,U: the final commitment values of A and B
/// * Z the final product between A and B.
/// * Challenges are returned in inverse order as well to avoid
/// repeating the operation multiple times later on.
/// * There are T,U,Z vectors as well for the MIPP relationship. Both TIPP and
/// MIPP share the same challenges however, enabling to re-use common operations
/// between them, such as the KZG proof for commitment keys.
pub fn gipa_verify_tipp_mipp<E: Pairing, T: Transcript>(
    proof: &AggregateLegoProof<E>,
    r_shift: &E::ScalarField,
    transcript: &mut T,
) -> (
    GipaTUZ<E>,
    E::ScalarField,
    Vec<E::ScalarField>,
    Vec<E::ScalarField>,
) {
    let gipa = &proof.tmipp.gipa;
    // COM(A,B) = PROD e(A,B) given by prover
    let comms_ab = &gipa.comms_ab;
    // COM(C,r) = SUM C^r given by prover
    let comms_c = &gipa.comms_c;
    let comms_d = &gipa.comms_d;
    // Z vectors coming from the GIPA proofs
    let zs_ab = &gipa.z_ab;
    let zs_c = &gipa.z_c;
    let zs_d = &gipa.z_d;

    let mut challenges = Vec::new();
    let mut challenges_inv = Vec::new();

    transcript.append(b"inner-product-ab", &proof.z_ab);
    transcript.append(b"comm-c", &proof.z_c);
    transcript.append(b"comm-d", &proof.z_d);
    let mut c_inv: E::ScalarField =
        transcript.challenge_scalar::<E::ScalarField>(b"first-challenge");
    let mut c = c_inv.inverse().unwrap();

    // We first generate all challenges as this is the only consecutive process
    // that can not be parallelized then we scale the commitments in a
    // parallelized way
    for (i, (((comm_ab, z_ab), (comm_c, z_c)), (comm_d, z_d))) in comms_ab
        .iter()
        .zip(zs_ab.iter())
        .zip(comms_c.iter().zip(zs_c.iter()))
        .zip(comms_d.iter().zip(zs_d.iter()))
        .enumerate()
    {
        let (tab_l, tab_r) = comm_ab;
        let (tuc_l, tuc_r) = comm_c;
        let (tud_l, tud_r) = comm_d;
        let (zab_l, zab_r) = z_ab;
        let (zc_l, zc_r) = z_c;
        let (zd_l, zd_r) = z_d;

        // Fiat-Shamir challenge
        if i == 0 {
            // already generated c_inv and c outside of the loop
        } else {
            transcript.append(b"c_inv", &c_inv);
            transcript.append(b"zab_l", zab_l);
            transcript.append(b"zab_r", zab_r);
            transcript.append(b"zc_l", zc_l);
            transcript.append(b"zc_r", zc_r);
            transcript.append(b"zd_l", zd_l);
            transcript.append(b"zd_r", zd_r);
            transcript.append(b"tab_l", tab_l);
            transcript.append(b"tab_r", tab_r);
            transcript.append(b"tuc_l", tuc_l);
            transcript.append(b"tuc_r", tuc_r);
            transcript.append(b"tud_l", tud_l);
            transcript.append(b"tud_r", tud_r);
            c_inv = transcript.challenge_scalar::<E::ScalarField>(b"challenge_i");
            c = c_inv.inverse().unwrap();
        }
        challenges.push(c);
        challenges_inv.push(c_inv);
    }

    // output of the pair commitment T and U in TIPP -> COM((v,w),A,B)
    let PairCommitment { t: t_ab, u: u_ab } = proof.com_ab.clone();
    let z_ab = proof.z_ab; // in the end must be equal to Z = A^r * B

    // COM(v,C)
    let PairCommitment { t: t_c, u: u_c } = proof.com_c.clone();
    let z_c = proof.z_c.into_group(); // in the end must be equal to Z = C^r

    // COM(v,D)
    let PairCommitment { t: t_d, u: u_d } = proof.com_d.clone();
    let z_d = proof.z_d.into_group(); // in the end must be equal to Z = D^r

    let mut final_res = GipaTUZ {
        tab: t_ab,
        uab: u_ab,
        zab: z_ab,
        tc: t_c,
        uc: u_c,
        zc: z_c,
        td: t_d,
        ud: u_d,
        zd: z_d,
    };

    // we first multiply each entry of the Z U and L vectors by the respective
    // challenges independently
    // Since at the end we want to multiple all "t" values together, we do
    // multiply all of them in parallel and then merge then back at the end.
    // same for u and z.
    enum Op<'a, E: Pairing> {
        TAB(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        UAB(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        ZAB(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        TC(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        UC(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        TD(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
        UD(&'a PairingOutput<E>, <E::ScalarField as PrimeField>::BigInt),
    }

    let z_s = cfg_iter!(challenges)
        .zip(cfg_iter!(challenges_inv))
        .flat_map(|(c, c_inv)| [c.into_bigint(), c_inv.into_bigint()])
        .collect::<Vec<_>>();

    let zc_b = cfg_iter!(zs_c).flat_map(|t| [t.0, t.1]).collect::<Vec<_>>();
    let zd_b = cfg_iter!(zs_d).flat_map(|t| [t.0, t.1]).collect::<Vec<_>>();

    final_res.zc += E::G1::msm_bigint(&zc_b, z_s.as_slice());
    final_res.zd += E::G1::msm_bigint(&zd_b, z_s.as_slice());

    let iters = cfg_iter!(comms_ab)
        .zip(cfg_iter!(zs_ab))
        .zip(cfg_iter!(comms_c))
        .zip(cfg_iter!(comms_d))
        .zip(cfg_iter!(challenges).zip(cfg_iter!(challenges_inv)))
        .flat_map(|((((comm_ab, z_ab), comm_c), comm_d), (c, c_inv))| {
            // T and U values for right and left for AB part
            let (PairCommitment { t: tab_l, u: uab_l }, PairCommitment { t: tab_r, u: uab_r }) =
                comm_ab;
            let (zab_l, zab_r) = z_ab;

            // T and U values for right and left for C part
            let (PairCommitment { t: tc_l, u: uc_l }, PairCommitment { t: tc_r, u: uc_r }) = comm_c;

            // T and U values for right and left for D part
            let (PairCommitment { t: td_l, u: ud_l }, PairCommitment { t: td_r, u: ud_r }) = comm_d;

            let c_repr = c.into_bigint();
            let c_inv_repr = c_inv.into_bigint();

            // we multiple left side by x and right side by x^-1
            vec![
                Op::TAB::<E>(tab_l, c_repr),
                Op::TAB(tab_r, c_inv_repr),
                Op::UAB(uab_l, c_repr),
                Op::UAB(uab_r, c_inv_repr),
                Op::ZAB(zab_l, c_repr),
                Op::ZAB(zab_r, c_inv_repr),
                Op::TC::<E>(tc_l, c_repr),
                Op::TC(tc_r, c_inv_repr),
                Op::UC(uc_l, c_repr),
                Op::UC(uc_r, c_inv_repr),
                Op::TD::<E>(td_l, c_repr),
                Op::TD(td_r, c_inv_repr),
                Op::UD(ud_l, c_repr),
                Op::UD(ud_r, c_inv_repr),
            ]
        });

    #[cfg(feature = "parallel")]
    let res = iters
        .fold(GipaTUZ::<E>::default, |mut res, op: Op<E>| {
            match op {
                Op::TAB(tx, c) => {
                    let tx: PairingOutput<E> = tx.mul_bigint(c);
                    res.tab.add_assign(&tx);
                }
                Op::UAB(ux, c) => {
                    let ux: PairingOutput<E> = ux.mul_bigint(c);
                    res.uab.add_assign(&ux);
                }
                Op::ZAB(zx, c) => {
                    let zx: PairingOutput<E> = zx.mul_bigint(c);
                    res.zab.add_assign(&zx);
                }

                Op::TC(tx, c) => {
                    let tx: PairingOutput<E> = tx.mul_bigint(c);
                    res.tc.add_assign(&tx);
                }
                Op::UC(ux, c) => {
                    let ux: PairingOutput<E> = ux.mul_bigint(c);
                    res.uc.add_assign(&ux);
                }

                Op::TD(tx, d) => {
                    let tx: PairingOutput<E> = tx.mul_bigint(d);
                    res.td.add_assign(&tx);
                }
                Op::UD(ux, d) => {
                    let ux: PairingOutput<E> = ux.mul_bigint(d);
                    res.ud.add_assign(&ux);
                }
            }
            res
        })
        .reduce(GipaTUZ::default, |mut acc_res, res| {
            acc_res.merge(&res);
            acc_res
        });

    #[cfg(not(feature = "parallel"))]
    let res = iters.fold(GipaTUZ::<E>::default(), |mut res, op: Op<E>| {
        match op {
            Op::TAB(tx, c) => {
                let tx: PairingOutput<E> = tx.mul_bigint(c);
                res.tab.add_assign(&tx);
            }
            Op::UAB(ux, c) => {
                let ux: PairingOutput<E> = ux.mul_bigint(c);
                res.uab.add_assign(&ux);
            }
            Op::ZAB(zx, c) => {
                let zx: PairingOutput<E> = zx.mul_bigint(c);
                res.zab.add_assign(&zx);
            }

            Op::TC(tx, c) => {
                let tx: PairingOutput<E> = tx.mul_bigint(c);
                res.tc.add_assign(&tx);
            }
            Op::UC(ux, c) => {
                let ux: PairingOutput<E> = ux.mul_bigint(c);
                res.uc.add_assign(&ux);
            }

            Op::TD(tx, d) => {
                let tx: PairingOutput<E> = tx.mul_bigint(d);
                res.td.add_assign(&tx);
            }
            Op::UD(ux, d) => {
                let ux: PairingOutput<E> = ux.mul_bigint(d);
                res.ud.add_assign(&ux);
            }
        }
        res
    });

    // we reverse the order because the polynomial evaluation routine expects
    // the challenges in reverse order.Doing it here allows us to compute the final_r
    // in log time. Challenges are used as well in the KZG verification checks.
    challenges.reverse();
    challenges_inv.reverse();

    let ref_final_res = &mut final_res;
    let ref_challenges_inv = &challenges_inv;

    ref_final_res.merge(&res);
    let final_r = polynomial_evaluation_product_form_from_transcript(
        ref_challenges_inv,
        r_shift,
        &E::ScalarField::one(),
    );

    (final_res, final_r, challenges, challenges_inv)
}

/// Keeps track of the variables that have been sent by the prover and must
/// be multiplied together by the verifier. Both MIPP and TIPP are merged
/// together.
pub struct GipaTUZ<E: Pairing> {
    pub tab: PairingOutput<E>,
    pub uab: PairingOutput<E>,
    pub zab: PairingOutput<E>,
    pub tc: PairingOutput<E>,
    pub uc: PairingOutput<E>,
    pub zc: E::G1,
    pub td: PairingOutput<E>,
    pub ud: PairingOutput<E>,
    pub zd: E::G1,
}

impl<E: Pairing> Default for GipaTUZ<E> {
    fn default() -> Self {
        Self {
            tab: PairingOutput::<E>::zero(),
            uab: PairingOutput::<E>::zero(),
            zab: PairingOutput::<E>::zero(),
            tc: PairingOutput::<E>::zero(),
            uc: PairingOutput::<E>::zero(),
            zc: E::G1::zero(),
            td: PairingOutput::<E>::zero(),
            ud: PairingOutput::<E>::zero(),
            zd: E::G1::zero(),
        }
    }
}

impl<E: Pairing> GipaTUZ<E> {
    pub fn merge(&mut self, other: &Self) {
        self.tab.add_assign(&other.tab);
        self.uab.add_assign(&other.uab);
        self.zab.add_assign(&other.zab);
        self.tc.add_assign(&other.tc);
        self.uc.add_assign(&other.uc);
        self.zc.add_assign(&other.zc);
        self.td.add_assign(&other.td);
        self.ud.add_assign(&other.ud);
        self.zd.add_assign(&other.zd);
    }
}
