//! Sigma protocol for proving that two values committed in different groups are equal. As described in Figure 1 and its
//! extension in section 5 of the paper [Proofs of discrete logarithm equality across groups](https://eprint.iacr.org/2022/1593).
//!
//! Support proving with and without range proofs. For range proofs, Bulletproofs++ is used. The current Bulletproofs++ works over
//! 64-bit integers and can aggregate number of range proofs if that number is a power of 2. So the tests work with 64-bit, 4-chunks.
//!
//! Following is the map of symbols in the code to those in the paper
//! `WITNESS_BIT_SIZE` -> `b_x`
//! `CHALLENGE_BIT_SIZE` -> `b_c`
//! `ABORT_PARAM` -> `b_f`
//! `NUM_REPS` -> `tau`
//!
//! `RESPONSE_BYTE_SIZE` is the number of bytes need to represent `z` which lies in `[2^{WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE}, 2^{WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM} - 1]`
//!
//! The groups are assumed to be elliptic curve groups.

use crate::{error::Error, util::from_bytes_le};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter_mut, rand::RngCore, vec, vec::Vec, UniformRand};
use bulletproofs_plus_plus::prelude::{
    Proof as BppRangeProof, Prover as BppProver, SetupParams as BppSetupParams,
};
use crypto_bigint::{BoxedUint, RandomBits};
use dock_crypto_utils::{commitment::PedersenCommitmentKey, ff::powers, transcript::Transcript};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Range proof supplementing the proof of equality
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RangeProof<G: AffineRepr> {
    Bpp(BppRangeProof<G>),
}

/// A collection of range proofs supplementing the proof of equality
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RangeProofs<G: AffineRepr> {
    /// A collection of range proofs aggregated using Bulletproofs++.
    Bpp(BppRangeProof<G>),
}

/// The proof described in Figure 1 can have many repetitions of a sigma protocol. This is one repetition.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofSingleRep<
    G1: AffineRepr,
    G2: AffineRepr,
    const WITNESS_BIT_SIZE: usize,
    const CHALLENGE_BIT_SIZE: usize,
    const ABORT_PARAM: usize,
    const RESPONSE_BYTE_SIZE: usize,
> {
    /// Commitment to the randomness in group G1, called `K_p` in the paper
    pub k1_com: G1,
    /// Response in group G1, called `s_p` in the paper
    pub s1: G1::ScalarField,
    /// Commitment to the randomness in group G2, called `K_p` in the paper
    pub k2_com: G2,
    /// Response in group G2, called `s_q` in the paper
    pub s2: G2::ScalarField,
    pub z: BigInt<RESPONSE_BYTE_SIZE>,
}

/// Sigma protocol described in Figure 1. Optionally can contain a range proof if the verifier is not convinced
/// of the range of witness. Expects the witness to be in `[0, 2^WITNESS_BIT_SIZE)`
/// By convention, G1 is the group for range proof
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<
    G1: AffineRepr,
    G2: AffineRepr,
    const WITNESS_BIT_SIZE: usize,
    const CHALLENGE_BIT_SIZE: usize,
    const ABORT_PARAM: usize,
    const RESPONSE_BYTE_SIZE: usize,
    const NUM_REPS: usize,
> {
    pub eq: [ProofSingleRep<
        G1,
        G2,
        WITNESS_BIT_SIZE,
        CHALLENGE_BIT_SIZE,
        ABORT_PARAM,
        RESPONSE_BYTE_SIZE,
    >; NUM_REPS],
    pub rp: Option<RangeProof<G1>>,
}

/// Extension of the protocol described in section 5. Can handle a larger witness by breaking it into `NUM_CHUNKS`
/// number of chunks. This is essentially decomposing the witness into base `2^WITNESS_CHUNK_BIT_SIZE` digits
/// By convention, G1 is the group for range proof
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofLargeWitness<
    G1: AffineRepr,
    G2: AffineRepr,
    const NUM_CHUNKS: usize,
    const WITNESS_CHUNK_BIT_SIZE: usize,
    const CHALLENGE_BIT_SIZE: usize,
    const ABORT_PARAM: usize,
    const RESPONSE_BYTE_SIZE: usize,
    const NUM_REPS: usize,
> {
    pub eq: [[ProofSingleRep<
        G1,
        G2,
        WITNESS_CHUNK_BIT_SIZE,
        CHALLENGE_BIT_SIZE,
        ABORT_PARAM,
        RESPONSE_BYTE_SIZE,
    >; NUM_REPS]; NUM_CHUNKS],
    /// Commitments to each chunk in group G1
    pub comms_g1: [G1; NUM_CHUNKS],
    /// Commitments to each chunk in group G2
    pub comms_g2: [G2; NUM_CHUNKS],
    /// Range proofs for each chunk in the commitments in `comms_g1`
    pub rp: RangeProofs<G1>,
}

impl<
        G1: AffineRepr,
        G2: AffineRepr,
        const WITNESS_BIT_SIZE: usize,
        const CHALLENGE_BIT_SIZE: usize,
        const ABORT_PARAM: usize,
        const RESPONSE_BYTE_SIZE: usize,
        const NUM_REPS: usize,
    >
    Proof<G1, G2, WITNESS_BIT_SIZE, CHALLENGE_BIT_SIZE, ABORT_PARAM, RESPONSE_BYTE_SIZE, NUM_REPS>
{
    // ceil((WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM)/8) == RESPONSE_BYTE_SIZE
    const CHECK_RESP_SIZE: () = assert!(
        (WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM + 7) / 8 == RESPONSE_BYTE_SIZE
    );
    const CHECK_REP_COUNT: () = assert!((NUM_REPS * CHALLENGE_BIT_SIZE) >= 128,);
    const CHECK_GROUP_SIZE: () = assert!(
        // 2^(WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM) < min(g1_modulus_bitsize, g2_modulus_bitsize)
        ((WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM) as u32)
            < if G1::ScalarField::MODULUS_BIT_SIZE > G2::ScalarField::MODULUS_BIT_SIZE {
                G2::ScalarField::MODULUS_BIT_SIZE
            } else {
                G1::ScalarField::MODULUS_BIT_SIZE
            },
    );

    /// `r1` and `r2` are the randomness used in commitment to `witness` in groups G1 and G2 respectively
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn new<R: RngCore>(
        rng: &mut R,
        witness: &G1::ScalarField,
        r1: G1::ScalarField,
        r2: G2::ScalarField,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<Self, Error> {
        Ok(Self {
            eq: Self::new_equality_proof_only(
                rng,
                witness,
                r1,
                r2,
                comm_key_g1,
                comm_key_g2,
                transcript,
            )?,
            rp: None,
        })
    }

    /// `r1` and `r2` are the randomness used in commitment to `witness` in groups G1 and G2 respectively.
    /// `comm_g1` is the commitment to `witness` in group G1.
    /// `base` is used for configuring the size of range proofs.
    /// `g` and `h` of `comm_key_g1` should be same as `G` and `H_vec[0]` of Bulletproofs++ setup params
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn new_with_range_proof<R: RngCore>(
        rng: &mut R,
        witness: &G1::ScalarField,
        r1: G1::ScalarField,
        r2: G2::ScalarField,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        base: u16,
        comm_g1: G1,
        bpp_setup_params: BppSetupParams<G1>,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<Self, Error> {
        const { assert!(WITNESS_BIT_SIZE <= 64) };

        Self::ensure_bpp_gens_consistent_with_comm_key(&bpp_setup_params, comm_key_g1)?;

        let eq = Self::new_equality_proof_only(
            rng,
            witness,
            r1,
            r2,
            comm_key_g1,
            comm_key_g2,
            transcript,
        )?;

        let v = witness_as_u64(witness)?;
        let prover = BppProver::new_with_given_base(
            base,
            WITNESS_BIT_SIZE as u16,
            vec![comm_g1],
            vec![v],
            vec![r1],
        )?;
        let proof = prover.prove(rng, bpp_setup_params, transcript)?;
        Ok(Self {
            eq,
            rp: Some(RangeProof::Bpp(proof)),
        })
    }

    /// Verifies the proof of equality without checking for range proof.
    /// `comm_g1` and `comm_g2` are the commitments to `witness` in groups G1 and G2 respectively.
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn verify(
        &self,
        comm_g1: &G1,
        comm_g2: &G2,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        transcript: &mut impl Transcript,
    ) -> Result<(), Error> {
        Self::verify_equality_proof_only(
            &self.eq,
            comm_g1,
            comm_g2,
            comm_key_g1,
            comm_key_g2,
            transcript,
        )
    }

    /// Verifies the proof of equality and checks for range proof.
    /// `comm_g1` and `comm_g2` are the commitments to `witness` in groups G1 and G2 respectively.
    /// `g` and `h` of `comm_key_g1` should be same as `G` and `H_vec[0]` of Bulletproofs++ setup params
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn verify_with_range_proof(
        &self,
        comm_g1: &G1,
        comm_g2: &G2,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        bpp_setup_params: &BppSetupParams<G1>,
        transcript: &mut impl Transcript,
    ) -> Result<(), Error> {
        const { assert!(WITNESS_BIT_SIZE <= 64) };
        Self::ensure_bpp_gens_consistent_with_comm_key(bpp_setup_params, comm_key_g1)?;
        self.verify(comm_g1, comm_g2, comm_key_g1, comm_key_g2, transcript)?;
        if let Some(rp) = self.rp.as_ref() {
            let r = match rp {
                RangeProof::Bpp(bpp) => bpp.verify(
                    WITNESS_BIT_SIZE as u16,
                    &[*comm_g1],
                    bpp_setup_params,
                    transcript,
                )?,
            };
            Ok(r)
        } else {
            Err(Error::MissingRangeProof)
        }
    }

    pub fn new_equality_proof_only<R: RngCore>(
        rng: &mut R,
        witness: &G1::ScalarField,
        r1: G1::ScalarField,
        r2: G2::ScalarField,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<
        [ProofSingleRep<
            G1,
            G2,
            WITNESS_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
        >; NUM_REPS],
        Error,
    > {
        Self::static_asserts();
        let mut proofs = [ProofSingleRep::<
            G1,
            G2,
            WITNESS_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
        >::default(); NUM_REPS];

        let (min_resp, max_resp) = Self::max_min_resp();

        let x = witness.into_bigint();
        for (i, b) in x.to_bits_le().into_iter().enumerate() {
            if i >= WITNESS_BIT_SIZE {
                if b {
                    return Err(Error::WitnessBiggerThanExpected);
                }
            }
        }

        let wit_byte_size = Self::witness_byte_size();
        let mut x_bytes = x.to_bytes_le();
        x_bytes.drain(wit_byte_size..);

        let mut proof_count = 0;
        while proof_count < NUM_REPS {
            // clone the transcript and make changes to the cloned one as in case of abort the changes made to
            // the transcript need to be reverted and there is no function to revert an addition to the transcript.
            // In case of no abort, transcript will be set to this cloned one.
            let mut curr_trans = transcript.clone();

            let k = BoxedUint::try_random_bits(
                rng,
                (WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM) as u32,
            )
            .unwrap();

            let k_bytes = k.to_le_bytes();

            let k1 = G1::ScalarField::from_le_bytes_mod_order(&k_bytes);
            let k2 = G2::ScalarField::from_le_bytes_mod_order(&k_bytes);
            let t1 = G1::ScalarField::rand(rng);
            let t2 = G2::ScalarField::rand(rng);

            let k1_com = comm_key_g1.commit(&k1, &t1);
            let k2_com = comm_key_g2.commit(&k2, &t2);

            let c_bytes = Self::challenge_bytes(&k1_com, &k2_com, &mut curr_trans);

            let c = BoxedUint::from_le_slice(&c_bytes, c_bytes.len() as u32 * 8).unwrap();
            let x = BoxedUint::from_le_slice(&x_bytes, wit_byte_size as u32 * 8).unwrap();
            let z = k + (c * x);
            let z = from_bytes_le::<RESPONSE_BYTE_SIZE>(&z.to_le_bytes());

            if z < min_resp || z > max_resp {
                // Abort and restart this repetition
                continue;
            }

            *transcript = curr_trans;

            let c1 = G1::ScalarField::from_le_bytes_mod_order(&c_bytes);
            let c2 = G2::ScalarField::from_le_bytes_mod_order(&c_bytes);
            let s1 = t1 + c1 * r1;
            let s2 = t2 + c2 * r2;
            proofs[proof_count] = ProofSingleRep {
                k1_com,
                s1,
                k2_com,
                s2,
                z,
            };
            proof_count += 1;
        }
        Ok(proofs)
    }

    pub fn verify_equality_proof_only(
        eq: &[ProofSingleRep<
            G1,
            G2,
            WITNESS_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
        >; NUM_REPS],
        comm_g1: &G1,
        comm_g2: &G2,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        transcript: &mut impl Transcript,
    ) -> Result<(), Error> {
        Self::static_asserts();
        let (min_resp, max_resp) = Self::max_min_resp();
        for i in 0..NUM_REPS {
            if eq[i].z < min_resp || eq[i].z > max_resp {
                return Err(Error::ZOutOfRangeForRep(i));
            }
            let z_bytes = eq[i].z.to_bytes_le();
            let z1 = G1::ScalarField::from_le_bytes_mod_order(&z_bytes);
            let z2 = G2::ScalarField::from_le_bytes_mod_order(&z_bytes);

            let c_bytes = Self::challenge_bytes(&eq[i].k1_com, &eq[i].k2_com, transcript);

            let c1 = G1::ScalarField::from_le_bytes_mod_order(&c_bytes);
            let c2 = G2::ScalarField::from_le_bytes_mod_order(&c_bytes);

            if comm_key_g1.commit_as_projective(&z1, &eq[i].s1) != (eq[i].k1_com + comm_g1.mul(&c1))
            {
                return Err(Error::SchnorrCheckFailedForRep(i));
            }
            if comm_key_g2.commit_as_projective(&z2, &eq[i].s2) != (eq[i].k2_com + comm_g2.mul(&c2))
            {
                return Err(Error::SchnorrCheckFailedForRep(i));
            }
        }
        Ok(())
    }

    /// If Bulletproof setup params don't have common generators with the commitment to the witness, then extra commitments
    /// and their corresponding proof will be needed
    fn ensure_bpp_gens_consistent_with_comm_key(
        bpp_setup_params: &BppSetupParams<G1>,
        comm_key_g1: &PedersenCommitmentKey<G1>,
    ) -> Result<(), Error> {
        if bpp_setup_params.G != comm_key_g1.g || bpp_setup_params.H_vec[0] != comm_key_g1.h {
            return Err(Error::BulletproofsPlusPlusGeneratorsDontMatchCommitmentKey);
        }
        Ok(())
    }

    /// Minimum and maximum values of the response `z`
    fn max_min_resp() -> (BigInt<RESPONSE_BYTE_SIZE>, BigInt<RESPONSE_BYTE_SIZE>) {
        let mut max_resp = BigInt::<RESPONSE_BYTE_SIZE>::one();
        let mut min_resp = BigInt::<RESPONSE_BYTE_SIZE>::one();
        for i in 0..WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM {
            max_resp.mul2();
            if i < WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE {
                min_resp.mul2();
            }
        }
        max_resp.sub_with_borrow(&BigInt::one());
        (min_resp, max_resp)
    }

    /// Generate challenge from transcript by adding `k1_com`, `k2_com` and ensuring that the challenge
    /// is of `CHALLENGE_BIT_SIZE` bits max.
    fn challenge_bytes(k1_com: &G1, k2_com: &G2, transcript: &mut impl Transcript) -> Vec<u8> {
        transcript.append(b"K1", k1_com);
        transcript.append(b"K2", k2_com);

        let chal_byte_size = Self::challenge_byte_size();
        let mut c_bytes = vec![0; chal_byte_size];
        transcript.challenge_bytes(b"challenge", &mut c_bytes);

        // if CHALLENGE_BIT_SIZE is not multiple of 8, then unset MSBs beyond CHALLENGE_BIT_SIZE
        c_bytes[chal_byte_size - 1] = c_bytes[chal_byte_size - 1] & Self::challenge_mask();
        c_bytes
    }

    /// ceil(WITNESS_BIT_SIZE/8)
    const fn witness_byte_size() -> usize {
        (WITNESS_BIT_SIZE + 7) / 8
    }

    /// ceil(CHALLENGE_BIT_SIZE/8)
    const fn challenge_byte_size() -> usize {
        (CHALLENGE_BIT_SIZE + 7) / 8
    }

    /// if CHALLENGE_BIT_SIZE is not multiple of 8, then the mask used to unset MSBs beyond CHALLENGE_BIT_SIZE
    const fn challenge_mask() -> u8 {
        u8::MAX << (Self::challenge_byte_size() * 8 - CHALLENGE_BIT_SIZE)
    }

    const fn static_asserts() {
        let _ = Self::CHECK_RESP_SIZE;
        let _ = Self::CHECK_REP_COUNT;
        let _ = Self::CHECK_GROUP_SIZE;
    }
}

impl<
        G1: AffineRepr,
        G2: AffineRepr,
        const NUM_CHUNKS: usize,
        const WITNESS_CHUNK_BIT_SIZE: usize,
        const CHALLENGE_BIT_SIZE: usize,
        const ABORT_PARAM: usize,
        const RESPONSE_BYTE_SIZE: usize,
        const NUM_REPS: usize,
    >
    ProofLargeWitness<
        G1,
        G2,
        NUM_CHUNKS,
        WITNESS_CHUNK_BIT_SIZE,
        CHALLENGE_BIT_SIZE,
        ABORT_PARAM,
        RESPONSE_BYTE_SIZE,
        NUM_REPS,
    >
{
    // ceil((WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM)/8) == RESPONSE_BYTE_SIZE
    const CHECK_RESP_SIZE: () = assert!(
        (WITNESS_CHUNK_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM + 7) / 8 == RESPONSE_BYTE_SIZE
    );
    // ceil(G1::ScalarField::MODULUS_BIT_SIZE / WITNESS_CHUNK_BIT_SIZE) == NUM_CHUNKS
    const CHECK_NUM_CHUNKS: () = assert!(
        (G1::ScalarField::MODULUS_BIT_SIZE as usize + WITNESS_CHUNK_BIT_SIZE - 1)
            / WITNESS_CHUNK_BIT_SIZE
            == NUM_CHUNKS
    );
    // These 2 checks are due to the current limitation of the Bulletproofs++ implementation
    const CHECK_NUM_CHUNKS_2: () = assert!(NUM_CHUNKS.is_power_of_two() == true);
    const CHECK_WIT_SIZE: () = assert!(WITNESS_CHUNK_BIT_SIZE <= 64);

    /// `r1` and `r2` are the randomness used in commitment to `witness` in groups G1 and G2 respectively.
    /// `comm_g1` is the commitment to `witness` in group G1.
    /// `base` is used for configuring the size of range proofs.
    /// `g` and `h` of `comm_key_g1` should be same as `G` and `H_vec[0]` of Bulletproofs++ setup params
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn new<R: RngCore>(
        rng: &mut R,
        witness: &G1::ScalarField,
        r1: G1::ScalarField,
        r2: G2::ScalarField,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        base: u16,
        bpp_setup_params: BppSetupParams<G1>,
        transcript: &mut (impl Transcript + Clone),
    ) -> Result<Self, Error> {
        Self::static_asserts();

        Proof::<
            G1,
            G2,
            WITNESS_CHUNK_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
            NUM_REPS,
        >::ensure_bpp_gens_consistent_with_comm_key(&bpp_setup_params, comm_key_g1)?;

        let witness_decomposed = decompose::<G1>(&witness, WITNESS_CHUNK_BIT_SIZE);
        let r1_decomposed = decompose::<G1>(&r1, WITNESS_CHUNK_BIT_SIZE);
        let r2_decomposed = decompose::<G2>(&r2, WITNESS_CHUNK_BIT_SIZE);

        // Create commitments, witnesses and randomness for each chunk
        let mut comms_g1 = [G1::zero(); NUM_CHUNKS];
        let mut comms_g2 = [G2::zero(); NUM_CHUNKS];
        let mut w1s = vec![G1::ScalarField::zero(); NUM_CHUNKS];
        let mut r1s = vec![G1::ScalarField::zero(); NUM_CHUNKS];
        let mut r2s = vec![G2::ScalarField::zero(); NUM_CHUNKS];
        cfg_iter_mut!(w1s)
            .zip(cfg_iter_mut!(r1s))
            .zip(cfg_iter_mut!(r2s))
            .zip(cfg_iter_mut!(comms_g1))
            .zip(cfg_iter_mut!(comms_g2))
            .enumerate()
            .for_each(|(i, ((((w1_i, r1_i), r2_i), comm_1), comm_2))| {
                *w1_i = G1::ScalarField::from_le_bytes_mod_order(&witness_decomposed[i]);
                let w2_i = G2::ScalarField::from_le_bytes_mod_order(&witness_decomposed[i]);
                *r1_i = G1::ScalarField::from_le_bytes_mod_order(&r1_decomposed[i]);
                *r2_i = G2::ScalarField::from_le_bytes_mod_order(&r2_decomposed[i]);
                *comm_1 = comm_key_g1.commit(&w1_i, &r1_i);
                *comm_2 = comm_key_g2.commit(&w2_i, &r2_i);
            });

        let mut proofs = [[ProofSingleRep::<
            G1,
            G2,
            WITNESS_CHUNK_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
        >::default(); NUM_REPS]; NUM_CHUNKS];

        for i in 0..NUM_CHUNKS {
            proofs[i] = Proof::new_equality_proof_only(
                rng,
                &w1s[i],
                r1s[i],
                r2s[i],
                &comm_key_g1,
                &comm_key_g2,
                transcript,
            )?;
        }

        // Create range proof over all chunks. For Bulletproofs, all range proofs can be combined into one.
        let mut v = Vec::with_capacity(NUM_CHUNKS);
        let iter = cfg_into_iter!(w1s)
            .map(|w| witness_as_u64(&w))
            .collect::<Vec<_>>();
        for w in iter {
            v.push(w?);
        }

        let prover = BppProver::new_with_given_base(
            base,
            WITNESS_CHUNK_BIT_SIZE as u16,
            comms_g1.to_vec(),
            v,
            r1s,
        )?;
        let proof = prover.prove(rng, bpp_setup_params, transcript)?;
        Ok(Self {
            eq: proofs,
            rp: RangeProofs::Bpp(proof),
            comms_g1,
            comms_g2,
        })
    }

    /// `comm_g1` and `comm_g2` are the commitments to `witness` in groups G1 and G2 respectively.
    /// `g` and `h` of `comm_key_g1` should be same as `G` and `H_vec[0]` of Bulletproofs++ setup params
    /// This does not include the commitments, commitment key or any public parameters into the transcript.
    /// The caller should ensure that they have been added before
    pub fn verify(
        &self,
        comm_g1: &G1,
        comm_g2: &G2,
        comm_key_g1: &PedersenCommitmentKey<G1>,
        comm_key_g2: &PedersenCommitmentKey<G2>,
        bpp_setup_params: &BppSetupParams<G1>,
        transcript: &mut impl Transcript,
    ) -> Result<(), Error> {
        Self::static_asserts();

        Proof::<
            G1,
            G2,
            WITNESS_CHUNK_BIT_SIZE,
            CHALLENGE_BIT_SIZE,
            ABORT_PARAM,
            RESPONSE_BYTE_SIZE,
            NUM_REPS,
        >::ensure_bpp_gens_consistent_with_comm_key(bpp_setup_params, comm_key_g1)?;
        for i in 0..NUM_CHUNKS {
            Proof::verify_equality_proof_only(
                &self.eq[i],
                &self.comms_g1[i],
                &self.comms_g2[i],
                comm_key_g1,
                comm_key_g2,
                transcript,
            )?
        }

        let base = 2_u128.pow(WITNESS_CHUNK_BIT_SIZE as u32);
        let base_powers_g1 =
            powers::<G1::ScalarField>(&G1::ScalarField::from(base), NUM_CHUNKS as u32);
        let base_powers_g2 =
            powers::<G2::ScalarField>(&G2::ScalarField::from(base), NUM_CHUNKS as u32);
        if comm_g1 != &G1::Group::msm_unchecked(&self.comms_g1, &base_powers_g1).into_affine() {
            return Err(Error::RecreatedCommitmentsDontMatch);
        }
        if comm_g2 != &G2::Group::msm_unchecked(&self.comms_g2, &base_powers_g2).into_affine() {
            return Err(Error::RecreatedCommitmentsDontMatch);
        }

        let r = match &self.rp {
            RangeProofs::Bpp(bpp) => bpp.verify(
                WITNESS_CHUNK_BIT_SIZE as u16,
                &self.comms_g1,
                bpp_setup_params,
                transcript,
            )?,
        };
        Ok(r)
    }

    const fn static_asserts() {
        let _ = Self::CHECK_RESP_SIZE;
        let _ = Self::CHECK_NUM_CHUNKS;
        let _ = Self::CHECK_NUM_CHUNKS_2;
        let _ = Self::CHECK_WIT_SIZE;
    }
}

/// Parse witness as a u64. Expects that witness won't be > u64
fn witness_as_u64<F: PrimeField>(witness: &F) -> Result<u64, Error> {
    let x = witness.into_bigint();
    let x_as_u64_array = x.as_ref();
    for i in 1..x_as_u64_array.len() {
        if x_as_u64_array[i] != 0 {
            return Err(Error::WitnessBiggerThan64Bit);
        }
    }
    Ok(x_as_u64_array[0])
}

/// Decompose witness into base `2^chunk_bit_size` digits and each digit is in little-endian
fn decompose<G: AffineRepr>(n: &G::ScalarField, chunk_bit_size: usize) -> Vec<Vec<u8>> {
    let mut chunks = vec![];
    for bits in n.into_bigint().to_bits_le().chunks(chunk_bit_size) {
        let l = bits.len();
        let mut chunk = vec![0_u8; (l + 7) / 8];
        for (i, bits8) in bits.chunks(8).enumerate() {
            for (j, bit) in bits8.iter().enumerate() {
                chunk[i] |= (*bit as u8) << j;
            }
        }
        chunks.push(chunk);
    }
    chunks
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, SerializationError, Valid, Validate};
    use ark_std::io::{Read, Write};

    impl<G: AffineRepr> Valid for RangeProof<G> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::Bpp(e) => e.check(),
            }
        }
    }

    impl<G: AffineRepr> CanonicalSerialize for RangeProof<G> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Bpp(r) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::Bpp(r) => 0u8.serialized_size(compress) + r.serialized_size(compress),
            }
        }
    }

    impl<G: AffineRepr> CanonicalDeserialize for RangeProof<G> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::Bpp(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }

    impl<G: AffineRepr> Valid for RangeProofs<G> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::Bpp(e) => e.check(),
            }
        }
    }

    impl<G: AffineRepr> CanonicalSerialize for RangeProofs<G> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::Bpp(r) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::Bpp(r) => 0u8.serialized_size(compress) + r.serialized_size(compress),
            }
        }
    }

    impl<G: AffineRepr> CanonicalDeserialize for RangeProofs<G> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::Bpp(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tom256::Affine as tom256Aff;
    use ark_bls12_381::G1Affine as BlsG1Aff;
    use ark_secp256r1::Affine as secp256r1Aff;
    use ark_serialize::CanonicalSerialize;
    use blake2::Blake2b512;
    use dock_crypto_utils::{ff::inner_product, transcript::new_merlin_transcript};
    use rand_core::OsRng;

    #[test]
    fn decompose_into_chunks() {
        fn check<G: AffineRepr>() {
            let mut rng = OsRng::default();

            for x in [
                G::ScalarField::from(100_u32),
                G::ScalarField::from(512_u32),
                G::ScalarField::from(512512_u32),
                G::ScalarField::from(9989110_u32),
                G::ScalarField::from(99891109989110_u64),
                G::ScalarField::from(1675490980013_u64),
                G::ScalarField::rand(&mut rng),
                G::ScalarField::rand(&mut rng),
                G::ScalarField::rand(&mut rng),
                G::ScalarField::rand(&mut rng),
            ] {
                for chunk_bit_size in [4, 8, 16, 40, 52, 64] {
                    let base = 2_u128.pow(chunk_bit_size as u32);
                    let x_bits = x.into_bigint().to_bits_le();
                    let x_decomposed = decompose::<G>(&x, chunk_bit_size);
                    assert_eq!(
                        x_decomposed.len(),
                        (x_bits.len() + chunk_bit_size - 1) / chunk_bit_size
                    );
                    let base_powers = powers::<G::ScalarField>(
                        &G::ScalarField::from(base),
                        x_decomposed.len() as u32,
                    );

                    let x_decomposed = cfg_into_iter!(x_decomposed)
                        .map(|x_i| G::ScalarField::from_le_bytes_mod_order(&x_i))
                        .collect::<Vec<_>>();
                    let recreated_x = inner_product::<G::ScalarField>(&base_powers, &x_decomposed);
                    assert_eq!(recreated_x, x, "chunk_bit_size={}", chunk_bit_size);
                }
            }
        }

        check::<secp256r1Aff>();
        check::<BlsG1Aff>();
        check::<tom256Aff>();
    }

    #[test]
    fn check_without_range_proof() {
        macro_rules! check {
            ($fn_name: ident, $wit_size: expr, $chal_bit_size: expr, $abort_p: expr, $resp_size: expr, $num_reps: expr, $g1: ident, $g2: ident) => {
                fn $fn_name() {
                    let mut rng = OsRng::default();
                    const WITNESS_BIT_SIZE: usize = $wit_size;
                    const CHALLENGE_BIT_SIZE: usize = $chal_bit_size;
                    const ABORT_PARAM: usize = $abort_p;
                    const RESPONSE_BYTE_SIZE: usize = $resp_size;
                    const NUM_REPS: usize = $num_reps;
                    assert!(
                        (WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM + 7) / 8
                            == RESPONSE_BYTE_SIZE
                    );

                    let comm_key1 = PedersenCommitmentKey::<$g1>::new::<Blake2b512>(b"test");
                    let comm_key2 = PedersenCommitmentKey::<$g2>::new::<Blake2b512>(b"test");

                    // Since testing with WITNESS_BIT_SIZE > 32
                    let x = <$g1 as AffineRepr>::ScalarField::from(u32::rand(&mut rng));
                    let mut x_bytes = vec![];
                    x.serialize_compressed(&mut x_bytes).unwrap();

                    let x1 = <$g1 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let x2 = <$g2 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let r1 = <$g1 as AffineRepr>::ScalarField::rand(&mut rng);
                    let r2 = <$g2 as AffineRepr>::ScalarField::rand(&mut rng);

                    let comm_g1 = comm_key1.commit(&x1, &r1);
                    let comm_g2 = comm_key2.commit(&x2, &r2);

                    let nonce = b"123";

                    let mut prover_transcript = new_merlin_transcript(b"test");
                    prover_transcript.append_message_without_static_label(b"nonce", nonce);
                    prover_transcript.append(b"comm_key1", &comm_key1);
                    prover_transcript.append(b"comm_key2", &comm_key2);
                    prover_transcript.append(b"comm_g1", &comm_g1);
                    prover_transcript.append(b"comm_g2", &comm_g2);
                    let proof = Proof::<
                        $g1,
                        $g2,
                        WITNESS_BIT_SIZE,
                        CHALLENGE_BIT_SIZE,
                        ABORT_PARAM,
                        RESPONSE_BYTE_SIZE,
                        NUM_REPS,
                    >::new(
                        &mut rng,
                        &x1,
                        r1,
                        r2,
                        &comm_key1,
                        &comm_key2,
                        &mut prover_transcript,
                    )
                    .unwrap();

                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append_message_without_static_label(b"nonce", nonce);
                    verifier_transcript.append(b"comm_key1", &comm_key1);
                    verifier_transcript.append(b"comm_key2", &comm_key2);
                    verifier_transcript.append(b"comm_g1", &comm_g1);
                    verifier_transcript.append(b"comm_g2", &comm_g2);
                    proof
                        .verify(
                            &comm_g1,
                            &comm_g2,
                            &comm_key1,
                            &comm_key2,
                            &mut verifier_transcript,
                        )
                        .unwrap();
                }
                $fn_name();
            };
        }

        check!(check1, 52, 192, 8, 32, 1, secp256r1Aff, BlsG1Aff);

        check!(check2, 52, 192, 8, 32, 1, secp256r1Aff, tom256Aff);

        check!(check3, 52, 192, 8, 32, 1, tom256Aff, BlsG1Aff);

        check!(check4, 52, 120, 80, 32, 2, secp256r1Aff, BlsG1Aff);

        check!(check5, 52, 120, 80, 32, 2, secp256r1Aff, tom256Aff);

        check!(check6, 52, 120, 80, 32, 2, tom256Aff, BlsG1Aff);

        check!(check7, 64, 180, 8, 32, 1, secp256r1Aff, BlsG1Aff);

        check!(check8, 64, 180, 8, 32, 1, secp256r1Aff, tom256Aff);

        check!(check9, 64, 180, 8, 32, 1, tom256Aff, BlsG1Aff);

        check!(check10, 64, 108, 80, 32, 2, secp256r1Aff, BlsG1Aff);

        check!(check11, 64, 108, 80, 32, 2, secp256r1Aff, tom256Aff);

        check!(check12, 64, 108, 80, 32, 2, tom256Aff, BlsG1Aff);
    }

    #[test]
    fn check_with_range_proof() {
        macro_rules! check {
            ($fn_name: ident, $wit_size: expr, $chal_bit_size: expr, $abort_p: expr, $resp_size: expr, $num_reps: expr, $g1: ident, $g2: ident) => {
                fn $fn_name() {
                    let mut rng = OsRng::default();
                    const WITNESS_BIT_SIZE: usize = $wit_size;
                    const CHALLENGE_BIT_SIZE: usize = $chal_bit_size;
                    const ABORT_PARAM: usize = $abort_p;
                    const RESPONSE_BYTE_SIZE: usize = $resp_size;
                    const NUM_REPS: usize = $num_reps;
                    assert!(
                        (WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM + 7) / 8
                            == RESPONSE_BYTE_SIZE
                    );

                    let comm_key1 = PedersenCommitmentKey::<$g1>::new::<Blake2b512>(b"test");
                    let comm_key2 = PedersenCommitmentKey::<$g2>::new::<Blake2b512>(b"test");

                    let base = 2;
                    let mut bpp_setup_params = BppSetupParams::<$g1>::new_for_perfect_range_proof::<
                        Blake2b512,
                    >(b"test", base, WITNESS_BIT_SIZE as u16, 1);
                    bpp_setup_params.G = comm_key1.g;
                    bpp_setup_params.H_vec[0] = comm_key1.h;

                    // Since testing with WITNESS_BIT_SIZE < 64
                    let x = <$g1 as AffineRepr>::ScalarField::from(u64::rand(&mut rng));
                    let mut x_bytes = vec![];
                    x.serialize_compressed(&mut x_bytes).unwrap();

                    let x1 = <$g1 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let x2 = <$g2 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let r1 = <$g1 as AffineRepr>::ScalarField::rand(&mut rng);
                    let r2 = <$g2 as AffineRepr>::ScalarField::rand(&mut rng);

                    let comm_g1 = comm_key1.commit(&x1, &r1);
                    let comm_g2 = comm_key2.commit(&x2, &r2);

                    let mut prover_transcript = new_merlin_transcript(b"test");
                    prover_transcript.append(b"comm_key1", &comm_key1);
                    prover_transcript.append(b"comm_key2", &comm_key2);
                    prover_transcript.append(b"comm_g1", &comm_g1);
                    prover_transcript.append(b"comm_g2", &comm_g2);
                    prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
                    let proof = Proof::<
                        $g1,
                        $g2,
                        WITNESS_BIT_SIZE,
                        CHALLENGE_BIT_SIZE,
                        ABORT_PARAM,
                        RESPONSE_BYTE_SIZE,
                        NUM_REPS,
                    >::new_with_range_proof(
                        &mut rng,
                        &x1,
                        r1,
                        r2,
                        &comm_key1,
                        &comm_key2,
                        base,
                        comm_g1,
                        bpp_setup_params.clone(),
                        &mut prover_transcript,
                    )
                    .unwrap();

                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key1", &comm_key1);
                    verifier_transcript.append(b"comm_key2", &comm_key2);
                    verifier_transcript.append(b"comm_g1", &comm_g1);
                    verifier_transcript.append(b"comm_g2", &comm_g2);
                    verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
                    proof
                        .verify_with_range_proof(
                            &comm_g1,
                            &comm_g2,
                            &comm_key1,
                            &comm_key2,
                            &bpp_setup_params,
                            &mut verifier_transcript,
                        )
                        .unwrap();
                }
                $fn_name();
            };
        }

        check!(check1, 64, 180, 8, 32, 1, secp256r1Aff, BlsG1Aff);

        check!(check2, 64, 180, 8, 32, 1, secp256r1Aff, tom256Aff);

        check!(check3, 64, 180, 8, 32, 1, tom256Aff, BlsG1Aff);

        check!(check4, 64, 108, 80, 32, 2, secp256r1Aff, BlsG1Aff);

        check!(check5, 64, 108, 80, 32, 2, secp256r1Aff, tom256Aff);

        check!(check6, 64, 108, 80, 32, 2, tom256Aff, BlsG1Aff);
    }

    #[test]
    fn check_large_witnesses() {
        macro_rules! check {
            ($fn_name: ident, $wit_size: expr, $chal_bit_size: expr, $abort_p: expr, $resp_size: expr, $num_reps: expr, $num_chunks: expr, $g1: ident, $g2: ident) => {
                fn $fn_name() {
                    let mut rng = OsRng::default();
                    const WITNESS_BIT_SIZE: usize = $wit_size;
                    const CHALLENGE_BIT_SIZE: usize = $chal_bit_size;
                    const ABORT_PARAM: usize = $abort_p;
                    const RESPONSE_BYTE_SIZE: usize = $resp_size;
                    const NUM_REPS: usize = $num_reps;
                    const NUM_CHUNKS: usize = $num_chunks;
                    assert!(
                        (WITNESS_BIT_SIZE + CHALLENGE_BIT_SIZE + ABORT_PARAM + 7) / 8
                            == RESPONSE_BYTE_SIZE
                    );

                    let comm_key1 = PedersenCommitmentKey::<$g1>::new::<Blake2b512>(b"test");
                    let comm_key2 = PedersenCommitmentKey::<$g2>::new::<Blake2b512>(b"test");

                    let base = 2;
                    let mut bpp_setup_params =
                        BppSetupParams::<$g1>::new_for_perfect_range_proof::<Blake2b512>(
                            b"test",
                            base,
                            WITNESS_BIT_SIZE as u16,
                            NUM_CHUNKS as u32,
                        );
                    bpp_setup_params.G = comm_key1.g;
                    bpp_setup_params.H_vec[0] = comm_key1.h;

                    let mut x = <$g1 as AffineRepr>::ScalarField::rand(&mut rng);
                    while x.into_bigint().num_bits() < 210 {
                        x = <$g1 as AffineRepr>::ScalarField::rand(&mut rng);
                    }
                    let mut x_bytes = vec![];
                    x.serialize_compressed(&mut x_bytes).unwrap();

                    let x1 = <$g1 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let x2 = <$g2 as AffineRepr>::ScalarField::from_le_bytes_mod_order(&x_bytes);
                    let r1 = <$g1 as AffineRepr>::ScalarField::rand(&mut rng);
                    let r2 = <$g2 as AffineRepr>::ScalarField::rand(&mut rng);

                    let comm_g1 = comm_key1.commit(&x1, &r1);
                    let comm_g2 = comm_key2.commit(&x2, &r2);

                    let mut prover_transcript = new_merlin_transcript(b"test");
                    prover_transcript.append(b"comm_key1", &comm_key1);
                    prover_transcript.append(b"comm_key2", &comm_key2);
                    prover_transcript.append(b"comm_g1", &comm_g1);
                    prover_transcript.append(b"comm_g2", &comm_g2);
                    prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
                    let proof = ProofLargeWitness::<
                        $g1,
                        $g2,
                        NUM_CHUNKS,
                        WITNESS_BIT_SIZE,
                        CHALLENGE_BIT_SIZE,
                        ABORT_PARAM,
                        RESPONSE_BYTE_SIZE,
                        NUM_REPS,
                    >::new(
                        &mut rng,
                        &x1,
                        r1,
                        r2,
                        &comm_key1,
                        &comm_key2,
                        base,
                        bpp_setup_params.clone(),
                        &mut prover_transcript,
                    )
                    .unwrap();

                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key1", &comm_key1);
                    verifier_transcript.append(b"comm_key2", &comm_key2);
                    verifier_transcript.append(b"comm_g1", &comm_g1);
                    verifier_transcript.append(b"comm_g2", &comm_g2);
                    verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
                    proof
                        .verify(
                            &comm_g1,
                            &comm_g2,
                            &comm_key1,
                            &comm_key2,
                            &bpp_setup_params,
                            &mut verifier_transcript,
                        )
                        .unwrap();
                }
                $fn_name();
            };
        }

        check!(check1, 64, 180, 8, 32, 1, 4, secp256r1Aff, BlsG1Aff);

        check!(check2, 64, 180, 8, 32, 1, 4, secp256r1Aff, tom256Aff);

        check!(check3, 64, 180, 8, 32, 1, 4, tom256Aff, BlsG1Aff);

        check!(check4, 64, 108, 80, 32, 2, 4, secp256r1Aff, BlsG1Aff);

        check!(check5, 64, 108, 80, 32, 2, 4, secp256r1Aff, tom256Aff);

        check!(check6, 64, 108, 80, 32, 2, 4, tom256Aff, BlsG1Aff);
    }
}
