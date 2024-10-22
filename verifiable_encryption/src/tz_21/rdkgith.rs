//! Verifiable Encryption from DKG-in-the-head following Protocol 5 from the paper but adapted for the relation
//! `Y = G_1 * x_1 + G_2 * x_2 + ... G_k * x_k` where `x_i` are encrypted, `Y` and `G_i` are public.
//! Overview of the construction:
//! 1. For an encryption of `k` witnesses `x_1, x_2, ..., x_k`, prover secret shares each witness using Shamir secret sharing.
//! It samples `k` random polynomials `F_1, F_2, ... F_k` of degree `t` such that `t+1` evaluations of each polynomial are needed
//! to reconstruct the polynomial. `F_i(0) = x_i` and `F_i(j) = x_i + f_{i, 1}*j + f_{i, 1}*j^2 + ... f_{i, t}*j^t` and `f_{i, k}` is
//! the k-th coefficient of the polynomial `F_i`.
//! 2. Prover evaluates each polynomial at `N` points and each of these form a share of a party and encrypts each share. Each share's
//! ciphertext is of the form `(shared_secret, OTP_{i,j} + F_i(j))` where `OTP_{i,j}` is the one time pad derived from the shared secret
//! for the j-th share of witness `i`, i.e. `F_i(j)`.
//! 3. Prover commits to the coefficients of polynomials `t` commitments where commitment to j-th coefficient is `C_j = G_1 * f_{1, j} + G_2 * f_{2, j} + ... + G_k * f_{k, j}`.
//! 4. Prover sends `t` shares, commitment to the coefficients of the polynomials and `N-t` ciphertexts to the verifier which the
//! verifier cannot use to recover any witness since `t+1` shares are needed to reconstruct any witness.
//! 5. The verifier using the commitment to the coefficients of the polynomials and the revealed shares verifies the correctness of shares (same idea as
//! Feldman secret sharing) and integrity of prover's computation.
//! 6. To compress the `N-t` ciphertexts, verifier chooses a small number of ciphertexts and for each of those ciphertexts, multiplies it by
//! the appropriate Lagrange coefficient and adds it to sum of each revealed share with the corresponding Lagrange coefficient. The sum gives the
//! encryption of the witness. Eg, for the j-th share of i-th witness, ciphertext is `CT_j = OTP_{i,j} + F_i(j)`. Multiplying `CT_j` by its
//! Lagrange coefficient `l_j` and multiplying each of the `t` revealed shares of i-th witness with their Lagrange coefficient `l_k` as `F_i(k) * l_k`
//! and adding these gives `CT_j * l_j + \sum_{k!=j}{F_i(k) * l_k} = OTP_{i,j} * l_j + F_i(j) * l_j + \sum_{k!=j}{F_i(k) * l_k} = OTP_{i,j} * l_j + x_i`.
//! 7. Now decryptor can decrypt a ciphertext by computing Lagrange coefficient `l_j` and one time pad `OTP_{i,j}` to get witness `x_i`
//!
//! The encryption scheme used in generic and either the hashed Elgamal shown in the paper can be used or a more
//! efficient version of hashed Elgamal can be used where rather than generating a new shared secret for each witness's share,
//! only 1 shared secret is generated per party and then independent OTPs are derived for each witness share by "appending" counters
//! to that shared secret.

use crate::{
    error::VerifiableEncryptionError,
    tz_21::{encryption::BatchCiphertext, util::get_unique_indices_to_hide},
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{boxed::Box, cfg_into_iter, cfg_iter, cfg_iter_mut, rand::RngCore, vec, vec::Vec};
use digest::{Digest, DynDigest};
use dock_crypto_utils::{
    aliases::FullDigest,
    ff::{powers, powers_starting_from},
    hashing_utils::hash_to_field,
    msm::WindowTable,
};
use secret_sharing_and_dkg::{
    common::{lagrange_basis_at_0, lagrange_basis_at_0_for_all},
    shamir_ss::deal_secret,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Ciphertext and the proof of encryption. `CT` is the variant of Elgamal encryption used. See test for usage
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RdkgithProof<
    G: AffineRepr,
    CT: BatchCiphertext<G>,
    const NUM_PARTIES: usize,
    const THRESHOLD: usize,
    const NUM_PARTIES_MINUS_THRESHOLD: usize,
> {
    pub challenge: Vec<u8>,
    /// Commitment to the coefficients of polynomials
    pub poly_commitments: [G; THRESHOLD],
    /// Ciphertexts of the shares. The first element of the tuple is the party index
    // Following could be made a map indexed with u16 to speed up computation (lookups) by trading off memory
    pub ciphertexts: [(u16, CT); NUM_PARTIES_MINUS_THRESHOLD],
    /// Revealed shares and randomness used for encryption. The first element of the tuple is the party index, second is the
    /// shares of each witness for that party
    pub shares_and_enc_rands: [(u16, Vec<G::ScalarField>, CT::Randomness); THRESHOLD],
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedCiphertext<G: AffineRepr, CT: BatchCiphertext<G>, const SUBSET_SIZE: usize>(
    [CT; SUBSET_SIZE],
    /// This is helper data for making the decryptor more efficient. The decryptor could compute this
    /// on its own from the proof.
    [G::ScalarField; SUBSET_SIZE],
);

impl<
        G: AffineRepr,
        CT: BatchCiphertext<G>,
        const NUM_PARTIES: usize,
        const THRESHOLD: usize,
        const NUM_PARTIES_MINUS_THRESHOLD: usize,
    > RdkgithProof<G, CT, NUM_PARTIES, THRESHOLD, NUM_PARTIES_MINUS_THRESHOLD>
{
    // assert_eq! does not compile in stable Rust
    const CHECK_THRESHOLD: () = assert!(THRESHOLD + NUM_PARTIES_MINUS_THRESHOLD == NUM_PARTIES);

    pub fn new<R: RngCore, D: Digest + FullDigest>(
        rng: &mut R,
        witnesses: Vec<G::ScalarField>,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
    ) -> Self {
        let () = Self::CHECK_THRESHOLD;
        let witness_count = witnesses.len();
        assert_eq!(comm_key.len(), witness_count);
        let mut hasher = D::default();
        let mut to_hash = Vec::with_capacity(commitment.compressed_size());

        hash_elem!(commitment, hasher, to_hash);
        for c in comm_key {
            hash_elem!(c, hasher, to_hash);
        }
        hash_elem!(enc_key, hasher, to_hash);
        hash_elem!(enc_gen, hasher, to_hash);

        let enc_key_table = WindowTable::new(NUM_PARTIES * witness_count, enc_key.into_group());
        let enc_gen_table = WindowTable::new(NUM_PARTIES * witness_count, enc_gen.into_group());

        let mut commitments = [G::zero(); THRESHOLD];
        let mut polys = Vec::with_capacity(witness_count);
        let mut shares: [Vec<G::ScalarField>; NUM_PARTIES] =
            [(); NUM_PARTIES].map(|_| vec![G::ScalarField::zero(); witness_count]);
        // Create randomness for encryption of each share
        let mut enc_rands: [CT::Randomness; NUM_PARTIES] =
            [(); NUM_PARTIES].map(|_| CT::get_randomness_from_rng(rng, witness_count));
        let mut cts: [CT; NUM_PARTIES] = [(); NUM_PARTIES].map(|_| CT::default());

        // Secret share each witness such that `THRESHOLD` + 1 shares are needed to reconstruct
        for (i, w) in witnesses.into_iter().enumerate() {
            let (s, mut poly) =
                deal_secret::<R, G::ScalarField>(rng, w, THRESHOLD as u16 + 1, NUM_PARTIES as u16)
                    .unwrap();
            for j in 0..NUM_PARTIES {
                shares[j][i] = s.0[j].share;
            }
            // 0th coefficient is the witness
            poly.coeffs.remove(0);
            polys.push(poly);
        }
        // Commit to coefficients of the polynomials
        cfg_iter_mut!(commitments)
            .enumerate()
            .for_each(|(i, cm_i)| {
                let coeffs = cfg_into_iter!(0..witness_count)
                    .map(|j| polys[j].coeffs[i])
                    .collect::<Vec<_>>();
                *cm_i = G::Group::msm_unchecked(comm_key, &coeffs).into_affine();
            });
        core::mem::drop(polys);

        // Encrypt each share
        cfg_iter_mut!(cts).enumerate().for_each(|(i, ct)| {
            *ct = CT::new::<D>(&shares[i], &enc_rands[i], &enc_key_table, &enc_gen_table);
        });

        for i in 0..THRESHOLD {
            hash_elem!(commitments[i], hasher, to_hash);
        }
        for i in 0..NUM_PARTIES {
            hash_elem!(cts[i], hasher, to_hash);
        }

        let challenge = Box::new(hasher).finalize().to_vec();
        // Indices of the `NUM_PARTIES_MINUS_THRESHOLD` parties for which ciphertexts of the shares will be given to the verifier.
        let indices_to_hide = get_unique_indices_to_hide::<D>(
            &challenge,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
            NUM_PARTIES as u16,
        );

        let mut ciphertexts: [(u16, CT); NUM_PARTIES_MINUS_THRESHOLD] =
            [(); NUM_PARTIES_MINUS_THRESHOLD].map(|_| (0, CT::default()));
        let mut shares_and_enc_rands: [(u16, Vec<G::ScalarField>, CT::Randomness); THRESHOLD] =
            [(); THRESHOLD].map(|_| {
                (
                    0,
                    Vec::with_capacity(witness_count),
                    CT::Randomness::default(),
                )
            });

        // Prepare `THRESHOLD` number of shares and encryption randomness and `NUM_PARTIES_MINUS_THRESHOLD` number of ciphertexts to share with the verifier
        let mut ctx_idx = 0;
        let mut s_idx = 0;
        for i in 0..NUM_PARTIES {
            if indices_to_hide.contains(&(i as u16)) {
                ciphertexts[ctx_idx].0 = i as u16;
                core::mem::swap(&mut ciphertexts[ctx_idx].1, &mut cts[i]);
                ctx_idx += 1;
            } else {
                shares_and_enc_rands[s_idx].0 = i as u16;
                core::mem::swap(&mut shares_and_enc_rands[s_idx].1, &mut shares[i]);
                core::mem::swap(&mut shares_and_enc_rands[s_idx].2, &mut enc_rands[i]);
                // shares_and_enc_rands[s_idx].1 = shares[i].clone();
                // shares_and_enc_rands[s_idx].2 = enc_rands[i].clone();
                s_idx += 1;
            }
        }

        debug_assert_eq!(ctx_idx, NUM_PARTIES_MINUS_THRESHOLD);
        debug_assert_eq!(s_idx, THRESHOLD);

        Self {
            challenge,
            poly_commitments: commitments,
            ciphertexts,
            shares_and_enc_rands,
        }
    }

    pub fn verify<D: FullDigest + Digest>(
        &self,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
    ) -> Result<(), VerifiableEncryptionError> {
        let () = Self::CHECK_THRESHOLD;
        let witness_count = comm_key.len();
        for i in 0..NUM_PARTIES_MINUS_THRESHOLD {
            assert_eq!(self.ciphertexts[i].1.batch_size(), witness_count);
        }
        for i in 0..THRESHOLD {
            assert_eq!(self.shares_and_enc_rands[i].1.len(), witness_count);
            assert!(CT::is_randomness_size_correct(
                &self.shares_and_enc_rands[i].2,
                witness_count
            ));
        }
        let hidden_indices = get_unique_indices_to_hide::<D>(
            &self.challenge,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
            NUM_PARTIES as u16,
        );
        for (i, _) in self.ciphertexts.iter() {
            assert!(hidden_indices.contains(i));
        }
        for (i, _, _) in self.shares_and_enc_rands.iter() {
            assert!(!hidden_indices.contains(i));
        }

        let mut hasher = D::default();
        let mut to_hash = Vec::with_capacity(commitment.compressed_size());

        hash_elem!(commitment, hasher, to_hash);
        for c in comm_key {
            hash_elem!(c, hasher, to_hash);
        }
        hash_elem!(enc_key, hasher, to_hash);
        hash_elem!(enc_gen, hasher, to_hash);

        let enc_key_table = WindowTable::new(NUM_PARTIES * witness_count, enc_key.into_group());
        let enc_gen_table = WindowTable::new(NUM_PARTIES * witness_count, enc_gen.into_group());

        let mut cts: [CT; NUM_PARTIES] = [(); NUM_PARTIES].map(|_| CT::default());

        cfg_iter_mut!(cts).enumerate().for_each(|(i, ct)| {
            if hidden_indices.contains(&(i as u16)) {
                // Ciphertexts given in the proof
                for (k, c) in &self.ciphertexts {
                    if i as u16 == *k {
                        *ct = c.clone();
                        break;
                    }
                }
            } else {
                for (k, s, r) in &self.shares_and_enc_rands {
                    // Create ciphertexts for shares and randomness given in the proof
                    if i as u16 == *k {
                        *ct = CT::new::<D>(s, r, &enc_key_table, &enc_gen_table);
                        break;
                    }
                }
            }
        });

        for i in 0..THRESHOLD {
            hash_elem!(self.poly_commitments[i], hasher, to_hash);
        }
        for i in 0..NUM_PARTIES {
            hash_elem!(cts[i], hasher, to_hash);
        }

        core::mem::drop(cts);

        let challenge = Box::new(hasher).finalize().to_vec();
        if challenge != self.challenge {
            return Err(VerifiableEncryptionError::InvalidProof);
        }

        // This is slow and was just for testing
        // for (i, sr) in &self.shares_and_enc_rands {
        //     let mut pows = powers::<G::ScalarField>(&G::ScalarField::from(i+1), THRESHOLD as u32 + 1);
        //     pows.remove(0);
        //     let shares = sr.into_iter().map(|j| j.0.clone()).collect::<Vec<_>>();
        //     if G::Group::msm_unchecked(comm_key, &shares) != (G::Group::msm_unchecked(&self.commitments, &pows) + *commitment) {
        //         return Err(VerifiableEncryptionError::InvalidProof);
        //     }
        // }

        // Need to check that the commitment to the coefficients of polynomials are consistent with the commitment to the shares.
        // Eg. each party i, check if G_1 * F_1(i) + ... + G_k * F_k(i) == commitment + poly_commitments[0] * i + poly_commitments[1] * i^2 + ... + poly_commitments[t-1] * i^{t-1}
        // Each check requires an MSM, which is expensive as we have to do `THRESHOLD` number of checks requiring `THRESHOLD`. So we combine these `THRESHOLD`
        // checks into 1 by using a random linear combination. i.e. rather than doing `THRESHOLD` checks of the form `LHS_i == RHS_i`, verifier generates `THRESHOLD`
        // number of random values `r_1, r_2, .., t_t` and checks if
        //  `LHS_1 * r_1 + LHS_2 * r_2 + ... LHS_t * r_t == RHS_1 * r_1 + RHS_2 * r_2 + ... RHS_t * r_t`  --- (1)
        // New LHS = `L` = `G_1 * ( F_1(1)*r_1 + F_1(2)*r_2 + ... + F_1(t)*r_t ) + G_2 * ( F_2(1)*r_1 + F_2(2)*r_2 + ... + F_2(t)*r_t ) + ... G_k * ( F_k(1)*r_1 + F_k(2)*r_2 + ... + F_k(t)*r_t )`  --- (2)
        // New RHS = `R` = `commitment * (r_1 + r_2 + ... r_t) + poly_commitments[0] * (r_1*1 + r_2*2 + ... r_t*t) + ... + poly_commitments[t-1]* (r_1*1^t + r_2*2^t + ... r_t*t^t)`

        let random = hash_to_field::<G::ScalarField, D>(b"", &D::digest(&self.challenge));
        // Create many randoms from single random
        // randoms = [1, random, random^2, ..., random^{t-1}], randoms[j] = random^j
        let randoms = powers::<G::ScalarField>(&random, THRESHOLD as u32);

        // For each witness, create sum of its share multiplied by a random value.
        // For witness i, create \sum_{j=1 to THRESHOLD}{s_{i,j} * randoms[j]}. These sums for the scalars which when multiplied
        // with commitment key give the new LHS `L` in above equation (2)
        let evals = cfg_into_iter!(0..witness_count)
            .map(|i| {
                cfg_iter!(self.shares_and_enc_rands)
                    .enumerate()
                    .map(|(j, (_, s, _))| s[i] * randoms[j])
                    .sum::<G::ScalarField>()
            })
            .collect::<Vec<_>>();

        // Powers of party indices, and each index's power multiplied by a random. s_i is the party index
        // [ [1, s_1, {s_1}^2, ..., {s_1}^t], [random, random*s_2, random*{s_2}^2, ..., random*{s_2}^t], [random^2, random^2*s_3, random^2*{s_3}^2, ..., random^2*{s_3}^t], ... [random^{t-1}, random^{t-1}*s_t, ..., random^{t-1}*{s_t}^{t-1}] ]
        let pows: Vec<_> = cfg_into_iter!(randoms)
            .zip(cfg_iter!(self.shares_and_enc_rands))
            .map(|(r, (j, _, _))| {
                powers_starting_from::<G::ScalarField>(
                    r,
                    &G::ScalarField::from(j + 1), // +1 because party indices start from 1.
                    THRESHOLD as u32 + 1,
                )
            })
            .collect::<Vec<_>>();

        // [1 + random + random^2 + .. + random^{t-1}, s_1 + random*s_2 + random^2*s_3 .. + random^{t-1}*s_t, .., {s_1}^t + random*{s_2}^t + .. random^{t-1}*{s_t}^{t-1}]
        let mut power_sums = cfg_into_iter!(0..THRESHOLD + 1)
            .map(|i| {
                cfg_into_iter!(0..THRESHOLD)
                    .map(|j| pows[j][i])
                    .sum::<G::ScalarField>()
            })
            .collect::<Vec<_>>();

        let mut c = self.poly_commitments.to_vec();
        c.insert(0, *commitment);

        // if G::Group::msm_unchecked(comm_key, &evals) != G::Group::msm_unchecked(&c, &power_sums) {
        //     return Err(VerifiableEncryptionError::InvalidProof);
        // }
        // Convert above 2 MSMs into 1
        c.extend_from_slice(comm_key);
        let mut evals = cfg_into_iter!(evals).map(|e| -e).collect::<Vec<_>>();
        power_sums.append(&mut evals);
        if G::Group::msm_unchecked(&c, &power_sums) != G::Group::zero() {
            return Err(VerifiableEncryptionError::InvalidProof);
        }
        Ok(())
    }

    /// Described in Appendix D.2 in the paper
    pub fn compress<const SUBSET_SIZE: usize, D: Digest + FullDigest>(
        &self,
    ) -> CompressedCiphertext<G, CT, SUBSET_SIZE> {
        let () = Self::CHECK_THRESHOLD;
        const { assert!(SUBSET_SIZE <= NUM_PARTIES_MINUS_THRESHOLD) };
        let hidden_indices = get_unique_indices_to_hide::<D>(
            &self.challenge,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
            NUM_PARTIES as u16,
        );
        for (i, _) in self.ciphertexts.iter() {
            assert!(hidden_indices.contains(i));
        }
        for (i, _, _) in self.shares_and_enc_rands.iter() {
            assert!(!hidden_indices.contains(i));
        }
        let witness_count = self.ciphertexts[0].1.batch_size();
        let mut compressed_cts: [CT; SUBSET_SIZE] = [(); SUBSET_SIZE].map(|_| CT::default());

        // Party indices for which shares are revealed
        let mut opened_indices = Vec::with_capacity(THRESHOLD);
        for i in 0..NUM_PARTIES as u16 {
            if !hidden_indices.contains(&i) {
                // 1 is added to each party's index so that no index is 0 as polynomial can't be evaluated at 0
                opened_indices.push(i + 1);
            }
        }
        let hidden_indices = hidden_indices.into_iter().collect::<Vec<_>>();

        // Choose a random subset of size `SUBSET_SIZE` from the indices of `hidden_indices`
        let mut challenge_for_subset_gen = self.challenge.clone();
        for (i, s, r) in &self.shares_and_enc_rands {
            challenge_for_subset_gen.push((i & 255) as u8);
            challenge_for_subset_gen.push(((i >> 8) & 255) as u8);
            for s_i in s {
                s_i.serialize_compressed(&mut challenge_for_subset_gen)
                    .unwrap();
            }
            r.serialize_compressed(&mut challenge_for_subset_gen)
                .unwrap();
        }
        let subset = get_unique_indices_to_hide::<D>(
            &D::digest(&challenge_for_subset_gen),
            SUBSET_SIZE as u16,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
        )
        .into_iter()
        .map(|i| hidden_indices[i as usize])
        .collect::<Vec<_>>();

        // Lagrange basis for each index in `opened_indices`
        let lagrange_basis_for_opened_indices =
            lagrange_basis_at_0_for_all::<G::ScalarField>(opened_indices.clone()).unwrap();

        // Lagrange basis for each index in `subset`
        let mut lagrange_basis_for_hidden_indices = [G::ScalarField::zero(); SUBSET_SIZE];
        cfg_iter_mut!(lagrange_basis_for_hidden_indices)
            .enumerate()
            .for_each(|(i, l_i)| {
                *l_i =
                    lagrange_basis_at_0::<G::ScalarField>(&opened_indices, subset[i] + 1).unwrap()
            });

        cfg_iter_mut!(compressed_cts)
            .enumerate()
            .for_each(|(i, ct)| {
                // +1 as polynomial can't be evaluated at 0
                let party_index = subset[i] + 1;

                let mut cphtx_idx = None;
                for (j, (k, _)) in self.ciphertexts.iter().enumerate() {
                    if *k == subset[i] {
                        cphtx_idx = Some(j);
                    }
                }
                let cphtx_idx = cphtx_idx.unwrap();

                let deltas = cfg_iter!(opened_indices)
                    .enumerate()
                    .map(|(j, o)| {
                        let p = G::ScalarField::from(party_index);
                        let o = G::ScalarField::from(*o);
                        (lagrange_basis_for_opened_indices[j] * p) * (p - o).inverse().unwrap()
                    })
                    .collect::<Vec<_>>();

                let offset = cfg_into_iter!(0..witness_count)
                    .map(|j| {
                        cfg_iter!(deltas)
                            .zip(cfg_iter!(self.shares_and_enc_rands))
                            .map(|(d, (_, s, _))| *d * s[j])
                            .sum::<G::ScalarField>()
                    })
                    .collect::<Vec<_>>();
                *ct = self.ciphertexts[cphtx_idx].1.clone();
                ct.multiply_with_ciphertexts(&lagrange_basis_for_hidden_indices[i]);
                ct.add_to_ciphertexts(&offset);
            });

        CompressedCiphertext(compressed_cts, lagrange_basis_for_hidden_indices)
    }

    pub fn witness_count(&self) -> usize {
        self.ciphertexts[0].1.batch_size()
    }
}

impl<G: AffineRepr, CT: BatchCiphertext<G>, const SUBSET_SIZE: usize>
    CompressedCiphertext<G, CT, SUBSET_SIZE>
{
    pub fn decrypt<D: FullDigest>(
        &self,
        dec_key: &G::ScalarField,
        commitment: &G,
        comm_key: &[G],
    ) -> Result<Vec<G::ScalarField>, VerifiableEncryptionError> {
        let witness_count = comm_key.len();
        for i in 0..SUBSET_SIZE {
            assert_eq!(self.0[i].batch_size(), witness_count);
            let witnesses = self.0[i].decrypt_after_multiplying_otp::<D>(&self.1[i], dec_key);
            if *commitment == G::Group::msm_unchecked(comm_key, &witnesses).into_affine() {
                return Ok(witnesses);
            }
        }
        Err(VerifiableEncryptionError::DecryptionFailed)
    }

    pub fn encrypted_count(&self) -> usize {
        self.0[0].batch_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tz_21::encryption::SimpleBatchElgamalCiphertext;
    use ark_bls12_381::G1Affine;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::elgamal::{keygen, BatchedHashedElgamalCiphertext};
    use std::time::Instant;

    #[test]
    fn prove_verify() {
        fn check<G: AffineRepr>(count: usize) {
            let mut rng = StdRng::seed_from_u64(0u64);

            let gen = G::rand(&mut rng);
            let (sk, pk) = keygen::<_, G>(&mut rng, &gen);

            let witnesses = (0..count)
                .map(|_| G::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();
            let comm_key = (0..count).map(|_| G::rand(&mut rng)).collect::<Vec<_>>();
            let commitment = G::Group::msm_unchecked(&comm_key, &witnesses).into_affine();

            macro_rules! run_test {
                ($parties: expr, $threshold: expr, $parties_minus_thresh: expr, $subset_size: expr, $ct_type: ty, $ct_type_name: expr) => {{
                    println!(
                        "\nFor {} hashed Elgamal encryption, # witnesses = {}, # parties = {}, # threshold = {}, subset size = {}",
                        $ct_type_name, count, $parties, $threshold, $subset_size
                    );
                    let start = Instant::now();
                    let proof = RdkgithProof::<
                        _,
                        $ct_type,
                        $parties,
                        $threshold,
                        $parties_minus_thresh,
                    >::new::<_, Blake2b512>(
                        &mut rng,
                        witnesses.clone(),
                        &commitment,
                        &comm_key,
                        &pk.0,
                        &gen,
                    );
                    println!("Proof generated in: {:?}", start.elapsed());

                    for i in 0..$threshold {
                        assert_eq!(proof.shares_and_enc_rands[i].1.len(), count);
                        assert!(<$ct_type>::is_randomness_size_correct(&proof.shares_and_enc_rands[i].2, count));
                    }

                    for i in 0..$parties_minus_thresh {
                        assert_eq!(proof.ciphertexts[i].1.batch_size(), count);
                    }

                    let start = Instant::now();
                    proof
                        .verify::<Blake2b512>(&commitment, &comm_key, &pk.0, &gen)
                        .unwrap();
                    println!("Proof verified in: {:?}", start.elapsed());
                    println!("Proof size: {:?}", proof.compressed_size());

                    let start = Instant::now();
                    let ct = proof.compress::<$subset_size, Blake2b512>();
                    println!("Ciphertext compressed in: {:?}", start.elapsed());
                    println!("Ciphertext size: {:?}", ct.compressed_size());

                    for i in 0..$subset_size {
                        assert_eq!(ct.0[i].batch_size(), count);
                    }

                    let start = Instant::now();
                    let decrypted_witnesses = ct
                        .decrypt::<Blake2b512>(&sk.0, &commitment, &comm_key)
                        .unwrap();
                    println!("Ciphertext decrypted in: {:?}", start.elapsed());
                    assert_eq!(decrypted_witnesses, witnesses);
                }};
            }

            let name1 = "simple";
            let name2 = "batched";

            run_test!(132, 64, 68, 67, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(192, 36, 156, 145, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(512, 23, 489, 406, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(160, 80, 80, 55, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(256, 226, 30, 30, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(704, 684, 20, 20, SimpleBatchElgamalCiphertext<G>, name1);

            run_test!(132, 64, 68, 67, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(192, 36, 156, 145, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(512, 23, 489, 406, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(160, 80, 80, 55, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(256, 226, 30, 30, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(704, 684, 20, 20, BatchedHashedElgamalCiphertext<G>, name2);
        }

        check::<G1Affine>(1);
        check::<G1Affine>(2);
        check::<G1Affine>(3);
        check::<G1Affine>(4);
        check::<G1Affine>(8);
    }
}
