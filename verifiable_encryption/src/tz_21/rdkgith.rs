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

use crate::{error::VerifiableEncryptionError, tz_21::util::get_unique_indices_to_hide};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, rand::RngCore, UniformRand};
use digest::{Digest, DynDigest};
use dock_crypto_utils::{
    aliases::FullDigest,
    elgamal::HashedElgamalCiphertext,
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

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RdkgithProof<
    const NUM_PARTIES: usize,
    const THRESHOLD: usize,
    const NUM_PARTIES_MINUS_THRESHOLD: usize,
    G: AffineRepr,
> {
    pub challenge: Vec<u8>,
    /// Commitment to the coefficients of polynomials
    pub poly_commitments: [G; THRESHOLD],
    /// Ciphertexts of the shares. The first element of the tuple is the party index
    // Following could be made a map indexed with u16 to speed up computation (lookups) by trading off memory
    pub ciphertexts: [(u16, Vec<HashedElgamalCiphertext<G>>); NUM_PARTIES_MINUS_THRESHOLD],
    /// Revealed shares and randomness used for encryption. The first element of the tuple is the party index
    pub shares_and_enc_rands: [(u16, Vec<(G::ScalarField, G::ScalarField)>); THRESHOLD],
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedCiphertext<const SUBSET_SIZE: usize, G: AffineRepr>(
    [Vec<HashedElgamalCiphertext<G>>; SUBSET_SIZE],
    /// This is helper data for making the decryptor more efficient. The decryptor could compute this
    /// on its own from the proof.
    [G::ScalarField; SUBSET_SIZE],
);

impl<
        const NUM_PARTIES: usize,
        const THRESHOLD: usize,
        const NUM_PARTIES_MINUS_THRESHOLD: usize,
        G: AffineRepr,
    > RdkgithProof<NUM_PARTIES, THRESHOLD, NUM_PARTIES_MINUS_THRESHOLD, G>
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
        let mut shares = Vec::with_capacity(witness_count);
        let mut enc_rands: Vec<[G::ScalarField; NUM_PARTIES]> = Vec::with_capacity(witness_count);
        let mut cts: [Vec<HashedElgamalCiphertext<G>>; NUM_PARTIES] =
            [(); NUM_PARTIES].map(|_| vec![HashedElgamalCiphertext::<G>::default(); witness_count]);

        // Secret share each witness such that `THRESHOLD` + 1 shares are needed to reconstruct
        for w in witnesses {
            let (s, mut poly) =
                deal_secret::<R, G::ScalarField>(rng, w, THRESHOLD as u16 + 1, NUM_PARTIES as u16)
                    .unwrap();
            shares.push(s);
            // 0th coefficient is the witness
            poly.coeffs.remove(0);
            polys.push(poly);
            // Create randomness for encryption of each share
            let mut r = [G::ScalarField::zero(); NUM_PARTIES];
            for i in 0..NUM_PARTIES {
                r[i] = G::ScalarField::rand(rng);
            }
            enc_rands.push(r);
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
        // Encrypt each share
        cfg_iter_mut!(cts).enumerate().for_each(|(i, ct)| {
            cfg_iter_mut!(ct).enumerate().for_each(|(j, ct_j)| {
                *ct_j = HashedElgamalCiphertext::new_given_randomness_and_window_tables::<D>(
                    &shares[j].0[i].share,
                    &enc_rands[j][i],
                    &enc_key_table,
                    &enc_gen_table,
                );
            });
        });

        for i in 0..THRESHOLD {
            hash_elem!(commitments[i], hasher, to_hash);
        }
        for i in 0..NUM_PARTIES {
            for j in 0..witness_count {
                hash_elem!(cts[i][j], hasher, to_hash);
            }
        }

        let challenge = Box::new(hasher).finalize().to_vec();
        // Indices of the `NUM_PARTIES_MINUS_THRESHOLD` parties for which ciphertexts of the shares will be given to the verifier.
        let indices_to_hide = get_unique_indices_to_hide::<D>(
            &challenge,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
            NUM_PARTIES as u16,
        );

        let mut ciphertexts: [(u16, Vec<HashedElgamalCiphertext<G>>); NUM_PARTIES_MINUS_THRESHOLD] =
            [(); NUM_PARTIES_MINUS_THRESHOLD].map(|_| (0, Vec::with_capacity(witness_count)));
        let mut shares_and_enc_rands: [(u16, Vec<(G::ScalarField, G::ScalarField)>); THRESHOLD] =
            [(); THRESHOLD].map(|_| (0, Vec::with_capacity(witness_count)));

        // Prepare `THRESHOLD` number of shares and encryption randomness and `NUM_PARTIES_MINUS_THRESHOLD` number of ciphertexts to share with the verifier
        let mut ctx_idx = 0;
        let mut s_idx = 0;
        for i in 0..NUM_PARTIES {
            if indices_to_hide.contains(&(i as u16)) {
                ciphertexts[ctx_idx].0 = i as u16;
                for j in 0..witness_count {
                    ciphertexts[ctx_idx].1.push(cts[i][j]);
                }
                ctx_idx += 1;
            } else {
                shares_and_enc_rands[s_idx].0 = i as u16;
                for j in 0..witness_count {
                    shares_and_enc_rands[s_idx]
                        .1
                        .push((shares[j].0[i].share, enc_rands[j][i]));
                }
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

    fn verify<D: FullDigest + Digest>(
        &self,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
    ) -> Result<(), VerifiableEncryptionError> {
        let () = Self::CHECK_THRESHOLD;
        let witness_count = comm_key.len();
        for i in 0..NUM_PARTIES_MINUS_THRESHOLD {
            assert_eq!(self.ciphertexts[i].1.len(), witness_count);
        }
        for i in 0..THRESHOLD {
            assert_eq!(self.shares_and_enc_rands[i].1.len(), witness_count);
        }
        let hidden_indices = get_unique_indices_to_hide::<D>(
            &self.challenge,
            NUM_PARTIES_MINUS_THRESHOLD as u16,
            NUM_PARTIES as u16,
        );
        for (i, _) in self.ciphertexts.iter() {
            assert!(hidden_indices.contains(i));
        }
        for (i, _) in self.shares_and_enc_rands.iter() {
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

        let mut cts: [Vec<HashedElgamalCiphertext<G>>; NUM_PARTIES] =
            [(); NUM_PARTIES].map(|_| vec![HashedElgamalCiphertext::<G>::default(); witness_count]);

        cfg_iter_mut!(cts).enumerate().for_each(|(i, ct)| {
            if hidden_indices.contains(&(i as u16)) {
                // Ciphertexts given in the proof
                for (k, c) in &self.ciphertexts {
                    if i as u16 == *k {
                        *ct = c.clone();
                        break
                    }
                }
            } else {
                for (k, sr) in &self.shares_and_enc_rands {
                    // Create ciphertexts for shares and randomness given in the proof
                    if i as u16 == *k {
                        *ct = cfg_into_iter!(0..witness_count).map(|j| HashedElgamalCiphertext::new_given_randomness_and_window_tables::<D>(&sr[j].0, &sr[j].1, &enc_key_table, &enc_gen_table)).collect();
                        break
                    }
                }
            }
        });

        for i in 0..THRESHOLD {
            hash_elem!(self.poly_commitments[i], hasher, to_hash);
        }
        for i in 0..NUM_PARTIES {
            for j in 0..witness_count {
                hash_elem!(cts[i][j], hasher, to_hash);
            }
        }

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
                    .map(|(j, (_, sr))| sr[i].0 * randoms[j])
                    .sum::<G::ScalarField>()
            })
            .collect::<Vec<_>>();

        // Powers of party indices, and each index's power multiplied by a random. s_i is the party index
        // [ [1, s_1, {s_1}^2, ..., {s_1}^t], [random, random*s_2, random*{s_2}^2, ..., random*{s_2}^t], [random^2, random^2*s_3, random^2*{s_3}^2, ..., random^2*{s_3}^t], ... [random^{t-1}, random^{t-1}*s_t, ..., random^{t-1}*{s_t}^{t-1}] ]
        let pows: Vec<_> = cfg_into_iter!(randoms)
            .zip(cfg_iter!(self.shares_and_enc_rands))
            .map(|(r, (j, _))| {
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
    ) -> CompressedCiphertext<SUBSET_SIZE, G> {
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
        for (i, _) in self.shares_and_enc_rands.iter() {
            assert!(!hidden_indices.contains(i));
        }
        let witness_count = self.ciphertexts[0].1.len();
        let mut compressed_cts: [Vec<HashedElgamalCiphertext<G>>; SUBSET_SIZE] =
            [(); SUBSET_SIZE].map(|_| vec![HashedElgamalCiphertext::<G>::default(); witness_count]);

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
        // TODO: Check if this is secure. The objective is to avoid the use of random number generation on the verifier side
        let subset = get_unique_indices_to_hide::<D>(
            &D::digest(&self.challenge),
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

                cfg_iter_mut!(ct).enumerate().for_each(|(j, ct_j)| {
                    ct_j.eph_pk = self.ciphertexts[cphtx_idx].1[j].eph_pk;
                    ct_j.encrypted = self.ciphertexts[cphtx_idx].1[j].encrypted
                        * lagrange_basis_for_hidden_indices[i];
                    ct_j.encrypted += cfg_iter!(deltas)
                        .zip(cfg_iter!(self.shares_and_enc_rands))
                        .map(|(d, (_, sr))| *d * sr[j].0)
                        .sum::<G::ScalarField>();
                })
            });

        CompressedCiphertext(compressed_cts, lagrange_basis_for_hidden_indices)
    }
}

impl<const SUBSET_SIZE: usize, G: AffineRepr> CompressedCiphertext<SUBSET_SIZE, G> {
    pub fn decrypt<D: FullDigest>(
        &self,
        dec_key: &G::ScalarField,
        commitment: &G,
        comm_key: &[G],
    ) -> Result<Vec<G::ScalarField>, VerifiableEncryptionError> {
        let witness_count = comm_key.len();
        for i in 0..SUBSET_SIZE {
            assert_eq!(self.0[i].len(), witness_count);
            let witnesses = cfg_into_iter!(0..witness_count)
                .map(|j| {
                    let otp = self.1[i]
                        * HashedElgamalCiphertext::otp::<D>(
                            (self.0[i][j].eph_pk * dec_key).into_affine(),
                        );
                    self.0[i][j].encrypted - otp
                })
                .collect::<Vec<_>>();
            if *commitment == G::Group::msm_unchecked(comm_key, &witnesses).into_affine() {
                return Ok(witnesses);
            }
        }
        Err(VerifiableEncryptionError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Affine;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::elgamal::keygen;
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
                ($parties: expr, $threshold: expr, $parties_minus_thresh: expr, $subset_size: expr) => {{
                    println!(
                        "\n# witnesses = {}, # parties = {}, # threshold = {}, subset size = {}",
                        count, $parties, $threshold, $subset_size
                    );
                    let start = Instant::now();
                    let proof = RdkgithProof::<
                        $parties,
                        $threshold,
                        $parties_minus_thresh,
                        _,
                    >::new::<_, Blake2b512>(
                        &mut rng,
                        witnesses.clone(),
                        &commitment,
                        &comm_key,
                        &pk.0,
                        &gen,
                    );
                    println!("Proof generated in: {:?}", start.elapsed());

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

                    let start = Instant::now();
                    let decrypted_witnesses = ct
                        .decrypt::<Blake2b512>(&sk.0, &commitment, &comm_key)
                        .unwrap();
                    println!("Ciphertext decrypted in: {:?}", start.elapsed());
                    assert_eq!(decrypted_witnesses, witnesses);
                }};
            }

            run_test!(132, 64, 68, 67);
            run_test!(192, 36, 156, 145);
            run_test!(512, 23, 489, 406);
            run_test!(160, 80, 80, 55);
            run_test!(256, 226, 30, 30);
            run_test!(704, 684, 20, 20);
        }

        check::<G1Affine>(1);
        check::<G1Affine>(2);
        check::<G1Affine>(3);
        check::<G1Affine>(4);
        check::<G1Affine>(8);
    }
}
