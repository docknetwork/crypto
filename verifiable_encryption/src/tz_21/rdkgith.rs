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
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, rand::RngCore, vec, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    aliases::FullDigest,
    ff::{powers, powers_starting_from},
    hashing_utils::hash_to_field,
    msm::WindowTable,
    transcript::Transcript,
};
use secret_sharing_and_dkg::{
    common::{lagrange_basis_at_0, lagrange_basis_at_0_for_all},
    shamir_ss::deal_secret,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

const POLY_COMMITMENT_LABEL: &'static [u8; 16] = b"poly_commitments";
const CIPHERTEXTS_LABEL: &'static [u8; 11] = b"ciphertexts";
const CHALLENGE_LABEL: &'static [u8; 9] = b"challenge";

/// Ciphertext and the proof of encryption. `CT` is the variant of Elgamal encryption used. See test for usage
/// Some of the struct fields like, `ciphertexts`, `poly_commitments` etc. could be created as arrays rather than vectors
/// as their length depends on the generic constants but as the constants are large, it causes stack-overflow.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RdkgithProof<
    G: AffineRepr,
    CT: BatchCiphertext<G>,
    const NUM_PARTIES: usize,
    const THRESHOLD: usize,
> {
    pub challenge: Vec<u8>,
    /// Commitment to the coefficients of polynomials
    pub poly_commitments: Vec<G>,
    /// Ciphertexts of the shares. The first element of the tuple is the party index
    // Following could be made a map indexed with u16 to speed up computation (lookups) by trading off memory
    pub ciphertexts: Vec<(u16, CT)>,
    /// Revealed shares and randomness used for encryption. The first element of the tuple is the party index, second is the
    /// shares of each witness for that party
    pub shares_and_enc_rands: Vec<(u16, Vec<G::ScalarField>, CT::Randomness)>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedCiphertext<G: AffineRepr, CT: BatchCiphertext<G>, const SUBSET_SIZE: usize>(
    /// Ciphertexts
    Vec<CT>,
    /// This is helper data for making the decryptor more efficient. The decryptor could compute this
    /// on its own from the proof.
    Vec<G::ScalarField>,
);

impl<G: AffineRepr, CT: BatchCiphertext<G>, const NUM_PARTIES: usize, const THRESHOLD: usize>
    RdkgithProof<G, CT, NUM_PARTIES, THRESHOLD>
{
    // assert_eq! does not compile in stable Rust
    const CHECK_THRESHOLD: () = assert!(THRESHOLD <= NUM_PARTIES);

    /// Create verifiable encryption of vector `witnesses` that are also committed in a Pedersen commitment
    /// created with the commitment key `comm_key`. The encryption key is `enc_key` and group generator
    /// used in that key is `gen`. Its assumed that the public values like commitment key, commitment, encryption key,
    /// encryption key generator are all included in the transcript.
    pub fn new<R: RngCore, D: Digest + FullDigest>(
        rng: &mut R,
        witnesses: Vec<G::ScalarField>,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
        transcript: &mut impl Transcript,
    ) -> Result<Self, VerifiableEncryptionError> {
        let () = Self::CHECK_THRESHOLD;
        let witness_count = witnesses.len();
        if comm_key.len() != witness_count {
            return Err(VerifiableEncryptionError::UnexpectedCommitmentKeySize(
                comm_key.len(),
                witness_count,
            ));
        }

        let enc_key_table = WindowTable::new(NUM_PARTIES * witness_count, enc_key.into_group());
        let enc_gen_table = WindowTable::new(NUM_PARTIES * witness_count, enc_gen.into_group());

        let mut commitments = vec![G::zero(); THRESHOLD];
        let mut polys = Vec::with_capacity(witness_count);
        let mut shares: Vec<Vec<G::ScalarField>> = (0..NUM_PARTIES)
            .map(|_| vec![G::ScalarField::zero(); witness_count])
            .collect();
        // Create randomness for encryption of each share
        let mut enc_rands: Vec<CT::Randomness> = (0..NUM_PARTIES)
            .map(|_| CT::get_randomness_from_rng(rng, witness_count))
            .collect();
        let mut cts: Vec<CT> = (0..NUM_PARTIES).map(|_| CT::default()).collect();

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
            // hash_elem!(commitments[i], hasher, to_hash);
            transcript.append(POLY_COMMITMENT_LABEL, &commitments[i]);
        }
        for i in 0..NUM_PARTIES {
            // hash_elem!(cts[i], hasher, to_hash);
            transcript.append(CIPHERTEXTS_LABEL, &cts[i]);
        }

        // Challenge can also be an array since the digest function is a parameter which makes the output size also known at compile time
        let mut challenge = vec![0; (NUM_PARTIES - THRESHOLD) * 2];
        transcript.challenge_bytes(CHALLENGE_LABEL, &mut challenge);
        let num_hidden = (NUM_PARTIES - THRESHOLD) as u16;
        // Indices of the `num_hidden` parties for which ciphertexts of the shares will be given to the verifier.
        let indices_to_hide =
            get_unique_indices_to_hide::<D>(&challenge, num_hidden, NUM_PARTIES as u16);

        let mut ciphertexts: Vec<(u16, CT)> = (0..num_hidden).map(|_| (0, CT::default())).collect();
        let mut shares_and_enc_rands: Vec<(u16, Vec<G::ScalarField>, CT::Randomness)> = (0
            ..THRESHOLD)
            .map(|_| {
                (
                    0,
                    Vec::with_capacity(witness_count),
                    CT::Randomness::default(),
                )
            })
            .collect();

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

        debug_assert_eq!(ctx_idx, num_hidden as usize);
        debug_assert_eq!(s_idx, THRESHOLD);

        Ok(Self {
            challenge,
            poly_commitments: commitments,
            ciphertexts,
            shares_and_enc_rands,
        })
    }

    /// Verify the proof of verifiable encryption of values that are also committed in a Pedersen commitment
    /// `commitment` created with the commitment key `comm_key`. The encryption key is `enc_key` and group
    /// generator used in that key is `gen`. Its assumed that the public values like commitment key, commitment,
    /// encryption key, encryption key generator are all included in the transcript.
    pub fn verify<D: FullDigest + Digest>(
        &self,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
        transcript: &mut impl Transcript,
    ) -> Result<(), VerifiableEncryptionError> {
        let () = Self::CHECK_THRESHOLD;
        let witness_count = comm_key.len();
        let num_hidden = NUM_PARTIES - THRESHOLD;
        if self.poly_commitments.len() != THRESHOLD {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfCommitments(
                self.poly_commitments.len(),
                THRESHOLD,
            ));
        }
        if self.ciphertexts.len() != num_hidden {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfCiphertexts(
                self.ciphertexts.len(),
                num_hidden,
            ));
        }
        if self.shares_and_enc_rands.len() != THRESHOLD {
            return Err(
                VerifiableEncryptionError::UnexpectedNumberOfSharesAndEncRands(
                    self.shares_and_enc_rands.len(),
                    THRESHOLD,
                ),
            );
        }
        for i in 0..num_hidden {
            if self.ciphertexts[i].1.batch_size() != witness_count {
                return Err(
                    VerifiableEncryptionError::InequalNumberOfCiphertextsAndWitnesses(
                        self.ciphertexts[i].1.batch_size(),
                        witness_count,
                    ),
                );
            }
        }
        for i in 0..THRESHOLD {
            if self.shares_and_enc_rands[i].1.len() != witness_count {
                return Err(
                    VerifiableEncryptionError::InequalNumberOfSharesAndWitnesses(
                        self.shares_and_enc_rands[i].1.len(),
                        witness_count,
                    ),
                );
            }
            if !CT::is_randomness_size_correct(&self.shares_and_enc_rands[i].2, witness_count) {
                return Err(VerifiableEncryptionError::IncompatibleRandomnessSize);
            }
        }
        let hidden_indices =
            get_unique_indices_to_hide::<D>(&self.challenge, num_hidden as u16, NUM_PARTIES as u16);
        for (i, _) in self.ciphertexts.iter() {
            if !hidden_indices.contains(i) {
                return Err(VerifiableEncryptionError::CiphertextNotFound(*i));
            }
        }

        let enc_key_table = WindowTable::new(NUM_PARTIES * witness_count, enc_key.into_group());
        let enc_gen_table = WindowTable::new(NUM_PARTIES * witness_count, enc_gen.into_group());

        let mut cts: Vec<CT> = (0..NUM_PARTIES).map(|_| CT::default()).collect();

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
            transcript.append(POLY_COMMITMENT_LABEL, &self.poly_commitments[i]);
        }
        for i in 0..NUM_PARTIES {
            transcript.append(CIPHERTEXTS_LABEL, &cts[i]);
        }

        core::mem::drop(cts);

        let mut challenge = vec![0; (NUM_PARTIES - THRESHOLD) * 2];
        transcript.challenge_bytes(CHALLENGE_LABEL, &mut challenge);
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
    ) -> Result<CompressedCiphertext<G, CT, SUBSET_SIZE>, VerifiableEncryptionError> {
        let () = Self::CHECK_THRESHOLD;
        let num_hidden = NUM_PARTIES - THRESHOLD;
        if SUBSET_SIZE > num_hidden {
            return Err(VerifiableEncryptionError::SubsetSizeGreaterThenExpected(
                SUBSET_SIZE,
                num_hidden,
            ));
        }
        let hidden_indices =
            get_unique_indices_to_hide::<D>(&self.challenge, num_hidden as u16, NUM_PARTIES as u16);
        for (i, _) in self.ciphertexts.iter() {
            if !hidden_indices.contains(i) {
                return Err(VerifiableEncryptionError::CiphertextNotFound(*i));
            }
        }
        let witness_count = self.ciphertexts[0].1.batch_size();
        let mut compressed_cts: Vec<CT> = (0..SUBSET_SIZE).map(|_| CT::default()).collect();

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
            num_hidden as u16,
        )
        .into_iter()
        .map(|i| hidden_indices[i as usize])
        .collect::<Vec<_>>();

        // Lagrange basis for each index in `opened_indices`
        let lagrange_basis_for_opened_indices =
            lagrange_basis_at_0_for_all::<G::ScalarField>(opened_indices.clone()).unwrap();

        // Lagrange basis for each index in `subset`
        let mut lagrange_basis_for_hidden_indices = vec![G::ScalarField::zero(); SUBSET_SIZE];
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

        Ok(CompressedCiphertext(
            compressed_cts,
            lagrange_basis_for_hidden_indices,
        ))
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
        if self.0.len() != SUBSET_SIZE {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfCiphertexts(
                self.0.len(),
                SUBSET_SIZE,
            ));
        }
        if self.1.len() != SUBSET_SIZE {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfHelperData(
                self.1.len(),
                SUBSET_SIZE,
            ));
        }
        for i in 0..SUBSET_SIZE {
            if self.0[i].batch_size() != witness_count {
                return Err(
                    VerifiableEncryptionError::InequalNumberOfCiphertextsAndWitnesses(
                        self.0[i].batch_size(),
                        witness_count,
                    ),
                );
            }
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
    use dock_crypto_utils::{
        elgamal::{keygen, BatchedHashedElgamalCiphertext},
        transcript::new_merlin_transcript,
    };
    use std::time::Instant;

    #[test]
    fn prove_verify() {
        fn check<G: AffineRepr>(num_witnesses: usize) {
            let mut rng = StdRng::seed_from_u64(0u64);

            let gen = G::rand(&mut rng);
            let (sk, pk) = keygen::<_, G>(&mut rng, &gen);

            let witnesses = (0..num_witnesses)
                .map(|_| G::ScalarField::rand(&mut rng))
                .collect::<Vec<_>>();
            let comm_key = (0..num_witnesses)
                .map(|_| G::rand(&mut rng))
                .collect::<Vec<_>>();
            let commitment = G::Group::msm_unchecked(&comm_key, &witnesses).into_affine();

            macro_rules! run_test {
                ($parties: expr, $threshold: expr, $subset_size: expr, $ct_type: ty, $ct_type_name: expr) => {{
                    println!(
                        "\nFor {} hashed Elgamal encryption, # witnesses = {}, # parties = {}, # threshold = {}, subset size = {}",
                        $ct_type_name, num_witnesses, $parties, $threshold, $subset_size
                    );
                    let parties_minus_thresh = $parties - $threshold;
                    let start = Instant::now();
                    let mut prover_transcript = new_merlin_transcript(b"test");
                    prover_transcript.append(b"comm_key", &comm_key);
                    prover_transcript.append(b"enc_key", &pk);
                    prover_transcript.append(b"enc_gen", &gen);
                    prover_transcript.append(b"commitment", &commitment);
                    let proof = RdkgithProof::<
                        _,
                        $ct_type,
                        $parties,
                        $threshold,
                    >::new::<_, Blake2b512>(
                        &mut rng,
                        witnesses.clone(),
                        &comm_key,
                        &pk.0,
                        &gen,
                        &mut prover_transcript
                    ).unwrap();
                    println!("Proof generated in: {:?}", start.elapsed());

                    for i in 0..$threshold {
                        assert_eq!(proof.shares_and_enc_rands[i].1.len(), num_witnesses);
                        assert!(<$ct_type>::is_randomness_size_correct(&proof.shares_and_enc_rands[i].2, num_witnesses));
                    }

                    for i in 0..parties_minus_thresh {
                        assert_eq!(proof.ciphertexts[i].1.batch_size(), num_witnesses);
                    }

                    let start = Instant::now();
                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key", &comm_key);
                    verifier_transcript.append(b"enc_key", &pk);
                    verifier_transcript.append(b"enc_gen", &gen);
                    verifier_transcript.append(b"commitment", &commitment);
                    proof
                        .verify::<Blake2b512>(&commitment, &comm_key, &pk.0, &gen, &mut verifier_transcript)
                        .unwrap();
                    println!("Proof verified in: {:?}", start.elapsed());
                    println!("Proof size: {:?}", proof.compressed_size());

                    let invalid_comm = (commitment + G::rand(&mut rng)).into_affine();
                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key", &comm_key);
                    verifier_transcript.append(b"enc_key", &pk);
                    verifier_transcript.append(b"enc_gen", &gen);
                    verifier_transcript.append(b"commitment", &invalid_comm);
                    assert!(proof
                        .verify::<Blake2b512>(&invalid_comm, &comm_key, &pk.0, &gen, &mut verifier_transcript).is_err());

                    let invalid_pk = G::rand(&mut rng);
                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key", &comm_key);
                    verifier_transcript.append(b"enc_key", &invalid_pk);
                    verifier_transcript.append(b"enc_gen", &gen);
                    verifier_transcript.append(b"commitment", &commitment);
                    assert!(proof
                        .verify::<Blake2b512>(&commitment, &comm_key, &invalid_pk, &gen, &mut verifier_transcript).is_err());

                    let start = Instant::now();
                    let ct = proof.compress::<$subset_size, Blake2b512>().unwrap();
                    println!("Ciphertext compressed in: {:?}", start.elapsed());
                    println!("Ciphertext size: {:?}", ct.compressed_size());

                    for i in 0..$subset_size {
                        assert_eq!(ct.0[i].batch_size(), num_witnesses);
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

            run_test!(132, 64, 68, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(192, 36, 156, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(512, 23, 489, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(160, 80, 80, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(256, 226, 30, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(704, 684, 20, SimpleBatchElgamalCiphertext<G>, name1);

            run_test!(132, 64, 68, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(192, 36, 156, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(512, 23, 489, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(160, 80, 80, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(256, 226, 30, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(704, 684, 20, BatchedHashedElgamalCiphertext<G>, name2);
        }

        check::<G1Affine>(1);
        check::<G1Affine>(2);
        check::<G1Affine>(3);
        check::<G1Affine>(4);
        check::<G1Affine>(8);
    }
}
