//! Verifiable Encryption from DKG-in-the-head following Protocol 4 from the paper but adapted for the relation
//! `Y = G_1 * x_1 + G_2 * x_2 + ... G_k * x_k` where `x_i` are encrypted, `Y` and `G_i` are public.
//!
//! Overview of the construction:
//! 1. For each repetition, the prover secret shares each witness (`x_i`) using additive secret sharing of the form: for a witness `w`,
//! create `N` shares by selecting `N` random values `s_1`, `s_2`, ... `s_n` and setting `delta = w - \sum_{i=1 to N}{s_i}`, `s_1 = s1 + delta`. Note that now
//! the sum of shares is the witness as `\sum_{i=1 to N}{s_i} = w`. Its important to select a random for `s_1` first otherwise the construction won't be
//! secure when any index expect for party 1 is revealed (because of delta).
//! 2. Each party's share is encrypted and committed to: party `j` commits to its shares of the witnesses `x_i` as `C_i = G_1 * s_{1,j} + G_2 * s_{1,j} + ... G_k * s_{k,j}`
//! where `s_{i,j}` is the j'th party's share of witness `x_i`. Each share's ciphertext is of the form `(shared_secret, OTP_{i,j} + s_{i,j})` where `OTP_{i,j}` is
//! the one time pad derived from the shared secret for the j-th share of witness `i`, i.e. `s_{i,j}`.
//! 3. Prover commits to all ciphertexts and commitments and for each repetition, picks (using random oracle) a random party index whose shares are not to be
//! revealed but reveals shares of all other parties to the verifier and shares the ciphertext of shares of the hidden party.
//! 4. Using the revealed shares and ciphertexts, verifier reconstructs all the ciphertexts and commitments and checks the prover's integrity.
//! 5. To compress the ciphertexts, verifier chooses a small number of repetitions from all the repetitions and for each repetition, adds the revealed shares
//! and the unrevealed share's ciphertext. Because of the homomorphic property of ciphertexts, the additions gives the ciphertext of the witness
//! as `OTP_{i,j} + s_{i,j} + \sum{k!=j}{s_{i,k}} = OTP_i + x_i` (`delta` also needs to added to this sum depending on which index is being revealed).
//! 6. Decryptor generates the OTP using shared secret and decrypts to get the witnesses.
//!
//! The encryption scheme used in generic and either the hashed Elgamal shown in the paper can be used or a more
//! efficient version of hashed Elgamal can be used where rather than generating a new shared secret for each witness's share,
//! only 1 shared secret is generated per party and then independent OTPs are derived for each witness share by "appending" counters
//! to that shared secret.

use crate::{
    error::VerifiableEncryptionError,
    tz_21::{
        encryption::BatchCiphertext,
        seed_tree::{SeedTree, TreeOpening, DEFAULT_SALT_SIZE, DEFAULT_SEED_SIZE},
        util::get_indices_to_hide,
    },
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, rand::RngCore, vec, vec::Vec};
use core::marker::PhantomData;
use digest::{Digest, ExtendableOutput, Update};
use dock_crypto_utils::{aliases::FullDigest, msm::WindowTable, transcript::Transcript};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

const SALT_LABEL: &[u8; 4] = b"salt";
const SHARE_COMMITMENT_LABEL: &'static [u8; 17] = b"share_commitments";
const CIPHERTEXTS_LABEL: &'static [u8; 11] = b"ciphertexts";
const CHALLENGE_LABEL: &'static [u8; 9] = b"challenge";

/// Ciphertext and the proof of encryption. `CT` is the variant of Elgamal encryption used. See test for usage
/// Some of the struct fields like, `ciphertexts`, `tree_openings` etc. could be created as arrays rather than vectors
/// as their length depends on the generic constants but as the constants are large, it causes stack-overflow.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DkgithProof<
    G: AffineRepr,
    CT: BatchCiphertext<G>,
    const NUM_PARTIES: usize,
    const NUM_REPETITIONS: usize,
    const SEED_SIZE: usize = DEFAULT_SEED_SIZE,
    const SALT_SIZE: usize = DEFAULT_SALT_SIZE,
> {
    pub challenge: Vec<u8>,
    /// Ciphertext of the unopened shares of each witness in each repetition
    pub ciphertexts: Vec<CT>,
    /// Openings required to reconstruct tree in each iteration to reveal the shares except one
    pub tree_openings: Vec<TreeOpening<SEED_SIZE>>,
    /// Delta for each witness in each repetition
    pub deltas: Vec<Vec<G::ScalarField>>,
    pub salt: [u8; SALT_SIZE],
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedCiphertext<G: AffineRepr, CT: BatchCiphertext<G>, const SUBSET_SIZE: usize>(
    Vec<CT>,
    PhantomData<G>,
);

impl<
        G: AffineRepr,
        CT: BatchCiphertext<G>,
        const NUM_PARTIES: usize,
        const NUM_REPETITIONS: usize,
        const SEED_SIZE: usize,
        const SALT_SIZE: usize,
    > DkgithProof<G, CT, NUM_PARTIES, NUM_REPETITIONS, SEED_SIZE, SALT_SIZE>
{
    const CHECK_NUM_PARTIES: () = assert!(NUM_PARTIES.is_power_of_two());
    const CHECK_SALT_SIZE: () = assert!((2 * SEED_SIZE) == SALT_SIZE);

    /// Create verifiable encryption of vector `witnesses` that are also committed in a Pedersen commitment
    /// created with the commitment key `comm_key`. The encryption key is `enc_key` and group generator
    /// used in that key is `gen`. Its assumed that the public values like commitment key, commitment, encryption key,
    /// encryption key generator are all included in the transcript.
    pub fn new<R: RngCore, D: FullDigest + Digest, X: Default + Update + ExtendableOutput>(
        rng: &mut R,
        witnesses: Vec<G::ScalarField>,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
        transcript: &mut impl Transcript,
    ) -> Result<Self, VerifiableEncryptionError> {
        let _ = Self::CHECK_NUM_PARTIES;
        let _ = Self::CHECK_SALT_SIZE;
        let witness_count = witnesses.len();
        if comm_key.len() != witness_count {
            return Err(VerifiableEncryptionError::UnexpectedCommitmentKeySize(
                comm_key.len(),
                witness_count,
            ));
        }

        let mut salt = [0u8; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        transcript.append_message(SALT_LABEL, &salt);

        // Populate the trees for each repetition
        let root_seeds =
            vec![SeedTree::<NUM_PARTIES, SEED_SIZE>::random_seed(rng); NUM_REPETITIONS];
        let mut seed_trees = vec![SeedTree::<NUM_PARTIES, SEED_SIZE>::default(); NUM_REPETITIONS];
        cfg_iter_mut!(seed_trees)
            .zip(cfg_into_iter!(root_seeds))
            .enumerate()
            .for_each(|(rep_index, (tree, root_seed))| {
                *tree = SeedTree::<NUM_PARTIES, SEED_SIZE>::create_given_root_node::<X>(
                    root_seed, &salt, rep_index,
                );
            });

        let zero_ff = G::ScalarField::zero();
        let mut cts: Vec<Vec<CT>> = (0..NUM_REPETITIONS)
            .map(|_| (0..NUM_PARTIES).map(|_| CT::default()).collect::<Vec<_>>())
            .collect();
        let mut deltas: Vec<Vec<G::ScalarField>> = (0..NUM_REPETITIONS)
            .map(|_| vec![zero_ff; witness_count])
            .collect();
        let mut share_commitments = vec![vec![G::zero(); NUM_PARTIES]; NUM_REPETITIONS];

        let enc_key_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_key.into_group(),
        );
        let enc_gen_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_gen.into_group(),
        );

        cfg_iter_mut!(cts)
            .zip(cfg_iter_mut!(share_commitments))
            .zip(cfg_iter_mut!(deltas))
            .enumerate()
            .for_each(|(rep_index, ((ct, cm), d))| {
                // For repetition index `rep_index`
                let shares_rep = cfg_into_iter!(0..witness_count)
                    .zip(cfg_iter_mut!(d))
                    .map(|(i, d_i)| {
                        // For i'th witness, generate additive shares of the witness by using randomness from the seed tree of this repetition
                        let mut shares_i = [zero_ff; NUM_PARTIES];
                        cfg_iter_mut!(shares_i).enumerate().for_each(|(j, s_j)| {
                            // Get the share for j'th party
                            *s_j = seed_trees[rep_index]
                                .get_leaf_as_finite_field_element::<G::ScalarField, D>(
                                    j as u16,
                                    &i.to_le_bytes(),
                                );
                        });

                        let sum = cfg_iter!(shares_i).sum::<G::ScalarField>();
                        *d_i = witnesses[i] - sum;
                        shares_i[0] += d_i;

                        shares_i
                    })
                    .collect::<Vec<_>>();

                let c = cfg_iter_mut!(ct)
                    .enumerate()
                    .map(|(j, ct_j)| {
                        // Encrypt each party's share and use the tree to get the randomness for the encryption
                        let shares_j = cfg_into_iter!(0..witness_count)
                            .map(|k| shares_rep[k][j])
                            .collect::<Vec<_>>();
                        let enc_rands =
                            CT::get_randomness_from_seed_tree::<NUM_PARTIES, SEED_SIZE, D>(
                                &seed_trees[rep_index],
                                j as u16,
                                witness_count,
                            );
                        *ct_j = CT::new::<D>(&shares_j, &enc_rands, &enc_key_table, &enc_gen_table);
                        // Each party commits to its share of the witnesses
                        G::Group::msm_unchecked(comm_key, &shares_j)
                    })
                    .collect::<Vec<_>>();
                *cm = G::Group::normalize_batch(&c).try_into().unwrap();
            });

        for i in 0..NUM_REPETITIONS {
            for j in 0..NUM_PARTIES {
                transcript.append(SHARE_COMMITMENT_LABEL, &share_commitments[i][j]);
                transcript.append(CIPHERTEXTS_LABEL, &cts[i][j]);
            }
        }

        // Challenge can also be an array since the digest function is a parameter which makes the output size also known at compile time
        let mut challenge = vec![0; NUM_REPETITIONS * 2];
        transcript.challenge_bytes(CHALLENGE_LABEL, &mut challenge);
        // Indices of parties whose share won't be shared with the verifier. Generated by a random oracle.
        let indices_to_hide =
            get_indices_to_hide::<D>(&challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        // Ciphertexts for hidden shares
        let mut ciphertexts: Vec<CT> = (0..NUM_REPETITIONS).map(|_| CT::default()).collect();
        // Openings to let the verifier learn all shares except the one which prover wants to hide.
        let mut tree_openings: Vec<TreeOpening<SEED_SIZE>> =
            vec![
                vec![
                    SeedTree::<NUM_PARTIES, SEED_SIZE>::zero_seed();
                    SeedTree::<NUM_PARTIES, SEED_SIZE>::depth() as usize
                ];
                NUM_REPETITIONS
            ];

        for i in 0..NUM_REPETITIONS {
            core::mem::swap(
                &mut ciphertexts[i],
                &mut cts[i][indices_to_hide[i] as usize],
            );
        }
        cfg_iter_mut!(tree_openings).enumerate().for_each(|(i, t)| {
            *t = seed_trees[i].open_seeds(indices_to_hide[i]);
        });

        Ok(Self {
            challenge,
            ciphertexts,
            tree_openings,
            deltas,
            salt,
        })
    }

    /// Verify the proof of verifiable encryption of values that are also committed in a Pedersen commitment
    /// `commitment` created with the commitment key `comm_key`. The encryption key is `enc_key` and group
    /// generator used in that key is `gen`. Its assumed that the public values like commitment key, commitment,
    /// encryption key, encryption key generator are all included in the transcript.
    pub fn verify<D: FullDigest + Digest, X: Default + Update + ExtendableOutput>(
        &self,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
        transcript: &mut impl Transcript,
    ) -> Result<(), VerifiableEncryptionError> {
        let _ = Self::CHECK_NUM_PARTIES;
        let _ = Self::CHECK_SALT_SIZE;
        let witness_count = comm_key.len();
        if self.ciphertexts.len() != NUM_REPETITIONS {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfCiphertexts(
                self.ciphertexts.len(),
                NUM_REPETITIONS,
            ));
        }
        if self.tree_openings.len() != NUM_REPETITIONS {
            return Err(VerifiableEncryptionError::UnexpectedNumberOfTreeOpenings(
                self.tree_openings.len(),
                NUM_REPETITIONS,
            ));
        }
        if self.deltas.len() != NUM_REPETITIONS {
            return Err(VerifiableEncryptionError::InequalNumberOfDeltas(
                self.deltas.len(),
                NUM_REPETITIONS,
            ));
        }
        for i in 0..NUM_REPETITIONS {
            if self.ciphertexts[i].batch_size() != witness_count {
                return Err(
                    VerifiableEncryptionError::InequalNumberOfCiphertextsAndWitnesses(
                        self.ciphertexts[i].batch_size(),
                        witness_count,
                    ),
                );
            }
            if self.deltas[i].len() != witness_count {
                return Err(VerifiableEncryptionError::InequalNumberOfDeltaForWitnesses(
                    self.deltas[i].len(),
                    witness_count,
                ));
            }
        }
        let hidden_indices =
            get_indices_to_hide::<D>(&self.challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        transcript.append_message(SALT_LABEL, &self.salt);

        let mut cts: Vec<Vec<CT>> = (0..NUM_REPETITIONS)
            .map(|_| (0..NUM_PARTIES).map(|_| CT::default()).collect())
            .collect();
        let mut comms = vec![vec![G::zero(); NUM_PARTIES]; NUM_REPETITIONS];

        let zero_ff = G::ScalarField::zero();

        let enc_key_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_key.into_group(),
        );
        let enc_gen_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_gen.into_group(),
        );

        // Reconstruct revealed shares
        let seed_trees_ = (0..NUM_REPETITIONS).map(|rep_index| {
            SeedTree::<NUM_PARTIES, SEED_SIZE>::reconstruct_tree::<X>(
                hidden_indices[rep_index],
                &self.tree_openings[rep_index],
                &self.salt,
                rep_index,
            )
        });
        let mut seed_trees = Vec::with_capacity(NUM_REPETITIONS);
        for st in seed_trees_ {
            seed_trees.push(st?);
        }

        cfg_iter_mut!(cts)
            .zip(cfg_iter_mut!(comms))
            .zip(cfg_into_iter!(seed_trees))
            .enumerate()
            .for_each(|(rep_index, ((ct, cm), seed_tree))| {
                // For repetition index `rep_index`

                let hidden_party_index = hidden_indices[rep_index] as usize;
                let shares_rep = cfg_into_iter!(0..witness_count)
                    .map(|i| {
                        // For i'th witness, create its shares
                        let mut shares_i = [zero_ff; NUM_PARTIES];
                        cfg_iter_mut!(shares_i).enumerate().for_each(|(j, s_j)| {
                            // For j'th party
                            if hidden_party_index != j {
                                *s_j = seed_tree
                                    .get_leaf_as_finite_field_element::<G::ScalarField, D>(
                                        j as u16,
                                        &i.to_le_bytes(),
                                    );
                            }
                        });
                        shares_i[0] += self.deltas[rep_index][i];
                        shares_i
                    })
                    .collect::<Vec<_>>();

                // Reconstruct commitments to the shares
                // Create ciphertexts for revealed share
                let mut c = vec![G::Group::zero(); NUM_PARTIES];
                cfg_iter_mut!(c)
                    .zip(cfg_iter_mut!(ct))
                    .enumerate()
                    .for_each(|(j, (c_j, ct_j))| {
                        if hidden_party_index != j {
                            let shares_j = cfg_into_iter!(0..witness_count)
                                .map(|k| shares_rep[k][j])
                                .collect::<Vec<_>>();
                            let enc_rands =
                                CT::get_randomness_from_seed_tree::<NUM_PARTIES, SEED_SIZE, D>(
                                    &seed_tree,
                                    j as u16,
                                    witness_count,
                                );
                            *ct_j =
                                CT::new::<D>(&shares_j, &enc_rands, &enc_key_table, &enc_gen_table);
                            *c_j = G::Group::msm_unchecked(comm_key, &shares_j);
                        } else {
                            *ct_j = self.ciphertexts[rep_index].clone();
                        }
                    });
                // Since the sum of all shares is the witness, sum of all commitments to the shares will be the final commitment and
                // thus the commitment to the unrevealed share is the difference of final commitment and sum of revealed shares' commitments
                c[hidden_party_index] = commitment.into_group() - cfg_iter!(c).sum::<G::Group>();
                *cm = G::Group::normalize_batch(&c).try_into().unwrap();
            });

        for i in 0..NUM_REPETITIONS {
            for j in 0..NUM_PARTIES {
                transcript.append(SHARE_COMMITMENT_LABEL, &comms[i][j]);
                transcript.append(CIPHERTEXTS_LABEL, &cts[i][j]);
            }
        }
        let mut challenge = vec![0; NUM_REPETITIONS * 2];
        transcript.challenge_bytes(CHALLENGE_LABEL, &mut challenge);
        if challenge != self.challenge {
            return Err(VerifiableEncryptionError::InvalidProof);
        }
        Ok(())
    }

    /// Described in Appendix D.1 in the paper
    pub fn compress<
        const SUBSET_SIZE: usize,
        D: Digest + FullDigest,
        X: Default + Update + ExtendableOutput,
    >(
        &self,
    ) -> Result<CompressedCiphertext<G, CT, SUBSET_SIZE>, VerifiableEncryptionError> {
        let _ = Self::CHECK_NUM_PARTIES;
        let _ = Self::CHECK_SALT_SIZE;
        const { assert!(SUBSET_SIZE <= NUM_REPETITIONS) };

        let hidden_indices =
            get_indices_to_hide::<D>(&self.challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        // Choose a random subset of size `SUBSET_SIZE` from the indices of `hidden_indices`
        let mut challenge_for_subset_gen = self.challenge.clone();
        for o in &self.tree_openings {
            for n in o {
                challenge_for_subset_gen.extend_from_slice(n);
            }
        }
        let subset = get_indices_to_hide::<D>(
            &D::digest(&challenge_for_subset_gen),
            SUBSET_SIZE as u16,
            NUM_REPETITIONS as u16,
        );

        let witness_count = self.ciphertexts[0].batch_size();
        let mut compressed_cts: Vec<CT> = (0..SUBSET_SIZE).map(|_| CT::default()).collect();

        // Get the revealed shares
        let seed_trees_ = (0..SUBSET_SIZE).map(|i| {
            let rep_index = subset[i] as usize;
            SeedTree::<NUM_PARTIES, SEED_SIZE>::reconstruct_tree::<X>(
                hidden_indices[rep_index],
                &self.tree_openings[rep_index],
                &self.salt,
                rep_index,
            )
        });
        let mut seed_trees = Vec::with_capacity(SUBSET_SIZE);
        for st in seed_trees_ {
            seed_trees.push(st?);
        }

        cfg_iter_mut!(compressed_cts)
            .enumerate()
            .for_each(|(i, ct)| {
                let rep_index = subset[i] as usize;
                let seed_tree = &seed_trees[i];
                // Add the revealed shares to the ciphertext of the unrevealed share to get a ciphertext of the witness.
                let share_sum = cfg_into_iter!(0..witness_count)
                    .map(|j| {
                        // Get sum of shares of the j'th witness
                        let mut share_sum = cfg_into_iter!(0..NUM_PARTIES)
                            .map(|k| {
                                if hidden_indices[rep_index] != k as u16 {
                                    seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(
                                        k as u16,
                                        &j.to_le_bytes(),
                                    )
                                } else {
                                    G::ScalarField::zero()
                                }
                            })
                            .sum::<G::ScalarField>();
                        // 0th share contains delta already
                        if hidden_indices[rep_index] != 0 {
                            share_sum += self.deltas[rep_index][j];
                        }
                        share_sum
                    })
                    .collect::<Vec<_>>();
                *ct = self.ciphertexts[rep_index].clone();
                ct.add_to_ciphertexts(&share_sum);
            });
        Ok(CompressedCiphertext(compressed_cts, PhantomData))
    }

    pub fn witness_count(&self) -> usize {
        self.ciphertexts[0].batch_size()
    }

    // NOTE: Ideally the verifier will compress the ciphertext and since functions `verify` and `compress` share some code, it will be more efficient to
    // have a function called `verify_and_compress` than calling `verify` and then `compress`
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
        for i in 0..SUBSET_SIZE {
            let ct_i = &self.0[i];
            if ct_i.batch_size() != witness_count {
                return Err(
                    VerifiableEncryptionError::InequalNumberOfCiphertextsAndWitnesses(
                        ct_i.batch_size(),
                        witness_count,
                    ),
                );
            }
            let witnesses = ct_i.decrypt::<D>(dec_key);
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
    use sha3::Shake256;
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

            const SEED_SIZE: usize = 16;
            const SALT_SIZE: usize = 32;

            // const TEST_VECTOR: [(u16, u16, u16); 4] =
            //     [(64, 48, 15), (85, 20, 20), (16, 32, 30), (4, 64, 48)];

            // for (N, tau, n) in TEST_VECTOR.iter() {
            //     let proof = DkgithProof::<SEED_SIZE, SALT_SIZE, N, tau, _>::new(&mut rng, witnesses.clone(), &commitment, &comm_key);
            // }

            macro_rules! run_test {
                ($parties: expr, $reps: expr, $subset_size: expr, $ct_type: ty, $ct_type_name: expr) => {{
                    println!(
                        "\nFor {} hashed Elgamal encryption, # witnesses = {}, # parties = {}, # repetitions = {}, subset size = {}",
                        $ct_type_name, num_witnesses, $parties, $reps, $subset_size
                    );
                    let depth = SeedTree::<$parties, SEED_SIZE>::depth() as usize;
                    let start = Instant::now();
                    let mut prover_transcript = new_merlin_transcript(b"test");
                    prover_transcript.append(b"comm_key", &comm_key);
                    prover_transcript.append(b"enc_key", &pk);
                    prover_transcript.append(b"enc_gen", &gen);
                    prover_transcript.append(b"commitment", &commitment);
                    let proof = DkgithProof::<
                        _,
                        $ct_type,
                        $parties,
                        $reps,
                        SEED_SIZE,
                        SALT_SIZE,
                    >::new::<_, Blake2b512, Shake256>(
                        &mut rng,
                        witnesses.clone(),
                        &comm_key,
                        &pk.0,
                        &gen,
                        &mut prover_transcript
                    ).unwrap();
                    println!("Proof generated in: {:?}", start.elapsed());

                    for i in 0..$reps {
                        assert_eq!(proof.deltas[i].len(), num_witnesses);
                        assert_eq!(proof.ciphertexts[i].batch_size(), num_witnesses);
                        assert_eq!(proof.tree_openings[i].len(), depth);
                    }

                    let start = Instant::now();
                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key", &comm_key);
                    verifier_transcript.append(b"enc_key", &pk);
                    verifier_transcript.append(b"enc_gen", &gen);
                    verifier_transcript.append(b"commitment", &commitment);
                    proof
                        .verify::<Blake2b512, Shake256>(&commitment, &comm_key, &pk.0, &gen, &mut verifier_transcript)
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
                        .verify::<Blake2b512, Shake256>(&invalid_comm, &comm_key, &pk.0, &gen, &mut verifier_transcript).is_err());

                    let invalid_pk = G::rand(&mut rng);
                    let mut verifier_transcript = new_merlin_transcript(b"test");
                    verifier_transcript.append(b"comm_key", &comm_key);
                    verifier_transcript.append(b"enc_key", &invalid_pk);
                    verifier_transcript.append(b"enc_gen", &gen);
                    verifier_transcript.append(b"commitment", &commitment);
                    assert!(proof
                        .verify::<Blake2b512, Shake256>(&commitment, &comm_key, &invalid_pk, &gen, &mut verifier_transcript).is_err());

                    let start = Instant::now();
                    let ct = proof.compress::<$subset_size, Blake2b512, Shake256>().unwrap();
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

            run_test!(64, 48, 15, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(16, 32, 30, SimpleBatchElgamalCiphertext<G>, name1);
            run_test!(4, 64, 48, SimpleBatchElgamalCiphertext<G>, name1);

            run_test!(64, 48, 15, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(16, 32, 30, BatchedHashedElgamalCiphertext<G>, name2);
            run_test!(4, 64, 48, BatchedHashedElgamalCiphertext<G>, name2);
        }

        check::<G1Affine>(1);
        check::<G1Affine>(2);
        check::<G1Affine>(3);
        check::<G1Affine>(4);
        check::<G1Affine>(8);
    }
}
