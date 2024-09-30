//! Verifiable Encryption from DKG-in-the-head following Protocol 4 from the paper but adapted for the relation
//! `Y = G_1 * x_1 + G_2 * x_2 + ... G_k * x_k` where `x_i` are encrypted, `Y` and `G_i` are public.
//! The only difference with implementation in the module `dkgith` is that a more efficient variant of Elgamal called batched
//! Elgamal is used where rather than generating a new shared secret for each witness's share, only 1 shared secret is generated
//! per party and then independent OTPs are derived for each witness share by "appending" counters to that shared secret.

// TODO: This contains a lot of duplicate code from module `dkgith`. Abstract the encryption scheme to reduce duplication

use crate::{
    error::VerifiableEncryptionError,
    tz_21::{
        seed_tree::{SeedTree, TreeOpening},
        util::get_indices_to_hide,
    },
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, rand::RngCore, vec, vec::Vec};
use digest::{Digest, DynDigest};
use dock_crypto_utils::{
    aliases::FullDigest, elgamal::BatchedHashedElgamalCiphertext, msm::WindowTable,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DkgithProof<
    const SEED_SIZE: usize,
    const SALT_SIZE: usize,
    const NUM_PARTIES: usize,
    const DEPTH: usize,
    const NUM_TOTAL_NODES: usize,
    const NUM_REPETITIONS: usize,
    G: AffineRepr,
> {
    pub challenge: Vec<u8>,
    /// Ciphertext of the unopened shares of each witness in each iteration
    pub ciphertexts: [BatchedHashedElgamalCiphertext<G>; NUM_REPETITIONS],
    /// Openings required to reconstruct tree in each iteration to reveal the shares except one
    pub tree_openings: [TreeOpening<SEED_SIZE, DEPTH>; NUM_REPETITIONS],
    pub deltas: [Vec<G::ScalarField>; NUM_REPETITIONS],
    /// Delta for each witness in each iteration
    pub salt: [u8; SALT_SIZE],
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedCiphertext<const SUBSET_SIZE: usize, G: AffineRepr>(
    [BatchedHashedElgamalCiphertext<G>; SUBSET_SIZE],
);

impl<
        const SEED_SIZE: usize,
        const SALT_SIZE: usize,
        const NUM_PARTIES: usize,
        const DEPTH: usize,
        const NUM_TOTAL_NODES: usize,
        const NUM_REPETITIONS: usize,
        G: AffineRepr,
    > DkgithProof<SEED_SIZE, SALT_SIZE, NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, NUM_REPETITIONS, G>
{
    const CHECK_SALT_SIZE: () = assert!((2 * SEED_SIZE) == SALT_SIZE);

    pub fn new<R: RngCore, D: FullDigest + Digest>(
        rng: &mut R,
        witnesses: Vec<G::ScalarField>,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
    ) -> Self {
        let _ = Self::CHECK_SALT_SIZE;
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

        let mut salt = [0u8; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        DynDigest::update(&mut hasher, &salt);

        // Populate the trees for each repetition
        let root_seeds =
            [SeedTree::<NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, SEED_SIZE>::random_seed(rng);
                NUM_REPETITIONS];
        let mut seed_trees = [SeedTree::<NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, SEED_SIZE>::default();
            NUM_REPETITIONS];
        cfg_iter_mut!(seed_trees)
            .zip(cfg_into_iter!(root_seeds))
            .enumerate()
            .for_each(|(rep_index, (tree, root_seed))| {
                *tree = SeedTree::<NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, SEED_SIZE>::create_given_root_node(
                    root_seed, &salt, rep_index,
                );
            });

        let zero_ff = G::ScalarField::zero();
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] =
        //     [(); NUM_REPETITIONS].map(|_| [(); NUM_PARTIES].map(|_| BatchedHashedElgamalCiphertext::<G>::default()));
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] =
        //     [(); NUM_REPETITIONS].map(|_| [BatchedHashedElgamalCiphertext::<G>::default(); NUM_PARTIES]);
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = from_fn(|_| from_fn(|_| BatchedHashedElgamalCiphertext::<G>::default()));
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = [(); NUM_REPETITIONS].map(|_| <[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]>::repeat(BatchedHashedElgamalCiphertext::<G>::default()).as_ref_array());
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = [(); NUM_REPETITIONS].map(|_| arr![BatchedHashedElgamalCiphertext::<G>::default(); NUM_PARTIES]);
        // let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = [(); NUM_REPETITIONS].map(|_| array![BatchedHashedElgamalCiphertext::<G>::default(); NUM_PARTIES]);
        let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = (0
            ..NUM_REPETITIONS)
            .map(|_| {
                (0..NUM_PARTIES)
                    .map(|_| BatchedHashedElgamalCiphertext::<G>::default())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut deltas: [Vec<G::ScalarField>; NUM_REPETITIONS] =
            [(); NUM_REPETITIONS].map(|_| vec![zero_ff; witness_count]);
        let mut share_commitments = [[G::zero(); NUM_PARTIES]; NUM_REPETITIONS];

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
                let shares_rep = cfg_into_iter!(0..witness_count).zip(cfg_iter_mut!(d)).map(|(i, d_i)| {
                    // For i'th witness, generate additive shares of the witness by using randomness from the seed tree of this repetition
                    let mut shares_i = [zero_ff; NUM_PARTIES];
                    cfg_iter_mut!(shares_i).enumerate().for_each(|(j, s_j)| {
                        // For j'th party
                        *s_j = seed_trees[rep_index].get_leaf_as_finite_field_element::<G::ScalarField, D>(j as u16, &salt, rep_index, &i.to_le_bytes());
                    });

                    let sum = cfg_iter!(shares_i).sum::<G::ScalarField>();
                    *d_i = witnesses[i] - sum;
                    shares_i[0] += d_i;

                    shares_i
                }).collect::<Vec<_>>();

                // Each party commits to its share of the witnesses
                // Encrypt each party's share and use the tree to get the randomness for the encryption
                let c = cfg_iter_mut!(ct).enumerate().map(|(j, ct_j)|{
                    let shares_j = cfg_into_iter!(0..witness_count).map(|k| shares_rep[k][j]).collect::<Vec<_>>();
                    let r = seed_trees[rep_index].get_leaf_as_finite_field_element::<G::ScalarField, D>(j as u16, &salt, rep_index, &(witness_count + j).to_le_bytes());
                    *ct_j = BatchedHashedElgamalCiphertext::new_given_randomness_and_window_tables::<D>(&shares_j, &r, &enc_key_table, &enc_gen_table);
                    G::Group::msm_unchecked(comm_key, &shares_j)
                }).collect::<Vec<_>>();
                *cm = G::Group::normalize_batch(&c).try_into().unwrap();
            });

        for i in 0..NUM_REPETITIONS {
            for j in 0..NUM_PARTIES {
                hash_elem!(share_commitments[i][j], hasher, to_hash);
                hash_elem!(cts[i][j], hasher, to_hash);
            }
        }

        let challenge = Box::new(hasher).finalize().to_vec();
        // Indices of parties whose share won't be shared with the verifier. Generated by a random oracle.
        let indices_to_hide =
            get_indices_to_hide::<D>(&challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        // Ciphertexts for hidden shares
        let mut ciphertexts: [BatchedHashedElgamalCiphertext<G>; NUM_REPETITIONS] =
            [(); NUM_REPETITIONS].map(|_| BatchedHashedElgamalCiphertext::<G>::default());
        // Openings to let the verifier learn all shares except the one which prover wants to hide.
        let mut tree_openings: [TreeOpening<SEED_SIZE, DEPTH>; NUM_REPETITIONS] =
            [[SeedTree::<NUM_PARTIES, NUM_TOTAL_NODES, DEPTH, SEED_SIZE>::zero_seed(); DEPTH];
                NUM_REPETITIONS];

        for i in 0..NUM_REPETITIONS {
            ciphertexts[i] = cts[i][indices_to_hide[i] as usize].clone();
        }
        cfg_iter_mut!(tree_openings).enumerate().for_each(|(i, t)| {
            *t = seed_trees[i].open_seeds(indices_to_hide[i]);
        });

        Self {
            challenge,
            ciphertexts,
            tree_openings,
            deltas,
            salt,
        }
    }

    fn verify<D: FullDigest + Digest>(
        &self,
        commitment: &G,
        comm_key: &[G],
        enc_key: &G,
        enc_gen: &G,
    ) -> Result<(), VerifiableEncryptionError> {
        let _ = Self::CHECK_SALT_SIZE;
        let witness_count = comm_key.len();
        for i in 0..NUM_REPETITIONS {
            assert_eq!(self.ciphertexts[i].batch_size(), witness_count);
            assert_eq!(self.deltas[i].len(), witness_count);
        }
        let hidden_indices =
            get_indices_to_hide::<D>(&self.challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        let mut hasher = D::default();
        let mut to_hash = Vec::with_capacity(commitment.compressed_size());

        hash_elem!(commitment, hasher, to_hash);
        for c in comm_key {
            hash_elem!(c, hasher, to_hash);
        }
        hash_elem!(enc_key, hasher, to_hash);
        hash_elem!(enc_gen, hasher, to_hash);
        DynDigest::update(&mut hasher, &self.salt);

        let mut cts: [[BatchedHashedElgamalCiphertext<G>; NUM_PARTIES]; NUM_REPETITIONS] = (0
            ..NUM_REPETITIONS)
            .map(|_| {
                (0..NUM_PARTIES)
                    .map(|_| BatchedHashedElgamalCiphertext::<G>::default())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mut comms = [[G::zero(); NUM_PARTIES]; NUM_REPETITIONS];

        let zero_ff = G::ScalarField::zero();

        let enc_key_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_key.into_group(),
        );
        let enc_gen_table = WindowTable::new(
            NUM_REPETITIONS * NUM_PARTIES * witness_count,
            enc_gen.into_group(),
        );

        cfg_iter_mut!(cts)
            .zip(cfg_iter_mut!(comms))
            .enumerate()
            .for_each(|(rep_index, (ct, cm))| {
                // For repetition index `rep_index`

                // Reconstruct revealed shares
                let seed_tree = SeedTree::<NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, SEED_SIZE>::reconstruct_tree(
                    hidden_indices[rep_index],
                    &self.tree_openings[rep_index],
                    &self.salt,
                    rep_index,
                );
                let hidden_party_index = hidden_indices[rep_index] as usize;
                let shares_rep = cfg_into_iter!(0..witness_count).map(|i| {
                    // For i'th witness, create its shares
                    let mut shares_i = [zero_ff; NUM_PARTIES];
                    cfg_iter_mut!(shares_i).enumerate().for_each(|(j, s_j)| {
                        // For j'th party
                        if hidden_party_index != j {
                            *s_j = seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(j as u16, &self.salt, rep_index, &i.to_le_bytes());
                        }
                    });
                    shares_i[0] += self.deltas[rep_index][i];
                    shares_i
                }).collect::<Vec<_>>();

                // Create ciphertexts for revealed share
                // Reconstruct commitments to the shares
                let mut c = vec![G::Group::zero(); NUM_PARTIES];
                cfg_iter_mut!(c).zip(cfg_iter_mut!(ct)).enumerate().for_each(|(j, (c_j, ct_j))| {
                    if hidden_party_index != j {
                        let shares_j = cfg_into_iter!(0..witness_count).map(|k| shares_rep[k][j]).collect::<Vec<_>>();
                        let r = seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(j as u16, &self.salt, rep_index, &(witness_count + j).to_le_bytes());
                        *c_j = G::Group::msm_unchecked(comm_key, &shares_j);
                        *ct_j = BatchedHashedElgamalCiphertext::new_given_randomness_and_window_tables::<D>(&shares_j, &r, &enc_key_table, &enc_gen_table);
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
                hash_elem!(comms[i][j], hasher, to_hash);
                hash_elem!(cts[i][j], hasher, to_hash);
            }
        }
        let challenge = Box::new(hasher).finalize().to_vec();
        if challenge != self.challenge {
            return Err(VerifiableEncryptionError::InvalidProof);
        }
        Ok(())
    }

    pub fn compress<const SUBSET_SIZE: usize, D: Digest + FullDigest>(
        &self,
    ) -> CompressedCiphertext<SUBSET_SIZE, G> {
        let _ = Self::CHECK_SALT_SIZE;
        const { assert!(SUBSET_SIZE <= NUM_REPETITIONS) };
        let hidden_indices =
            get_indices_to_hide::<D>(&self.challenge, NUM_REPETITIONS as u16, NUM_PARTIES as u16);
        // Choose a random subset of size `SUBSET_SIZE` from the indices of `hidden_indices`
        // TODO: Check if this is secure. The objective is to avoid the use of random number generation on the verifier side
        let subset = get_indices_to_hide::<D>(
            &D::digest(&self.challenge),
            SUBSET_SIZE as u16,
            NUM_REPETITIONS as u16,
        );
        let witness_count = self.deltas[0].len();
        let mut compressed_cts: [BatchedHashedElgamalCiphertext<G>; SUBSET_SIZE] =
            [(); SUBSET_SIZE].map(|_| BatchedHashedElgamalCiphertext::<G>::default());

        cfg_iter_mut!(compressed_cts)
            .enumerate()
            .for_each(|(i, ct)| {
                let rep_index = subset[i] as usize;

                // Get the revealed shares
                let seed_tree =
                    SeedTree::<NUM_PARTIES, DEPTH, NUM_TOTAL_NODES, SEED_SIZE>::reconstruct_tree(
                        hidden_indices[rep_index],
                        &self.tree_openings[rep_index],
                        &self.salt,
                        rep_index,
                    );
                let shares_sum = cfg_into_iter!(0..witness_count).map(|j| {
                    // Get sum of shares of the j'th witness
                    let sum = cfg_into_iter!(0..NUM_PARTIES)
                        .map(|k| {
                            if hidden_indices[rep_index] != k as u16 {
                                seed_tree.get_leaf_as_finite_field_element::<G::ScalarField, D>(
                                    k as u16,
                                    &self.salt,
                                    rep_index,
                                    &j.to_le_bytes(),
                                )
                            } else {
                                G::ScalarField::zero()
                            }
                        })
                        .sum::<G::ScalarField>();
                    // 0th share contains delta already
                    if hidden_indices[rep_index] != 0 {
                        sum + self.deltas[rep_index][j]
                    } else {
                        sum
                    }
                });
                *ct = self.ciphertexts[rep_index].clone();
                // Add the revealed shares to the ciphertext of the unrevealed share to get a ciphertext of the witness.
                cfg_iter_mut!(ct.encrypted)
                    .zip(cfg_into_iter!(shares_sum))
                    .for_each(|(e_j, s_j)| {
                        *e_j += s_j;
                    })
            });

        CompressedCiphertext(compressed_cts)
    }

    // NOTE: Ideally the verifier will compress the ciphertext and since functions `verify` and `compress` share some code, it will be more efficient to
    // have a function called `verify_and_compress` than calling `verify` and then `compress`
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
            let ct_i = &self.0[i];
            assert_eq!(ct_i.batch_size(), witness_count);
            let witnesses = ct_i.decrypt::<D>(dec_key);
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

            const SEED_SIZE: usize = 16;
            const SALT_SIZE: usize = 32;

            macro_rules! run_test {
                ($parties: expr, $reps: expr, $depth: expr, $nodes: expr, $subset_size: expr) => {{
                    println!(
                        "\n# witnesses = {}, # parties = {}, # repetitions = {}, subset size = {}",
                        count, $parties, $reps, $subset_size
                    );
                    let start = Instant::now();
                    let proof = DkgithProof::<
                        SEED_SIZE,
                        SALT_SIZE,
                        $parties,
                        $depth,
                        $nodes,
                        $reps,
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

            run_test!(64, 48, 6, 127, 15);
            run_test!(16, 32, 4, 31, 30);
            run_test!(4, 64, 2, 7, 48);
        }

        check::<G1Affine>(1);
        check::<G1Affine>(2);
        check::<G1Affine>(3);
        check::<G1Affine>(4);
        check::<G1Affine>(8);
    }
}
