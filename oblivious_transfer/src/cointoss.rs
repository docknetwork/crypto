//! Generate 1 or more random numbers using commit-and-release coin tossing.
//! Called F_com in the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, collections::BTreeMap, rand::RngCore, vec, vec::Vec};
use digest::Digest;
use sha3::Sha3_256;

use super::ParticipantId;

use crate::error::OTError;

use dock_crypto_utils::expect_equality;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitments(pub Vec<Vec<u8>>);

// Note: The correct thing would be to use security parameter as const generic and the salt size
// should be double of that but that doesn't compile with stable Rust
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party<F: PrimeField, const SALT_SIZE: usize> {
    pub id: ParticipantId,
    pub protocol_id: Vec<u8>,
    pub own_shares_and_salts: Vec<(F, [u8; SALT_SIZE])>,
    // Following isn't allowed in stable Rust
    // pub own_shares_and_salts: Vec<(F, [u8; 2*SECURITY_PARAM])>,
    /// Stores commitments to shares received from other parties and used to verify against the
    /// shares received from them in a future round
    pub other_commitments: BTreeMap<ParticipantId, Commitments>,
    /// Stores shares received from other parties and used to compute the joint randomness
    pub other_shares: BTreeMap<ParticipantId, Vec<F>>,
}

impl<F: PrimeField, const SALT_SIZE: usize> Party<F, SALT_SIZE> {
    /// Creates randomness, commits to it and returns the commitments to be sent to the other parties.
    /// The randomness will serve as a share to the joint randomness. `batch_size` is the number of
    /// random values generated.
    pub fn commit<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        batch_size: u32,
        protocol_id: Vec<u8>,
    ) -> (Self, Commitments) {
        let shares_and_salts = (0..batch_size)
            .map(|_| {
                let mut salt = [0; SALT_SIZE];
                rng.fill_bytes(&mut salt);
                (F::rand(rng), salt)
            })
            .collect::<Vec<_>>();
        let commitments = Self::compute_commitments(&shares_and_salts, &protocol_id);
        (
            Self {
                id,
                protocol_id,
                own_shares_and_salts: shares_and_salts,
                other_commitments: Default::default(),
                other_shares: Default::default(),
            },
            Commitments(commitments),
        )
    }

    /// Process received commitments to the shares from another party and store it
    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        commitments: Commitments,
    ) -> Result<(), OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.other_commitments.contains_key(&sender_id) {
            return Err(OTError::AlreadyHaveCommitmentFromParticipant(sender_id));
        }
        expect_equality!(
            self.own_shares_and_salts.len(),
            commitments.0.len(),
            OTError::IncorrectNoOfCommitments
        );
        self.other_commitments.insert(sender_id, commitments);
        Ok(())
    }

    /// Process a received share from another party, verify it against the commitment receiver earlier
    /// and store the shares
    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares_and_salts: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), OTError> {
        if self.id == sender_id {
            return Err(OTError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if !self.other_commitments.contains_key(&sender_id) {
            return Err(OTError::MissingCommitmentFromParticipant(sender_id));
        }
        if self.other_shares.contains_key(&sender_id) {
            return Err(OTError::AlreadyHaveSharesFromParticipant(sender_id));
        }
        expect_equality!(
            self.own_shares_and_salts.len(),
            shares_and_salts.len(),
            OTError::IncorrectNoOfShares
        );
        let expected_commitments = Self::compute_commitments(&shares_and_salts, &self.protocol_id);
        if expected_commitments != self.other_commitments.get(&sender_id).unwrap().0 {
            return Err(OTError::IncorrectCommitment);
        }
        self.other_shares.insert(
            sender_id,
            shares_and_salts.into_iter().map(|(s, _)| s).collect(),
        );
        Ok(())
    }

    /// Use the shares received from all parties to compute the joint randomness
    pub fn compute_joint_randomness(self) -> Vec<F> {
        cfg_into_iter!(0..self.own_shares_and_salts.len())
            .map(|i| {
                let mut sum = self.own_shares_and_salts[i].0;
                for v in self.other_shares.values() {
                    sum += v[i];
                }
                sum
            })
            .collect()
    }

    pub fn has_commitment_from(&self, id: &ParticipantId) -> bool {
        self.other_commitments.contains_key(id)
    }

    pub fn has_shares_from(&self, id: &ParticipantId) -> bool {
        self.other_shares.contains_key(id)
    }

    /// Returns true if it has got shares from all other participants that sent commitments.
    pub fn has_shares_from_all_who_committed(&self) -> bool {
        self.other_shares.len() == self.other_commitments.len()
    }

    // pub const fn salt_size() -> usize {
    //     2 * SECURITY_PARAM
    // }

    fn compute_commitments(
        shares_and_salts: &[(F, [u8; SALT_SIZE])],
        label: &[u8],
    ) -> Vec<Vec<u8>> {
        cfg_into_iter!(0..shares_and_salts.len())
            .map(|i| hash(label, &shares_and_salts[i].0, &shares_and_salts[i].1))
            .collect()
    }
}

fn hash<F: PrimeField>(label: &[u8], share: &F, salt: &[u8]) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.extend_from_slice(label);
    share.serialize_compressed(&mut bytes).unwrap();
    bytes.extend_from_slice(salt);

    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use std::time::Instant;

    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn cointoss() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<const SALT_SIZE: usize>(rng: &mut StdRng, batch_size: u32, num_parties: u16) {
            let label = b"test".to_vec();
            let mut parties = vec![];
            let mut commitments = vec![];

            // All parties generate and commit to their share of the joint randomness
            let start = Instant::now();
            for i in 1..=num_parties {
                let (party, comm) =
                    Party::<Fr, SALT_SIZE>::commit(rng, i, batch_size, label.clone());
                parties.push(party);
                commitments.push(comm);
            }
            let commit_time = start.elapsed();

            // All parties send commitment to their shares to others
            let start = Instant::now();
            for i in 1..=num_parties {
                for j in 1..=num_parties {
                    if i != j {
                        parties[i as usize - 1]
                            .receive_commitment(j, commitments[j as usize - 1].clone())
                            .unwrap();
                    }
                }
            }
            let process_commit_time = start.elapsed();

            // All parties send their shares to others
            let start = Instant::now();
            for receiver_id in 1..=num_parties {
                for sender_id in 1..=num_parties {
                    if receiver_id != sender_id {
                        assert!(
                            !parties[receiver_id as usize - 1].has_shares_from_all_who_committed()
                        );
                        let share = parties[sender_id as usize - 1].own_shares_and_salts.clone();
                        parties[receiver_id as usize - 1]
                            .receive_shares(sender_id, share)
                            .unwrap();
                    }
                }
                assert!(parties[receiver_id as usize - 1].has_shares_from_all_who_committed());
            }
            let process_shares_time = start.elapsed();

            // Shares are received correctly
            for i in 1..=num_parties {
                for j in 1..=num_parties {
                    if i != j {
                        assert_eq!(
                            parties[j as usize - 1].other_shares.get(&i).unwrap(),
                            &parties[i as usize - 1]
                                .own_shares_and_salts
                                .clone()
                                .into_iter()
                                .map(|s| s.0)
                                .collect::<Vec<_>>()
                        )
                    }
                }
            }

            for i in 0..num_parties as usize {
                assert!(parties[i].has_shares_from_all_who_committed());
            }

            // All parties compute the joint randomness
            let start = Instant::now();
            let mut joint_randomness = vec![];
            for party in parties {
                joint_randomness.push(party.compute_joint_randomness());
            }
            let compute_randomness_time = start.elapsed();

            // All parties have the same joint randomness
            for i in 1..num_parties as usize {
                assert_eq!(joint_randomness[0], joint_randomness[i]);
            }

            println!("For a batch size of {} and {} parties, below is the total time taken by all parties", batch_size, num_parties);
            println!("Commitment time {:?}", commit_time);
            println!("Processing commitment time {:?}", process_commit_time);
            println!("Processing shares time {:?}", process_shares_time);
            println!(
                "Computing joint randomness time {:?}",
                compute_randomness_time
            );
        }

        check::<256>(&mut rng, 10, 5);
        check::<256>(&mut rng, 20, 5);
        check::<256>(&mut rng, 30, 5);
        check::<256>(&mut rng, 10, 10);
        check::<256>(&mut rng, 10, 20);
    }
}
