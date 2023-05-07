//! Generate 1 or more random numbers using commit-and-release coin tossing
//! Called F_com in the paper

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, collections::BTreeMap, rand::RngCore, vec, vec::Vec};
use digest::Digest;
use sha3::Sha3_256;

use oblivious_transfer::ParticipantId;

use crate::error::BBSPlusError;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub const SALT_SIZE: usize = 32;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitments(pub Vec<Vec<u8>>);

// TODO: Use security parameter as const generic and the salt size should be double of that
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party<F: PrimeField> {
    pub id: ParticipantId,
    pub protocol_id: Vec<u8>,
    pub own_shares_and_salts: Vec<(F, [u8; SALT_SIZE])>,
    pub commitments: BTreeMap<ParticipantId, Commitments>,
    pub other_shares: BTreeMap<ParticipantId, Vec<F>>,
}

impl<F: PrimeField> Party<F> {
    pub fn commit<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        batch_size: usize,
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
                commitments: Default::default(),
                other_shares: Default::default(),
            },
            Commitments(commitments),
        )
    }

    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        commitments: Commitments,
    ) -> Result<(), BBSPlusError> {
        if self.id == sender_id {
            return Err(BBSPlusError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if self.commitments.contains_key(&sender_id) {
            return Err(BBSPlusError::AlreadyHaveCommitmentFromParticipant(
                sender_id,
            ));
        }
        if self.own_shares_and_salts.len() != commitments.0.len() {
            return Err(BBSPlusError::IncorrectNoOfCommitments(
                self.own_shares_and_salts.len(),
                commitments.0.len(),
            ));
        }
        self.commitments.insert(sender_id, commitments);
        Ok(())
    }

    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares_and_salts: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), BBSPlusError> {
        if self.id == sender_id {
            return Err(BBSPlusError::SenderIdCannotBeSameAsSelf(sender_id, self.id));
        }
        if !self.commitments.contains_key(&sender_id) {
            return Err(BBSPlusError::MissingCommitmentFromParticipant(sender_id));
        }
        if self.other_shares.contains_key(&sender_id) {
            return Err(BBSPlusError::AlreadyHaveSharesFromParticipant(sender_id));
        }
        if self.own_shares_and_salts.len() != shares_and_salts.len() {
            return Err(BBSPlusError::IncorrectNoOfShares(
                self.own_shares_and_salts.len(),
                shares_and_salts.len(),
            ));
        }
        let expected_commitments = Self::compute_commitments(&shares_and_salts, &self.protocol_id);
        if expected_commitments != self.commitments.get(&sender_id).unwrap().0 {
            return Err(BBSPlusError::IncorrectCommitment);
        }
        self.other_shares.insert(
            sender_id,
            shares_and_salts.into_iter().map(|(s, _)| s).collect(),
        );
        Ok(())
    }

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
        self.commitments.contains_key(id)
    }

    pub fn has_shares_from(&self, id: &ParticipantId) -> bool {
        self.other_shares.contains_key(id)
    }

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

    use ark_std::rand::{rngs::StdRng, SeedableRng};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn cointoss() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let label = b"test".to_vec();
        let batch_size = 10;
        let num_parties = 5;
        let mut parties = vec![];
        let mut commitments = vec![];
        // All parties generate and commit to their share of the joint randomness
        for i in 1..=num_parties {
            let (party, comm) = Party::<Fr>::commit(&mut rng, i, batch_size, label.clone());
            parties.push(party);
            commitments.push(comm);
        }

        // All parties send commitment to their shares to others
        for i in 1..=num_parties {
            for j in 1..=num_parties {
                if i != j {
                    parties[i as usize - 1]
                        .receive_commitment(j, commitments[j as usize - 1].clone())
                        .unwrap();
                }
            }
        }

        // All parties send their shares to others
        for i in 1..=num_parties {
            for j in 1..=num_parties {
                if i != j {
                    let share = parties[j as usize - 1].own_shares_and_salts.clone();
                    parties[i as usize - 1].receive_shares(j, share).unwrap();
                }
            }
        }

        for i in 1..=num_parties {
            for j in 1..=num_parties {
                if i != j {
                    assert_eq!(
                        parties[j as usize - 1].other_shares.get(&i).unwrap(),
                        &parties[i as usize - 1] // TODO: Add a function
                            .own_shares_and_salts
                            .clone()
                            .into_iter()
                            .map(|s| s.0)
                            .collect::<Vec<_>>()
                    )
                }
            }
        }

        // All parties compute the joint randomness
        let mut joint_randomness = vec![];
        for party in parties {
            joint_randomness.push(party.compute_joint_randomness());
        }

        // All parties have the same joint randomness
        for i in 1..num_parties as usize {
            assert_eq!(joint_randomness[0], joint_randomness[i]);
        }
    }
}
