//! Generate a secret sharing of 0. Does not use a trusted party or Shamir secret sharing.
//! Called F_zero and described in section 3.1 in the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)

use super::ParticipantId;
use crate::{
    cointoss::{Commitments, Party as CommitmentParty},
    error::OTError,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec,
    vec::Vec,
};
use digest::DynDigest;

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party<F: PrimeField, const SALT_SIZE: usize> {
    pub id: ParticipantId,
    pub protocol_id: Vec<u8>,
    pub batch_size: u32,
    /// Commit-and-release coin tossing protocols run with each party
    pub cointoss_protocols: BTreeMap<ParticipantId, CommitmentParty<F, SALT_SIZE>>,
}

impl<F: PrimeField, const SALT_SIZE: usize> Party<F, SALT_SIZE> {
    /// Initiates a coin-tossing protocol with each party specified in `others`. `batch_size` is the number
    /// of 0s whose shares are generated, eg, if `batch_size` is 3, then `a_1, a_2, ..., a_n`,
    /// `b_1, b_2, ..., b_n` and `c_1, c_2, ..., c_n` are generated such that `\sum_{i}(a_{i}) = 0`,
    /// `\sum_{i}(b_{i}) = 0` and `\sum_{i}(c_{i}) = 0`.
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        batch_size: u32,
        others: BTreeSet<ParticipantId>,
        protocol_id: Vec<u8>,
    ) -> (Self, BTreeMap<ParticipantId, Commitments>) {
        let mut cointoss_protocols = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for other_id in &others {
            let (protocol, commitment) =
                CommitmentParty::commit(rng, id, batch_size, protocol_id.clone());
            cointoss_protocols.insert(other_id.clone(), protocol);
            commitments.insert(other_id.clone(), commitment);
        }
        (
            Self {
                id,
                protocol_id,
                batch_size,
                cointoss_protocols,
            },
            commitments,
        )
    }

    /// Process received commitments to the shares from another party and store it
    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        commitments: Commitments,
    ) -> Result<(), OTError> {
        if !self.cointoss_protocols.contains_key(&sender_id) {
            return Err(OTError::UnexpectedParticipant(sender_id));
        }
        let protocol = self.cointoss_protocols.get_mut(&sender_id).unwrap();
        protocol.receive_commitment(sender_id, commitments)?;
        Ok(())
    }

    /// Process a received share from another party, verify it against the commitment receiver earlier
    /// and store the shares
    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), OTError> {
        if !self.cointoss_protocols.contains_key(&sender_id) {
            return Err(OTError::UnexpectedParticipant(sender_id));
        }
        let protocol = self.cointoss_protocols.get_mut(&sender_id).unwrap();
        protocol.receive_shares(sender_id, shares)?;
        Ok(())
    }

    /// Use the shares received from all parties to create `batch_size` sets of shares of 0
    pub fn compute_zero_shares<D: Default + DynDigest + Clone>(self) -> Result<Vec<F>, OTError> {
        let mut randoness = BTreeMap::<ParticipantId, Vec<F>>::new();
        let mut shares = vec![F::zero(); self.batch_size as usize];
        for (id, protocol) in self.cointoss_protocols {
            if !protocol.has_shares_from(&id) {
                return Err(OTError::MissingSharesFromParticipant(id));
            }
            randoness.insert(id, protocol.compute_joint_randomness());
        }
        let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(&self.protocol_id);
        for (id, r) in randoness {
            let (small_idx, large_idx) = if self.id < id {
                (self.id, id)
            } else {
                (id, self.id)
            };
            let h = r
                .into_iter()
                .map(|r_i| hash_to_field(small_idx, large_idx, &r_i, &hasher))
                .collect::<Vec<_>>();
            for (i, h_i) in h.into_iter().enumerate() {
                shares[i] += if small_idx == self.id { -h_i } else { h_i };
            }
        }
        Ok(shares)
    }

    pub fn has_commitment_from(&self, id: &ParticipantId) -> Result<bool, OTError> {
        if !self.cointoss_protocols.contains_key(id) {
            return Err(OTError::UnexpectedParticipant(*id));
        }
        let protocol = self.cointoss_protocols.get(id).unwrap();
        Ok(protocol.other_commitments.contains_key(id))
    }

    pub fn has_shares_from(&self, id: &ParticipantId) -> Result<bool, OTError> {
        if !self.cointoss_protocols.contains_key(id) {
            return Err(OTError::UnexpectedParticipant(*id));
        }
        let protocol = self.cointoss_protocols.get(id).unwrap();
        Ok(protocol.other_shares.contains_key(id))
    }

    /// Returns true if it has got shares from all other participants that sent commitments.
    pub fn has_shares_from_all_who_committed(&self) -> bool {
        self.cointoss_protocols
            .values()
            .all(|p| p.has_shares_from_all_who_committed())
    }
}

pub fn hash_to_field<F: PrimeField, D: Default + DynDigest + Clone>(
    party_1: ParticipantId,
    party_2: ParticipantId,
    r: &F,
    hasher: &DefaultFieldHasher<D>,
) -> F {
    let mut bytes = vec![];
    r.serialize_compressed(&mut bytes).unwrap();
    bytes.push((party_1 & 255) as u8);
    bytes.push((party_1 >> 8) as u8);
    bytes.push((party_2 & 255) as u8);
    bytes.push((party_2 >> 8) as u8);
    hasher.hash_to_field(&bytes, 1).pop().unwrap()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;
    use std::time::Instant;

    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn zero_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check(rng: &mut StdRng, batch_size: u32, num_parties: u16) {
            let protocol_id = b"test".to_vec();
            let all_party_set = (1..=num_parties).into_iter().collect::<BTreeSet<_>>();
            let mut parties = vec![];
            let mut commitments = vec![];

            let start = Instant::now();
            for i in 1..=num_parties {
                let mut others = all_party_set.clone();
                others.remove(&i);
                let (party, comm) =
                    Party::<Fr, 256>::init(rng, i, batch_size, others, protocol_id.clone());
                parties.push(party);
                commitments.push(comm);
            }
            let commit_time = start.elapsed();

            let start = Instant::now();
            for i in 1..=num_parties {
                for j in 1..=num_parties {
                    if i != j {
                        parties[i as usize - 1]
                            .receive_commitment(
                                j,
                                commitments[j as usize - 1].get(&i).unwrap().clone(),
                            )
                            .unwrap();
                    }
                }
            }
            let process_commit_time = start.elapsed();

            let start = Instant::now();
            for receiver_id in 1..=num_parties {
                for sender_id in 1..=num_parties {
                    if receiver_id != sender_id {
                        assert!(
                            !parties[receiver_id as usize - 1].has_shares_from_all_who_committed()
                        );
                        let share = parties[sender_id as usize - 1] // TODO: Add a function for this.
                            .cointoss_protocols
                            .get(&receiver_id)
                            .unwrap()
                            .own_shares_and_salts
                            .clone();
                        parties[receiver_id as usize - 1]
                            .receive_shares(sender_id, share)
                            .unwrap();
                    }
                }
                assert!(parties[receiver_id as usize - 1].has_shares_from_all_who_committed());
            }
            let process_shares_time = start.elapsed();

            for i in 0..num_parties as usize {
                assert!(parties[i].has_shares_from_all_who_committed());
            }

            let start = Instant::now();
            let mut zero_shares = vec![];
            for party in parties {
                zero_shares.push(party.compute_zero_shares::<Blake2b512>().unwrap());
            }
            let compute_zero_shares_time = start.elapsed();

            assert_eq!(zero_shares.len(), num_parties as usize);
            for i in 0..batch_size as usize {
                let mut sum = Fr::zero();
                for j in 0..num_parties {
                    sum += zero_shares[j as usize][i];
                }
                assert!(sum.is_zero());
            }

            println!("For a batch size of {} and {} parties, below is the total time taken by all parties", batch_size, num_parties);
            println!("Commitment time {:?}", commit_time);
            println!("Processing commitment time {:?}", process_commit_time);
            println!("Processing shares time {:?}", process_shares_time);
            println!("Computing zero shares time {:?}", compute_zero_shares_time);
        }

        check(&mut rng, 10, 5);
        check(&mut rng, 20, 5);
        check(&mut rng, 30, 5);
        check(&mut rng, 10, 10);
        check(&mut rng, 10, 20);
    }
}
