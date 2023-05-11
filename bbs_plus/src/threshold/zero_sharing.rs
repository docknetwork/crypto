//! Generate a secret sharing of 0. Does not use a trusted party or Shamir secret sharing.
//! Called F_zero and described in section 3.1 in the paper

use crate::{
    error::BBSPlusError,
    threshold::commitment::{Commitments, Party as CommitmentParty, SALT_SIZE},
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
use oblivious_transfer_protocols::ParticipantId;

// TODO: This should be generic over the size of random committed seeds. Called lambda in the paper
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party<F: PrimeField> {
    pub id: ParticipantId,
    pub protocol_id: Vec<u8>,
    pub batch_size: usize,
    /// Commit-and-release coin tossing protocols run with each party
    pub cointoss_protocols: BTreeMap<ParticipantId, CommitmentParty<F>>,
}

impl<F: PrimeField> Party<F> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        batch_size: usize,
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

    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        commitments: Commitments,
    ) -> Result<(), BBSPlusError> {
        if !self.cointoss_protocols.contains_key(&sender_id) {
            return Err(BBSPlusError::UnexpectedParticipant(sender_id));
        }
        let protocol = self.cointoss_protocols.get_mut(&sender_id).unwrap();
        protocol.receive_commitment(sender_id, commitments)?;
        Ok(())
    }

    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), BBSPlusError> {
        if !self.cointoss_protocols.contains_key(&sender_id) {
            return Err(BBSPlusError::UnexpectedParticipant(sender_id));
        }
        let protocol = self.cointoss_protocols.get_mut(&sender_id).unwrap();
        protocol.receive_shares(sender_id, shares)?;
        Ok(())
    }

    pub fn compute_zero_shares<D: Default + DynDigest + Clone>(
        self,
    ) -> Result<Vec<F>, BBSPlusError> {
        let mut randoness = BTreeMap::<ParticipantId, Vec<F>>::new();
        let mut shares = vec![F::zero(); self.batch_size];
        for (id, protocol) in self.cointoss_protocols {
            if !protocol.has_shares_from(&id) {
                return Err(BBSPlusError::MissingSharesFromParticipant(id));
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

    pub fn has_commitment_from(&self, id: &ParticipantId) -> Result<bool, BBSPlusError> {
        if !self.cointoss_protocols.contains_key(id) {
            return Err(BBSPlusError::UnexpectedParticipant(*id));
        }
        let protocol = self.cointoss_protocols.get(id).unwrap();
        Ok(protocol.commitments.contains_key(id))
    }

    pub fn has_shares_from(&self, id: &ParticipantId) -> Result<bool, BBSPlusError> {
        if !self.cointoss_protocols.contains_key(id) {
            return Err(BBSPlusError::UnexpectedParticipant(*id));
        }
        let protocol = self.cointoss_protocols.get(id).unwrap();
        Ok(protocol.other_shares.contains_key(id))
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

    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn zero_sharing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let protocol_id = b"test".to_vec();
        let batch_size = 10;
        let num_parties = 5;
        let all_party_set = (1..=num_parties).into_iter().collect::<BTreeSet<_>>();
        let mut parties = vec![];
        let mut commitments = vec![];

        for i in 1..=num_parties {
            let mut others = all_party_set.clone();
            others.remove(&i);
            let (party, comm) =
                Party::<Fr>::init(&mut rng, i, batch_size, others, protocol_id.clone());
            parties.push(party);
            commitments.push(comm);
        }

        for i in 1..=num_parties {
            for j in 1..=num_parties {
                if i != j {
                    parties[i as usize - 1]
                        .receive_commitment(j, commitments[j as usize - 1].get(&i).unwrap().clone())
                        .unwrap();
                }
            }
        }

        for i in 1..=num_parties {
            for j in 1..=num_parties {
                if i != j {
                    let share = parties[j as usize - 1] // TODO: Add a function for this.
                        .cointoss_protocols
                        .get(&i)
                        .unwrap()
                        .own_shares_and_salts
                        .clone();
                    parties[i as usize - 1].receive_shares(j, share).unwrap();
                }
            }
        }

        let mut zero_shares = vec![];
        for party in parties {
            zero_shares.push(party.compute_zero_shares::<Blake2b512>().unwrap());
        }
        assert_eq!(zero_shares.len(), num_parties as usize);
        for i in 0..batch_size {
            let mut sum = Fr::zero();
            for j in 0..num_parties {
                sum += zero_shares[j as usize][i];
            }
            assert!(sum.is_zero());
        }
    }
}
