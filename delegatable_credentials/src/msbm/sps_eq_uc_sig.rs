//! SPSEQ-UC (Structure-Preserving Signatures on EQuivalence classes on Updatable Commitments) from section 3
//! of the [MSBM paper](https://eprint.iacr.org/2022/680). Builds on Mercurial signature

use crate::error::DelegationError;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::ops::{Add, Neg};
use ark_std::rand::RngCore;
use ark_std::{cfg_into_iter, cfg_iter, UniformRand};
use ark_std::{collections::BTreeSet, vec::Vec};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use dock_crypto_utils::ec::{
    batch_normalize_projective_into_affine, pairing_product_with_g2_prepared,
};

use dock_crypto_utils::serde_utils::{AffineGroupBytes, FieldBytes};
use schnorr_pok::error::SchnorrError;
use schnorr_pok::impl_proof_of_knowledge_of_discrete_log;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::Zeroize;

use crate::mercurial_sig::Signature as MercurialSig;
use crate::msbm::keys::{
    PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UpdateKey,
    UserPublicKey, UserSecretKey,
};
use crate::set_commitment::{
    AggregateSubsetWitness, SetCommitment, SetCommitmentOpening, SetCommitmentSRS, SubsetWitness,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl_proof_of_knowledge_of_discrete_log!(RandCommitmentProtocol, RandCommitmentProof);

#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
)]
pub struct Signature<E: PairingEngine> {
    /// Signature on the set-commitments
    pub comm_sig: MercurialSig<E>,
    /// Tag that has the user's public key which can switched with another user's
    #[serde_as(as = "AffineGroupBytes")]
    pub T: E::G1Affine,
}

impl<E: PairingEngine> Signature<E> {
    /// Generate a new signature and optionally an update key if `update_key_index` is provided.
    /// `messages` is a nested vector where each inner vector corresponds to one set of attributes and
    /// 1 set commitment will generated corresponding to each set. The commitments are then signed using mercurial
    /// signature. The maximum size of each inner vector must be `max_attributes_per_commitment`
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: Vec<Vec<E::Fr>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<usize>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: usize,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<
        (
            Self,
            Vec<SetCommitment<E>>,
            Vec<SetCommitmentOpening<E>>,
            Option<UpdateKey<E>>,
        ),
        DelegationError,
    > {
        let k = messages.len();
        assert!(k > 0);
        if set_comm_srs.size() < max_attributes_per_commitment {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                max_attributes_per_commitment,
                set_comm_srs.size(),
            ));
        }

        let mut commitments = Vec::with_capacity(k);
        let mut openings = Vec::with_capacity(k);
        let mut rho = Vec::with_capacity(k);

        // Commit to each message set
        for msgs in messages.into_iter() {
            if set_comm_srs.size() < msgs.len() {
                return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                    msgs.len(),
                    set_comm_srs.size(),
                ));
            }
            let r = E::Fr::rand(rng);
            let (com, o) = SetCommitment::new_with_given_randomness(
                r,
                msgs.into_iter().collect(),
                set_comm_srs,
            )?;
            rho.push(r);
            commitments.push(com);
            openings.push(o);
        }

        let (sig, uk) = Self::new_sig_and_update_key(
            rng,
            &commitments,
            user_public_key,
            update_key_index,
            secret_key,
            max_attributes_per_commitment,
            set_comm_srs,
        )?;
        Ok((sig, commitments, openings, uk))
    }

    /// Similar to `Self::new` but it does does not generate randomness but expects commitment to
    /// randomness and a proof that of knowledge of those commitment openings
    pub fn new_with_given_commitment_to_randomness<R: RngCore>(
        rng: &mut R,
        trapdoor_set_comm_srs: &E::Fr,
        commitment_to_randomness: Vec<E::G1Affine>,
        commitment_to_randomness_proof: Vec<RandCommitmentProof<E::G1Affine>>,
        challenge: &E::Fr,
        messages: Vec<Vec<E::Fr>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<usize>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: usize,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Vec<SetCommitment<E>>, Option<UpdateKey<E>>), DelegationError> {
        let k = messages.len();
        assert!(k > 0);
        if commitment_to_randomness.len() != k {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitment_to_randomness.len(),
                k,
            ));
        }
        if commitment_to_randomness_proof.len() != k {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitment_to_randomness_proof.len(),
                k,
            ));
        }

        // Verify proof of knowledge of randomness in the commitment
        for (i, proof) in commitment_to_randomness_proof.into_iter().enumerate() {
            if !proof.verify(
                &commitment_to_randomness[i],
                set_comm_srs.get_P1(),
                challenge,
            ) {
                return Err(DelegationError::InvalidSchnorrProof);
            }
        }
        let mut commitments = Vec::with_capacity(k);

        // Commit to each message set
        for (msgs, r) in messages
            .into_iter()
            .zip(commitment_to_randomness.into_iter())
        {
            if set_comm_srs.size() < msgs.len() {
                return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                    msgs.len(),
                    set_comm_srs.size(),
                ));
            }
            let com = SetCommitment::new_with_given_commitment_to_randomness(
                r,
                trapdoor_set_comm_srs,
                msgs.into_iter().collect(),
                set_comm_srs,
            )?;
            commitments.push(com);
        }
        let (sig, uk) = Self::new_sig_and_update_key(
            rng,
            &commitments,
            user_public_key,
            update_key_index,
            secret_key,
            max_attributes_per_commitment,
            set_comm_srs,
        )?;
        Ok((sig, commitments, uk))
    }

    /// Verify the signature given all messages and corresponding set commitments.
    pub fn verify(
        &self,
        commitments: &[SetCommitment<E>],
        message_sets: Vec<Vec<E::Fr>>,
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &RootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.verify_using_prepared_key(
            commitments,
            message_sets,
            openings,
            user_public_key,
            &issuer_public_key.prepared(),
            set_comm_srs,
        )
    }

    /// Verify the signature given set commitments corresponding to the messages and subsets of those
    /// messages and corresponding witnesses.
    pub fn verify_for_subsets(
        &self,
        commitments: &[SetCommitment<E>],
        subsets: Vec<Vec<E::Fr>>,
        subset_witnesses: &[SubsetWitness<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &RootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.verify_for_subsets_using_prepared_key(
            commitments,
            subsets,
            subset_witnesses,
            user_public_key,
            &issuer_public_key.prepared(),
            set_comm_srs,
        )
    }

    /// Similar to `Self::verify_for_subsets` but an aggregated witness is given for all subsets
    pub fn verify_for_subsets_with_aggregated_witness<
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<Vec<E::Fr>>,
        agg_witnesses: &AggregateSubsetWitness<E>,
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &RootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.verify_for_subsets_with_aggregated_witness_using_prepared_key::<D>(
            commitments,
            subsets,
            agg_witnesses,
            user_public_key,
            &issuer_public_key.prepared(),
            set_comm_srs,
        )
    }

    /// ChangeRep from the paper
    pub fn change_rep(
        &self,
        commitments: &[SetCommitment<E>],
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        update_key: Option<&UpdateKey<E>>,
        issuer_public_key: &RootIssuerPublicKey<E>,
        mu: &E::Fr,
        psi: &E::Fr,
        chi: &E::Fr,
        max_attributes_per_credential: usize,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<
        (
            Self,
            Vec<SetCommitment<E>>,
            Vec<SetCommitmentOpening<E>>,
            Option<UpdateKey<E>>,
            UserPublicKey<E>,
        ),
        DelegationError,
    > {
        let mut new_openings = openings.to_vec();
        for o in &mut new_openings {
            o.randomize(*mu);
        }
        let psi_inv = psi.inverse().unwrap();
        let (new_comm_sig, new_comms) = self.comm_sig.change_rep_with_given_randomness(
            mu,
            &psi_inv,
            &commitments.iter().map(|c| c.0).collect::<Vec<_>>(),
        );
        let new_T = self
            .T
            .mul(*psi)
            .add(issuer_public_key.X_0.mul(*chi * *psi))
            .into_affine();
        let new_pk = user_public_key.randomize_using_given_randomness(psi, chi, srs.get_P1());
        let mut new_uk = None;
        if let Some(uk) = update_key {
            uk.verify(&self, issuer_public_key, max_attributes_per_credential, srs)?;

            // The paper says the following commented line but that seems wrong.
            // let m = *mu * psi_inv;
            // new_uk = Some(uk.randomize(&m));

            new_uk = Some(uk.randomize(&psi_inv));
        }
        Ok((
            Self {
                comm_sig: new_comm_sig,
                T: new_T,
            },
            new_comms
                .into_iter()
                .map(|c| SetCommitment(c))
                .collect::<Vec<_>>(),
            new_openings,
            new_uk,
            new_pk,
        ))
    }

    /// ChangeRel from the paper. `insert_at_index` is the 0-based index where the commitment of the given messages should be inserted.
    pub fn change_rel(
        &self,
        messages: Vec<E::Fr>,
        insert_at_index: usize,
        new_update_key_index: Option<usize>,
        update_key: &UpdateKey<E>,
        rho: E::Fr,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<
        (
            Self,
            SetCommitment<E>,
            SetCommitmentOpening<E>,
            Option<UpdateKey<E>>,
        ),
        DelegationError,
    > {
        if update_key.start_index > insert_at_index {
            return Err(DelegationError::UnsupportedIndexInUpdateKey(
                insert_at_index,
                update_key.start_index,
                update_key.end_index(),
            ));
        }
        if update_key.max_attributes_per_commitment < messages.len() {
            return Err(DelegationError::UnsupportedNoOfAttributesInUpdateKey(
                messages.len(),
                update_key.max_attributes_per_commitment,
            ));
        }

        let msg_set = messages.into_iter().collect::<BTreeSet<_>>();

        let mut new_z = SetCommitmentSRS::<E>::eval::<E::G1Affine>(
            msg_set.clone(),
            &update_key.get_key_for_index(insert_at_index),
        )
        .mul(rho.into_repr());
        new_z.add_assign_mixed(&self.comm_sig.Z);
        let mut new_sig = self.clone();
        new_sig.comm_sig.Z = new_z.into_affine();

        let (com, o) = SetCommitment::<E>::new_with_given_randomness(rho, msg_set, srs)?;

        let mut uk = None;
        if let Some(l) = new_update_key_index {
            if (l > update_key.end_index()) || (l < update_key.start_index) {
                return Err(DelegationError::UnsupportedIndexInUpdateKey(
                    l,
                    update_key.start_index,
                    update_key.end_index(),
                ));
            }
            uk = Some(update_key.trim_key(insert_at_index + 1, l));
        }
        Ok((new_sig, com, o, uk))
    }

    pub fn verify_using_prepared_key(
        &self,
        commitments: &[SetCommitment<E>],
        message_sets: Vec<Vec<E::Fr>>,
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &PreparedRootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != message_sets.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                message_sets.len(),
            ));
        }
        if commitments.len() != openings.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                openings.len(),
            ));
        }

        self.verify_sig(
            commitments,
            user_public_key,
            issuer_public_key,
            set_comm_srs,
        )?;
        for (i, msgs) in message_sets.into_iter().enumerate() {
            commitments[i].open_set(&openings[i], msgs.into_iter().collect(), set_comm_srs)?;
        }
        Ok(())
    }

    pub fn verify_for_subsets_using_prepared_key(
        &self,
        commitments: &[SetCommitment<E>],
        subsets: Vec<Vec<E::Fr>>,
        subset_witnesses: &[SubsetWitness<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &PreparedRootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                subsets.len(),
            ));
        }
        if commitments.len() != subset_witnesses.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                subset_witnesses.len(),
            ));
        }
        self.verify_sig(
            commitments,
            user_public_key,
            issuer_public_key,
            set_comm_srs,
        )?;
        for (i, subset) in subsets.into_iter().enumerate() {
            subset_witnesses[i].verify(
                subset.into_iter().collect(),
                &commitments[i],
                set_comm_srs,
            )?;
        }
        Ok(())
    }

    pub fn verify_for_subsets_with_aggregated_witness_using_prepared_key<
        D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<Vec<E::Fr>>,
        agg_witnesses: &AggregateSubsetWitness<E>,
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &PreparedRootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                subsets.len(),
            ));
        }
        self.verify_sig(
            &commitments,
            user_public_key,
            issuer_public_key,
            set_comm_srs,
        )?;
        agg_witnesses.verify::<D>(
            commitments,
            subsets
                .into_iter()
                .map(|s| s.into_iter().collect())
                .collect(),
            set_comm_srs,
        )?;
        Ok(())
    }

    /// Remove the user's public key from the signature making it orphan
    pub fn to_orphan(
        &self,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: &RootIssuerPublicKey<E>,
    ) -> Self {
        let mut new_sig = self.clone();
        let mut new_t = issuer_public_key.X_0.mul(user_secret_key.0.neg());
        new_t.add_assign_mixed(&self.T);
        new_sig.T = new_t.into_affine();
        new_sig
    }

    /// Attach a user's public key to an orphan signature.
    pub fn from_orphan(
        &self,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: &RootIssuerPublicKey<E>,
    ) -> Self {
        let mut new_sig = self.clone();
        let mut new_t = issuer_public_key.X_0.mul(user_secret_key.0);
        new_t.add_assign_mixed(&self.T);
        new_sig.T = new_t.into_affine();
        new_sig
    }

    fn new_sig_and_update_key<R: RngCore>(
        rng: &mut R,
        commitments: &[SetCommitment<E>],
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<usize>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: usize,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let k = commitments.len();

        let y = E::Fr::rand(rng);
        let y_inv = y.inverse().unwrap();
        // The implementation of following Mercurial sig has y multiplied by Z and 1/y multiplied by Y and Y_tilde but the algorithm mentioned in this paper assumes the opposite. So passing
        // 1/y to keep the rest of the implementation matching the paper
        let comm_sig = MercurialSig::new_with_given_randomness(
            &y_inv,
            &commitments.iter().map(|c| c.0).collect::<Vec<_>>(),
            &secret_key.1,
            srs.get_P1(),
            srs.get_P2(),
        )?;
        let sk_merc = &secret_key.1 .0;
        let T = srs
            .get_P1()
            .mul(sk_merc[0] * y)
            .add(user_public_key.0.mul(secret_key.0))
            .into_affine();
        let sig = Self { comm_sig, T };
        let mut uk = None;
        if let Some(k_prime) = update_key_index {
            if k_prime < k {
                return Err(DelegationError::InvalidUpdateKeyIndex(k_prime, k));
            }
            if k_prime >= sk_merc.len() {
                return Err(
                    DelegationError::CannotCreateUpdateKeyOfRequiredSizeFromSecretKey(
                        k_prime,
                        sk_merc.len(),
                    ),
                );
            }
            let powers = &srs.P1[0..max_attributes_per_commitment];
            let key = cfg_into_iter!(k..=k_prime)
                .map(|i| {
                    let p = cfg_iter!(powers)
                        .map(|p| p.mul(sk_merc[i] * y_inv))
                        .collect();
                    batch_normalize_projective_into_affine(p)
                })
                .collect::<Vec<_>>();
            uk = Some(UpdateKey {
                start_index: k,
                max_attributes_per_commitment,
                keys: key,
            })
        }
        Ok((sig, uk))
    }

    fn verify_sig(
        &self,
        commitments: &[SetCommitment<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: &PreparedRootIssuerPublicKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let P2 = set_comm_srs.get_P2();
        self.comm_sig.verify_using_prepared_public_key(
            &commitments.iter().map(|c| c.0).collect::<Vec<_>>(),
            &issuer_public_key.X,
            set_comm_srs.get_P1(),
            P2,
        )?;
        if !pairing_product_with_g2_prepared::<E>(
            &[self.comm_sig.Y, user_public_key.0, self.T.neg()],
            &[
                issuer_public_key.X.0[0].clone(),
                issuer_public_key.X_0_hat.clone(),
                E::G2Prepared::from(*P2),
            ],
        )
        .is_one()
        {
            return Err(DelegationError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::msbm::keys::UserSecretKey;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn sign_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let t = 15;
        let max_attributes = 20;
        let l = 7;

        let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let msgs_1 = (0..t - 2).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_2 = (0..t - 1).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_3 = (0..t - 5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_4 = (0..t - 3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let (sig, comms, opns, uk) = Signature::new(
            &mut rng,
            vec![msgs_1.clone()],
            &upk,
            None,
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![msgs_1.clone()],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        let (mu, psi, chi) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));

        let (sig, comms, opns, uk, new_upk) = sig
            .change_rep(
                &comms,
                &opns,
                &upk,
                None,
                &ipk,
                &mu,
                &psi,
                &chi,
                t,
                &set_comm_srs,
            )
            .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![msgs_1.clone()],
            &opns,
            &new_upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        for j in 1..l {
            let (sig, comms, opns, uk) = Signature::new(
                &mut rng,
                vec![msgs_1.clone()],
                &upk,
                Some(j),
                &isk,
                t,
                &set_comm_srs,
            )
            .unwrap();
            sig.verify(
                &comms,
                vec![msgs_1.clone()],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 1);
            assert_eq!(uk.keys.len(), j);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();

            let (sig, comms, opns, uk, new_upk) = sig
                .change_rep(
                    &comms,
                    &opns,
                    &upk,
                    Some(&uk),
                    &ipk,
                    &mu,
                    &psi,
                    &chi,
                    t,
                    &set_comm_srs,
                )
                .unwrap();
            sig.verify(
                &comms,
                vec![msgs_1.clone()],
                &opns,
                &new_upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 1);
            assert_eq!(uk.keys.len(), j - 1 + 1);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();
        }

        let (sig, comms, opns, uk) = Signature::new(
            &mut rng,
            vec![msgs_1.clone(), msgs_2.clone()],
            &upk,
            None,
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![msgs_1.clone(), msgs_2.clone()],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        let (sig, comms, opns, uk, new_upk) = sig
            .change_rep(
                &comms,
                &opns,
                &upk,
                None,
                &ipk,
                &mu,
                &psi,
                &chi,
                t,
                &set_comm_srs,
            )
            .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![msgs_1.clone(), msgs_2.clone()],
            &opns,
            &new_upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        for j in 2..l {
            let (sig, comms, opns, uk) = Signature::new(
                &mut rng,
                vec![msgs_1.clone(), msgs_2.clone()],
                &upk,
                Some(j),
                &isk,
                t,
                &set_comm_srs,
            )
            .unwrap();
            sig.verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone()],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 2);
            assert_eq!(uk.keys.len(), j - 2 + 1);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();

            let (sig, comms, opns, uk, new_upk) = sig
                .change_rep(
                    &comms,
                    &opns,
                    &upk,
                    Some(&uk),
                    &ipk,
                    &mu,
                    &psi,
                    &chi,
                    t,
                    &set_comm_srs,
                )
                .unwrap();
            sig.verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone()],
                &opns,
                &new_upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 2);
            assert_eq!(uk.keys.len(), j - 2 + 1);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();
        }

        let (sig, comms, opns, uk) = Signature::new(
            &mut rng,
            vec![msgs_1.clone(), msgs_2.clone(), msgs_3.clone()],
            &upk,
            None,
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![msgs_1.clone(), msgs_2.clone(), msgs_3.clone()],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        for j in 3..l {
            let (sig, comms, opns, uk) = Signature::new(
                &mut rng,
                vec![msgs_1.clone(), msgs_2.clone(), msgs_3.clone()],
                &upk,
                Some(j),
                &isk,
                t,
                &set_comm_srs,
            )
            .unwrap();
            sig.verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone(), msgs_3.clone()],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 3);
            assert_eq!(uk.keys.len(), j - 3 + 1);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();
        }

        let (sig, comms, opns, uk) = Signature::new(
            &mut rng,
            vec![
                msgs_1.clone(),
                msgs_2.clone(),
                msgs_3.clone(),
                msgs_4.clone(),
            ],
            &upk,
            None,
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        assert!(uk.is_none());
        sig.verify(
            &comms,
            vec![
                msgs_1.clone(),
                msgs_2.clone(),
                msgs_3.clone(),
                msgs_4.clone(),
            ],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        for j in 4..l {
            let (sig, comms, opns, uk) = Signature::new(
                &mut rng,
                vec![
                    msgs_1.clone(),
                    msgs_2.clone(),
                    msgs_3.clone(),
                    msgs_4.clone(),
                ],
                &upk,
                Some(j),
                &isk,
                t,
                &set_comm_srs,
            )
            .unwrap();
            sig.verify(
                &comms,
                vec![
                    msgs_1.clone(),
                    msgs_2.clone(),
                    msgs_3.clone(),
                    msgs_4.clone(),
                ],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 4);
            assert_eq!(uk.keys.len(), j - 4 + 1);
            uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();
        }
    }

    #[test]
    fn update_signature_and_messages() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let t = 15;
        let max_attributes = 20;
        let l = 7;

        let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let msgs_1 = (0..t - 2).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_2 = (0..t - 1).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_3 = (0..t - 5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_4 = (0..t - 3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let (sig, mut comms, mut opns, uk) = Signature::new(
            &mut rng,
            vec![msgs_1.clone()],
            &upk,
            Some(3),
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        sig.verify(
            &comms,
            vec![msgs_1.clone()],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();
        let uk = uk.unwrap();
        assert_eq!(uk.start_index, 1);
        assert_eq!(uk.keys.len(), 3 - 1 + 1);
        uk.verify(&sig, &ipk, t, &set_comm_srs).unwrap();

        let rho = Fr::rand(&mut rng);
        let (new_sig, comm, o, uk1) = sig
            .change_rel(msgs_2.clone(), 1, None, &uk, rho, &set_comm_srs)
            .unwrap();
        comms.push(comm);
        opns.push(o);
        new_sig
            .verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone()],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
        assert!(uk1.is_none());

        let rho = Fr::rand(&mut rng);
        let (new_sig, comm, o, uk1) = new_sig
            .change_rel(msgs_3.clone(), 2, None, &uk, rho, &set_comm_srs)
            .unwrap();
        comms.push(comm);
        opns.push(o);
        new_sig
            .verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone(), msgs_3.clone()],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
        assert!(uk1.is_none());

        let rho = Fr::rand(&mut rng);
        let (new_sig, comm, o, uk1) = new_sig
            .change_rel(msgs_4.clone(), 3, None, &uk, rho, &set_comm_srs)
            .unwrap();
        comms.push(comm);
        opns.push(o);
        new_sig
            .verify(
                &comms,
                vec![
                    msgs_1.clone(),
                    msgs_2.clone(),
                    msgs_3.clone(),
                    msgs_4.clone(),
                ],
                &opns,
                &upk,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
        assert!(uk1.is_none());
    }

    #[test]
    fn switch_public_key() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let t = 15;
        let max_attributes = 20;
        let l = 7;

        let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let usk1 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk1 = UserPublicKey::new(&usk1, set_comm_srs.get_P1());

        let msgs_1 = (0..t - 2).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let msgs_2 = (0..t - 1).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let (sig, comms, opns, _) = Signature::new(
            &mut rng,
            vec![msgs_1.clone(), msgs_2.clone()],
            &upk,
            None,
            &isk,
            t,
            &set_comm_srs,
        )
        .unwrap();
        sig.verify(
            &comms,
            vec![msgs_1.clone(), msgs_2.clone()],
            &opns,
            &upk,
            &ipk,
            &set_comm_srs,
        )
        .unwrap();

        let orphan_sig = sig.to_orphan(&usk, &ipk);

        let new_sig = orphan_sig.from_orphan(&usk1, &ipk);

        new_sig
            .verify(
                &comms,
                vec![msgs_1.clone(), msgs_2.clone()],
                &opns,
                &upk1,
                &ipk,
                &set_comm_srs,
            )
            .unwrap();
    }
}
