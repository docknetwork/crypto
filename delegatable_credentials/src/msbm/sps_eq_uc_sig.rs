//! SPSEQ-UC (Structure-Preserving Signatures on EQuivalence classes on Updatable Commitments) from section 3
//! of the [MSBM paper](https://eprint.iacr.org/2022/680). Builds on Mercurial signature

use crate::error::DelegationError;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter,
    collections::BTreeSet,
    ops::{Add, Mul, Neg},
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use digest::Digest;

use dock_crypto_utils::serde_utils::ArkObjectBytes;

use schnorr_pok::discrete_log::PokDiscreteLog;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::Zeroize;

use crate::{
    mercurial_sig::Signature as MercurialSig,
    msbm::keys::{
        PreparedRootIssuerPublicKey, RootIssuerSecretKey, UpdateKey, UserPublicKey, UserSecretKey,
    },
    set_commitment::{
        AggregateSubsetWitness, PreparedSetCommitmentSRS, SetCommitment, SetCommitmentOpening,
        SetCommitmentSRS, SubsetWitness,
    },
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
pub struct Signature<E: Pairing> {
    /// Signature on the set-commitments
    pub comm_sig: MercurialSig<E>,
    /// Tag that has the user's public key which can switched with another user's
    #[serde_as(as = "ArkObjectBytes")]
    pub T: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    /// Generate a new signature and optionally an update key if `update_key_index` is provided.
    /// `messages` is a nested vector where each inner vector corresponds to one set of attributes and
    /// 1 set commitment will generated corresponding to each set. The commitments are then signed using mercurial
    /// signature. The maximum size of each inner vector must be `max_attributes_per_commitment`
    pub fn new<R: RngCore>(
        rng: &mut R,
        messages: Vec<Vec<E::ScalarField>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<u32>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: u32,
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
        if set_comm_srs.size() < max_attributes_per_commitment as usize {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                max_attributes_per_commitment as usize,
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
            let r = E::ScalarField::rand(rng);
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
        trapdoor_set_comm_srs: &E::ScalarField,
        commitment_to_randomness: Vec<E::G1Affine>,
        commitment_to_randomness_proof: Vec<PokDiscreteLog<E::G1Affine>>,
        challenge: &E::ScalarField,
        messages: Vec<Vec<E::ScalarField>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<u32>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: u32,
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

    /// ChangeRep from the paper
    pub fn change_rep(
        &self,
        commitments: &[SetCommitment<E>],
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        update_key: Option<&UpdateKey<E>>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        mu: &E::ScalarField,
        psi: &E::ScalarField,
        chi: &E::ScalarField,
        max_attributes_per_credential: u32,
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
        let issuer_public_key = issuer_public_key.into();
        let (new_sig, new_comms, new_openings, new_pk) = self.change_rep_without_update_key(
            commitments,
            openings,
            user_public_key,
            &issuer_public_key.X_0,
            mu,
            psi,
            chi,
            srs,
        )?;

        let mut new_uk = None;
        if let Some(uk) = update_key {
            uk.verify(self, issuer_public_key, max_attributes_per_credential, srs)?;

            let psi_inv = psi.inverse().unwrap();
            // The paper says the following commented line but that seems wrong.
            // let m = *mu * psi_inv;
            // new_uk = Some(uk.randomize(&m));

            new_uk = Some(uk.randomize(&psi_inv));
        }
        Ok((new_sig, new_comms, new_openings, new_uk, new_pk))
    }

    /// ChangeRel from the paper. `insert_at_index` is the 0-based index where the commitment of the given messages should be inserted.
    pub fn change_rel(
        &self,
        messages: Vec<E::ScalarField>,
        insert_at_index: u32,
        new_update_key_index: Option<u32>,
        update_key: &UpdateKey<E>,
        rho: E::ScalarField,
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
                insert_at_index as usize,
                update_key.start_index as usize,
                update_key.end_index() as usize,
            ));
        }
        if (update_key.max_attributes_per_commitment as usize) < messages.len() {
            return Err(DelegationError::UnsupportedNoOfAttributesInUpdateKey(
                messages.len(),
                update_key.max_attributes_per_commitment as usize,
            ));
        }

        let msg_set = messages.into_iter().collect::<BTreeSet<_>>();

        let mut new_z = SetCommitmentSRS::<E>::eval::<E::G1Affine>(
            msg_set.clone(),
            update_key.get_key_for_index(insert_at_index),
        )
        .mul_bigint(rho.into_bigint());
        new_z += self.comm_sig.Z;
        let mut new_sig = self.clone();
        new_sig.comm_sig.Z = new_z.into_affine();

        let (com, o) = SetCommitment::<E>::new_with_given_randomness(rho, msg_set, srs)?;

        let mut uk = None;
        if let Some(l) = new_update_key_index {
            if (l > update_key.end_index() as u32) || (l < update_key.start_index) {
                return Err(DelegationError::UnsupportedIndexInUpdateKey(
                    l as usize,
                    update_key.start_index as usize,
                    update_key.end_index() as usize,
                ));
            }
            uk = Some(update_key.trim_key(insert_at_index as u32 + 1, l));
        }
        Ok((new_sig, com, o, uk))
    }

    /// ChangeRep from the paper but does not change the update key. Used in credential show
    pub fn change_rep_without_update_key(
        &self,
        commitments: &[SetCommitment<E>],
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        X_0: &E::G1Affine,
        mu: &E::ScalarField,
        psi: &E::ScalarField,
        chi: &E::ScalarField,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<
        (
            Self,
            Vec<SetCommitment<E>>,
            Vec<SetCommitmentOpening<E>>,
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
        let new_T = self.T.mul(*psi).add(X_0.mul(*chi * *psi)).into_affine();
        let new_pk = user_public_key.randomize_using_given_randomness(psi, chi, srs.get_P1());
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
            new_pk,
        ))
    }

    /// Verify the signature given all messages and corresponding set commitments.
    pub fn verify(
        &self,
        commitments: &[SetCommitment<E>],
        message_sets: Vec<Vec<E::ScalarField>>,
        openings: &[SetCommitmentOpening<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
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
            set_comm_srs.get_P1(),
            E::G2Prepared::from(*set_comm_srs.get_P2()),
        )?;
        for (i, msgs) in message_sets.into_iter().enumerate() {
            commitments[i].open_set(&openings[i], msgs.into_iter().collect(), set_comm_srs)?;
        }
        Ok(())
    }

    /// Verify the signature given set commitments corresponding to the messages and subsets of those
    /// messages and corresponding witnesses.
    pub fn verify_for_subsets(
        &self,
        commitments: &[SetCommitment<E>],
        subsets: Vec<Vec<E::ScalarField>>,
        subset_witnesses: &[SubsetWitness<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
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
        let set_comm_srs = set_comm_srs.into();
        self.verify_sig(
            commitments,
            user_public_key,
            issuer_public_key,
            set_comm_srs.get_P1(),
            set_comm_srs.prepared_P2.clone(),
        )?;
        for (i, subset) in subsets.into_iter().enumerate() {
            subset_witnesses[i].verify(
                subset.into_iter().collect(),
                &commitments[i],
                &set_comm_srs,
            )?;
        }
        Ok(())
    }

    /// Similar to `Self::verify_for_subsets` but an aggregated witness is given for all subsets
    pub fn verify_for_subsets_with_aggregated_witness<D: Digest>(
        &self,
        commitments: Vec<SetCommitment<E>>,
        subsets: Vec<Vec<E::ScalarField>>,
        agg_witnesses: &AggregateSubsetWitness<E>,
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        if commitments.len() != subsets.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                commitments.len(),
                subsets.len(),
            ));
        }
        let set_comm_srs = set_comm_srs.into();
        self.verify_sig(
            &commitments,
            user_public_key,
            issuer_public_key,
            set_comm_srs.get_P1(),
            set_comm_srs.prepared_P2.clone(),
        )?;
        agg_witnesses.verify::<D>(
            commitments,
            subsets
                .into_iter()
                .map(|s| s.into_iter().collect())
                .collect(),
            &SetCommitmentSRS {
                P1: set_comm_srs.P1,
                P2: set_comm_srs.P2,
            },
        )?;
        Ok(())
    }

    /// Remove the user's public key from the signature making it orphan
    pub fn to_orphan(&self, user_secret_key: &UserSecretKey<E>, X_0: &E::G1Affine) -> Self {
        let mut new_sig = self.clone();
        let mut new_t = X_0.mul(user_secret_key.0.neg());
        new_t += self.T;
        new_sig.T = new_t.into_affine();
        new_sig
    }

    /// Attach a user's public key to an orphan signature.
    pub fn from_orphan(&self, user_secret_key: &UserSecretKey<E>, X_0: &E::G1Affine) -> Self {
        let mut new_sig = self.clone();
        let mut new_t = X_0.mul(user_secret_key.0);
        new_t += self.T;
        new_sig.T = new_t.into_affine();
        new_sig
    }

    fn new_sig_and_update_key<R: RngCore>(
        rng: &mut R,
        commitments: &[SetCommitment<E>],
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<u32>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: u32,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let k = commitments
            .len()
            .try_into()
            .map_err(|_| DelegationError::TooManyCommitments(commitments.len()))?;

        let y = E::ScalarField::rand(rng);
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
                return Err(DelegationError::InvalidUpdateKeyIndex(
                    k_prime as usize,
                    k as usize,
                ));
            }
            if k_prime as usize >= sk_merc.len() {
                return Err(
                    DelegationError::CannotCreateUpdateKeyOfRequiredSizeFromSecretKey(
                        k_prime as usize,
                        sk_merc.len(),
                    ),
                );
            }
            let powers = &srs.P1[0..max_attributes_per_commitment as usize];
            let key: Vec<Vec<<E as Pairing>::G1Affine>> = cfg_into_iter!(k..=k_prime)
                .map(|i| {
                    let p = cfg_iter!(powers)
                        .map(|p| p.mul(sk_merc[i as usize] * y_inv))
                        .collect::<Vec<_>>();
                    E::G1::normalize_batch(&p)
                })
                .collect::<Vec<_>>();
            uk = Some(UpdateKey {
                start_index: k as u32,
                max_attributes_per_commitment: max_attributes_per_commitment,
                keys: key,
            })
        }
        Ok((sig, uk))
    }

    fn verify_sig(
        &self,
        commitments: &[SetCommitment<E>],
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        P1: &E::G1Affine,
        P2: impl Into<E::G2Prepared>,
    ) -> Result<(), DelegationError> {
        let P2 = P2.into();
        let issuer_public_key = issuer_public_key.into();
        let x_1 = issuer_public_key.X.0[0].clone();
        let x_0_hat = issuer_public_key.X_0_hat.clone();
        self.comm_sig.verify(
            &commitments.iter().map(|c| c.0).collect::<Vec<_>>(),
            issuer_public_key.X,
            P1,
            P2.clone(),
        )?;
        if !E::multi_pairing(
            [
                self.comm_sig.Y,
                user_public_key.0,
                (-self.T.into_group()).into_affine(),
            ],
            [x_1, x_0_hat, P2],
        )
        .is_zero()
        {
            return Err(DelegationError::InvalidSignature);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::msbm::keys::{RootIssuerPublicKey, UserSecretKey};
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn sign_verify() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let t = 15;
        let max_attributes = 20;
        let l = 7;

        let (set_comm_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk);

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
            prep_ipk.clone(),
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
                prep_ipk.clone(),
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
            prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 1);
            assert_eq!(uk.keys.len(), j as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();

            let (sig, comms, opns, uk, new_upk) = sig
                .change_rep(
                    &comms,
                    &opns,
                    &upk,
                    Some(&uk),
                    prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 1);
            assert_eq!(uk.keys.len(), (j - 1 + 1) as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();
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
            prep_ipk.clone(),
            &set_comm_srs,
        )
        .unwrap();

        let (sig, comms, opns, uk, new_upk) = sig
            .change_rep(
                &comms,
                &opns,
                &upk,
                None,
                prep_ipk.clone(),
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
            prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 2);
            assert_eq!(uk.keys.len(), (j - 2 + 1) as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();

            let (sig, comms, opns, uk, new_upk) = sig
                .change_rep(
                    &comms,
                    &opns,
                    &upk,
                    Some(&uk),
                    prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 2);
            assert_eq!(uk.keys.len(), (j - 2 + 1) as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();
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
            prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 3);
            assert_eq!(uk.keys.len(), (j - 3 + 1) as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();
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
            prep_ipk.clone(),
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
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
            let uk = uk.unwrap();
            assert_eq!(uk.start_index, 4);
            assert_eq!(uk.keys.len(), (j - 4 + 1) as usize);
            uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();
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
            Blake2b512,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk);

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
            prep_ipk.clone(),
            &set_comm_srs,
        )
        .unwrap();
        let uk = uk.unwrap();
        assert_eq!(uk.start_index, 1);
        assert_eq!(uk.keys.len(), 3 - 1 + 1);
        uk.verify(&sig, prep_ipk.clone(), t, &set_comm_srs).unwrap();

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
                prep_ipk.clone(),
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
                prep_ipk.clone(),
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
                vec![msgs_1, msgs_2, msgs_3, msgs_4],
                &opns,
                &upk,
                prep_ipk,
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
            Blake2b512,
        >(&mut rng, max_attributes, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, l).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let usk1 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk1 = UserPublicKey::new(&usk1, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk.clone());

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
            prep_ipk.clone(),
            &set_comm_srs,
        )
        .unwrap();

        let orphan_sig = sig.to_orphan(&usk, &ipk.X_0);

        let new_sig = orphan_sig.from_orphan(&usk1, &ipk.X_0);

        new_sig
            .verify(
                &comms,
                vec![msgs_1, msgs_2],
                &opns,
                &upk1,
                prep_ipk,
                &set_comm_srs,
            )
            .unwrap();
    }
}
