//! Credential show and verification from Fig. 3 of the paper

use ark_ec::pairing::Pairing;

use ark_std::{collections::BTreeSet, io::Write, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;

use schnorr_pok::discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol};

use crate::{
    error::DelegationError,
    msbm::{
        issuance::Credential,
        keys::{PreparedRootIssuerPublicKey, UserPublicKey, UserSecretKey},
        sps_eq_uc_sig::Signature,
    },
    set_commitment::{
        AggregateSubsetWitness, PreparedSetCommitmentSRS, SetCommitment, SetCommitmentSRS,
    },
};

#[derive(Clone, Debug)]
pub struct CredentialShow<E: Pairing> {
    /// Commitment to each attribute set
    pub commitments: Vec<SetCommitment<E>>,
    /// Signature on the commitments
    pub signature: Signature<E>,
    /// Aggregate witness for subsets of all disclosed attributes.
    pub disclosed_attributes_witness: AggregateSubsetWitness<E>,
    pub pseudonym: UserPublicKey<E>,
    /// Schnorr proof of knowledge of secret key corresponding to the pseudonym.
    pub schnorr: PokDiscreteLog<E::G1Affine>,
}

/// Protocol to create `CredentialShow`
#[derive(Clone, Debug)]
pub struct CredentialShowProtocol<E: Pairing> {
    pub commitments: Vec<SetCommitment<E>>,
    pub signature: Signature<E>,
    pub disclosed_attributes_witness: AggregateSubsetWitness<E>,
    pub pseudonym: UserPublicKey<E>,
    pub pseudonym_secret: UserSecretKey<E>,
    pub schnorr: PokDiscreteLogProtocol<E::G1Affine>,
}

impl<E: Pairing> CredentialShowProtocol<E> {
    pub fn init<R: RngCore, D: Digest>(
        rng: &mut R,
        credential: Credential<E>,
        disclose_attrs: Vec<Vec<E::ScalarField>>,
        user_secret_key: &UserSecretKey<E>,
        user_public_key: &UserPublicKey<E>,
        X_0: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        if credential.commitments.len() != disclose_attrs.len() {
            return Err(DelegationError::UnequalSizeOfSequence(
                credential.commitments.len(),
                disclose_attrs.len(),
            ));
        }
        let mu = E::ScalarField::rand(rng);

        let (rand_cred, new_upk, psi, chi) =
            credential.randomize_for_show(rng, &mu, user_public_key, X_0, set_comm_srs)?;
        let new_usk = user_secret_key.randomize(&psi, &chi);

        // TODO: Use mem::replace to move commitments and attributes out of credential and avoid clones
        let mut witnesses = Vec::with_capacity(disclose_attrs.len());
        let disclose_attrs = disclose_attrs
            .into_iter()
            .map(|v| v.into_iter().collect::<BTreeSet<_>>())
            .collect::<Vec<_>>();
        for (i, d) in disclose_attrs.clone().into_iter().enumerate() {
            // Expect the caller to pass valid subset and the correct opening
            witnesses.push(rand_cred.commitments[i].open_subset_unchecked(
                &rand_cred.openings[i],
                d,
                rand_cred.attributes[i].clone().into_iter().collect(),
                set_comm_srs,
            )?);
        }
        let disclosed_attributes_witness = AggregateSubsetWitness::new::<D>(
            rand_cred.commitments.clone(),
            disclose_attrs,
            witnesses,
        )?;

        let blinding = E::ScalarField::rand(rng);
        let schnorr = PokDiscreteLogProtocol::init(new_usk.0, blinding, set_comm_srs.get_P1());
        Ok(Self {
            commitments: rand_cred.commitments.clone(),
            signature: rand_cred.signature,
            disclosed_attributes_witness,
            pseudonym: new_upk,
            pseudonym_secret: new_usk,
            schnorr,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        P1: &E::G1Affine,
        writer: W,
    ) -> Result<(), DelegationError> {
        self.schnorr
            .challenge_contribution(P1, &self.pseudonym.0, writer)
            .map_err(|e| e.into())
    }

    pub fn gen_show(self, challenge: &E::ScalarField) -> CredentialShow<E> {
        let schnorr = self.schnorr.gen_proof(challenge);
        CredentialShow {
            commitments: self.commitments,
            signature: self.signature,
            disclosed_attributes_witness: self.disclosed_attributes_witness,
            pseudonym: self.pseudonym,
            schnorr,
        }
    }
}

impl<E: Pairing> CredentialShow<E> {
    pub fn verify<D: Digest>(
        &self,
        disclose_attrs: Vec<Vec<E::ScalarField>>,
        challenge: &E::ScalarField,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        let set_comm_srs = set_comm_srs.into();
        let P1 = *set_comm_srs.get_P1();
        self.signature
            .verify_for_subsets_with_aggregated_witness::<D>(
                self.commitments.to_vec(),
                disclose_attrs,
                &self.disclosed_attributes_witness,
                &self.pseudonym,
                issuer_public_key,
                set_comm_srs,
            )?;
        if !self.schnorr.verify(&self.pseudonym.0, &P1, challenge) {
            return Err(DelegationError::InvalidSchnorrProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        P1: &E::G1Affine,
        writer: W,
    ) -> Result<(), DelegationError> {
        self.schnorr
            .challenge_contribution(P1, &self.pseudonym.0, writer)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::msbm::{
        issuance::tests::setup,
        keys::{RootIssuerPublicKey, RootIssuerSecretKey, UserSecretKey},
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn show_from_root_credential() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_attributes = 15;

        let (set_comm_srs, _, isk, ipk) = setup(&mut rng, max_attributes);

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk.clone());
        let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());

        let msgs_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_2 = (0..max_attributes - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let (cred, _) = Credential::issue_root(
            &mut rng,
            vec![msgs_1.clone(), msgs_2.clone()],
            &upk,
            None,
            &isk,
            max_attributes,
            &set_comm_srs,
        )
        .unwrap();
        let (cred_rand, pseudonym, _) = cred
            .process_received_from_root(&mut rng, None, &upk, &usk, prep_ipk.clone(), &set_comm_srs)
            .unwrap();

        let disclosed = vec![vec![], vec![]];
        let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred_rand.clone(),
            disclosed.clone(),
            &pseudonym.secret,
            &pseudonym.nym,
            &ipk.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show = show_p.gen_show(&challenge);
        show.verify::<Blake2b512>(
            disclosed,
            &challenge,
            prep_ipk.clone(),
            prep_set_comm_srs.clone(),
        )
        .unwrap();

        let disclosed = vec![vec![msgs_1[0], msgs_1[1]], vec![msgs_2[2]]];
        let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred_rand.clone(),
            disclosed.clone(),
            &pseudonym.secret,
            &pseudonym.nym,
            &ipk.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show = show_p.gen_show(&challenge);
        show.verify::<Blake2b512>(
            disclosed,
            &challenge,
            prep_ipk.clone(),
            prep_set_comm_srs.clone(),
        )
        .unwrap();

        let disclosed = vec![vec![msgs_1[0], msgs_1[1]], vec![]];
        let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred_rand,
            disclosed.clone(),
            &pseudonym.secret,
            &pseudonym.nym,
            &ipk.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show = show_p.gen_show(&challenge);
        show.verify::<Blake2b512>(disclosed, &challenge, prep_ipk, prep_set_comm_srs)
            .unwrap();
    }

    #[test]
    fn show_from_delegated_credential() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_attributes = 15;

        let (set_comm_srs, _, isk, ipk) = setup(&mut rng, max_attributes);

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let usk1 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk1 = UserPublicKey::new(&usk1, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk.clone());
        let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());

        let msgs_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_2 = (0..max_attributes - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_3 = (0..max_attributes - 5)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let (root_cred, uk) = Credential::issue_root(
            &mut rng,
            vec![msgs_1.clone(), msgs_2.clone()],
            &upk,
            Some(2),
            &isk,
            max_attributes,
            &set_comm_srs,
        )
        .unwrap();
        let uk = uk.unwrap();

        let (root_cred_rand, pseudonym, uk) = root_cred
            .process_received_from_root(
                &mut rng,
                Some(&uk),
                &upk,
                &usk,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
        let uk = uk.unwrap();

        // Delegate credential
        let (cred1, uk1) = root_cred_rand
            .delegate_with_new_attributes(
                &mut rng,
                msgs_3.clone(),
                &pseudonym.secret,
                &ipk.X_0,
                Some(2),
                &uk,
                &set_comm_srs,
            )
            .unwrap();
        let uk1 = uk1.unwrap();

        let (cred1_rand, pseudonym1, _) = cred1
            .process_received_delegated(
                &mut rng,
                Some(&uk1),
                &upk1,
                &usk1,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();

        // Show

        let disclosed = vec![vec![], vec![], vec![]];
        let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred1_rand.clone(),
            disclosed.clone(),
            &pseudonym1.secret,
            &pseudonym1.nym,
            &ipk.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show = show_p.gen_show(&challenge);
        show.verify::<Blake2b512>(
            disclosed,
            &challenge,
            prep_ipk.clone(),
            prep_set_comm_srs.clone(),
        )
        .unwrap();

        let disclosed = vec![vec![], vec![msgs_2[1]], vec![msgs_3[0], msgs_3[3]]];
        let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred1_rand.clone(),
            disclosed.clone(),
            &pseudonym1.secret,
            &pseudonym1.nym,
            &ipk.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show = show_p.gen_show(&challenge);
        show.verify::<Blake2b512>(
            disclosed,
            &challenge,
            prep_ipk.clone(),
            prep_set_comm_srs.clone(),
        )
        .unwrap();

        for i in 0..6 {
            let disclosed = vec![
                msgs_1[0..i + 1].to_vec(),
                msgs_2[0..i + 1].to_vec(),
                msgs_3[0..i + 1].to_vec(),
            ];

            let start = Instant::now();
            let show_p = CredentialShowProtocol::init::<_, Blake2b512>(
                &mut rng,
                cred1_rand.clone(),
                disclosed.clone(),
                &pseudonym1.secret,
                &pseudonym1.nym,
                &ipk.X_0,
                &set_comm_srs,
            )
            .unwrap();
            let challenge = Fr::rand(&mut rng);
            let show = show_p.gen_show(&challenge);
            let show_time = start.elapsed();

            let start = Instant::now();
            show.verify::<Blake2b512>(
                disclosed,
                &challenge,
                prep_ipk.clone(),
                prep_set_comm_srs.clone(),
            )
            .unwrap();
            let verify_time = start.elapsed();

            println!("For credential with 3 commitments with {} attributes in total and {} disclosed attributes", msgs_1.len() + msgs_2.len() + msgs_3.len(), (i+1)*3);
            println!("Show time {:?}", show_time);
            println!("Verify time {:?}", verify_time);
        }
    }

    #[test]
    fn show_from_multiple_credentials() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_attributes = 15;

        let (set_comm_srs, _, isk1, ipk1) = setup(&mut rng, max_attributes);

        let isk2 =
            RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(&mut rng, max_attributes).unwrap();
        let ipk2 = RootIssuerPublicKey::new(&isk2, set_comm_srs.get_P1(), set_comm_srs.get_P2());

        let usk1 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk1 = UserPublicKey::new(&usk1, set_comm_srs.get_P1());

        let usk2 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk2 = UserPublicKey::new(&usk2, set_comm_srs.get_P1());

        let prep_ipk1 = PreparedRootIssuerPublicKey::from(ipk1.clone());
        let prep_ipk2 = PreparedRootIssuerPublicKey::from(ipk2.clone());
        let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());

        let msgs_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_2 = (0..max_attributes - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_3 = (0..max_attributes - 5)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_4 = (0..max_attributes - 8)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_5 = (0..max_attributes - 10)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let (root_cred, uk) = Credential::issue_root(
            &mut rng,
            vec![msgs_1, msgs_2],
            &upk1,
            Some(2),
            &isk1,
            max_attributes,
            &set_comm_srs,
        )
        .unwrap();
        let uk = uk.unwrap();
        let (root_cred_rand, pseudonym, uk) = root_cred
            .process_received_from_root(
                &mut rng,
                Some(&uk),
                &upk1,
                &usk1,
                prep_ipk1.clone(),
                &set_comm_srs,
            )
            .unwrap();
        let uk = uk.unwrap();

        // Delegate credential
        let (cred1, uk1) = root_cred_rand
            .delegate_with_new_attributes(
                &mut rng,
                msgs_3,
                &pseudonym.secret,
                &ipk1.X_0,
                Some(2),
                &uk,
                &set_comm_srs,
            )
            .unwrap();
        let uk1 = uk1.unwrap();

        let (mu, psi, chi) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let (cred1_rand, pseudonym1, _) = cred1
            .process_received_delegated_using_given_randomness(
                &mu,
                psi,
                chi,
                Some(&uk1),
                &upk2,
                &usk2,
                prep_ipk1.clone(),
                &set_comm_srs,
            )
            .unwrap();

        let (root_cred2, uk2) = Credential::issue_root(
            &mut rng,
            vec![msgs_4, msgs_5],
            &upk2,
            Some(2),
            &isk2,
            max_attributes,
            &set_comm_srs,
        )
        .unwrap();
        let uk2 = uk2.unwrap();

        let mu1 = Fr::rand(&mut rng);
        let (root_cred2_rand, pseudonym2, _) = root_cred2
            .process_received_from_root_using_given_randomness(
                &mu1,
                psi,
                chi,
                Some(&uk2),
                &upk2,
                &usk2,
                prep_ipk2.clone(),
                &set_comm_srs,
            )
            .unwrap();

        assert_eq!(pseudonym1, pseudonym2);

        let disclosed_1 = vec![vec![], vec![], vec![]];
        let disclosed_2 = vec![vec![], vec![]];
        let show_p1 = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            cred1_rand,
            disclosed_1.clone(),
            &pseudonym1.secret,
            &pseudonym1.nym,
            &ipk1.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let show_p2 = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            root_cred2_rand,
            disclosed_2.clone(),
            &pseudonym2.secret,
            &pseudonym2.nym,
            &ipk2.X_0,
            &set_comm_srs,
        )
        .unwrap();

        let mut chal_bytes = vec![];
        show_p1
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        show_p2
            .challenge_contribution(set_comm_srs.get_P1(), &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);

        let show_1 = show_p1.gen_show(&challenge);
        show_1
            .verify::<Blake2b512>(
                disclosed_1,
                &challenge,
                prep_ipk1,
                prep_set_comm_srs.clone(),
            )
            .unwrap();

        let show_2 = show_p2.gen_show(&challenge);
        show_2
            .verify::<Blake2b512>(disclosed_2, &challenge, prep_ipk2, prep_set_comm_srs)
            .unwrap();
    }
}
