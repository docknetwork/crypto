//! Root and delegated credential issuance from Fig. 3 of the paper

use crate::{
    error::DelegationError,
    msbm::{
        keys::{
            PreparedRootIssuerPublicKey, RootIssuerSecretKey, UpdateKey, UserPublicKey,
            UserSecretKey,
        },
        sps_eq_uc_sig::Signature,
    },
    set_commitment::{SetCommitment, SetCommitmentOpening, SetCommitmentSRS},
};
use ark_ec::pairing::Pairing;
use ark_std::{rand::RngCore, vec::Vec, UniformRand};
use schnorr_pok::discrete_log::PokDiscreteLog;

/// Credential issued by a root or delegated issuer when it knows the randomness for set commitments
/// of attributes
#[derive(Clone, Debug)]
pub struct Credential<E: Pairing> {
    pub max_attributes_per_commitment: u32,
    pub attributes: Vec<Vec<E::ScalarField>>,
    pub commitments: Vec<SetCommitment<E>>,
    pub openings: Vec<SetCommitmentOpening<E>>,
    pub signature: Signature<E>,
}

/// Credential issued by a root issuer when given only the commitment to the randomness for set commitments
/// of attributes
#[derive(Clone, Debug)]
pub struct CredentialWithoutOpenings<E: Pairing> {
    pub max_attributes_per_commitment: u32,
    pub attributes: Vec<Vec<E::ScalarField>>,
    pub commitments: Vec<SetCommitment<E>>,
    pub signature: Signature<E>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pseudonym<E: Pairing> {
    pub nym: UserPublicKey<E>,
    pub secret: UserSecretKey<E>,
}

impl<E: Pairing> Credential<E> {
    /// Credential issued directly by the root issuer. The attributes are expected to be unique as the are committed
    /// using a set commitment scheme. One approach is to encode attributes as pairs with 1st element of the
    /// pair as an index and the 2nd element as the actual attribute value like `(0, attribute[0]), (1, attribute[1]), (2, attribute[2]), (n, attribute[n])`
    pub fn issue_root<R: RngCore>(
        rng: &mut R,
        attributes: Vec<Vec<E::ScalarField>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<u32>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: u32,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let (signature, commitments, openings, uk) = Signature::new(
            rng,
            attributes.clone(),
            user_public_key,
            update_key_index,
            secret_key,
            max_attributes_per_commitment,
            set_comm_srs,
        )?;
        Ok((
            Self {
                max_attributes_per_commitment,
                attributes,
                commitments,
                openings,
                signature,
            },
            uk,
        ))
    }

    /// Credential issued by the a delegated issuer after adding more attributes. The issued credential will
    /// have an orphan signature, i.e. the receiver's public key is not attached in the signature. The attributes
    /// are expected to be unique as the are committed using a set commitment scheme. One approach is to encode
    /// attributes as pairs with 1st element of the pair as an index and the 2nd element as the actual attribute
    /// value like `(0, attribute[0]), (1, attribute[1]), (2, attribute[2]), (n, attribute[n])`
    pub fn delegate_with_new_attributes<R: RngCore>(
        mut self,
        rng: &mut R,
        attributes: Vec<E::ScalarField>,
        user_secret_key: &UserSecretKey<E>,
        X_0: &E::G1Affine,
        new_update_key_index: Option<u32>,
        update_key: &UpdateKey<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let rho = E::ScalarField::rand(rng);
        let (new_sig, comm, o, new_uk) = self.signature.change_rel(
            attributes.clone(),
            self.attributes
                .len()
                .try_into()
                .map_err(|_| DelegationError::TooManyAttributes(self.attributes.len()))?,
            new_update_key_index,
            update_key,
            rho,
            set_comm_srs,
        )?;
        self.attributes.push(attributes);
        self.commitments.push(comm);
        self.openings.push(o);
        self.signature = new_sig.to_orphan(user_secret_key, X_0);
        Ok((self, new_uk))
    }

    /// Credential issued by the a delegated issuer without adding any more attributes. The issued credential will
    /// have an orphan signature, i.e. the receiver's public key is not attached in the signature.
    pub fn delegate_without_new_attributes(
        mut self,
        user_secret_key: &UserSecretKey<E>,
        X_0: &E::G1Affine,
        new_update_key_index: Option<u32>,
        update_key: &UpdateKey<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let mut new_uk = None;
        if let Some(l) = new_update_key_index {
            assert!(l <= update_key.end_index() + 1);
            new_uk = Some(
                update_key.trim_key(
                    self.attributes
                        .len()
                        .try_into()
                        .map_err(|_| DelegationError::TooManyAttributes(self.attributes.len()))?,
                    l,
                ),
            );
        }
        self.signature = self.signature.to_orphan(user_secret_key, X_0);
        Ok((self, new_uk))
    }

    pub fn randomize<R: RngCore>(
        self,
        rng: &mut R,
        user_public_key: &UserPublicKey<E>,
        update_key: Option<&UpdateKey<E>>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<
        (
            Self,
            Option<UpdateKey<E>>,
            UserPublicKey<E>,
            E::ScalarField,
            E::ScalarField,
        ),
        DelegationError,
    > {
        let (mu, psi, chi) = (
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
            E::ScalarField::rand(rng),
        );
        let (cred, uk, upk) = self.randomize_with_given_randomness(
            &mu,
            psi,
            chi,
            user_public_key,
            update_key,
            issuer_public_key,
            set_comm_srs,
        )?;
        Ok((cred, uk, upk, psi, chi))
    }

    pub fn randomize_for_show<R: RngCore>(
        self,
        rng: &mut R,
        commitment_randomness: &E::ScalarField,
        user_public_key: &UserPublicKey<E>,
        X_0: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, UserPublicKey<E>, E::ScalarField, E::ScalarField), DelegationError> {
        let (psi, chi) = (E::ScalarField::rand(rng), E::ScalarField::rand(rng));
        let (cred, upk) = self.randomize_without_update_key_with_given_randomness(
            commitment_randomness,
            psi,
            chi,
            user_public_key,
            X_0,
            set_comm_srs,
        )?;
        Ok((cred, upk, psi, chi))
    }

    pub fn randomize_with_given_randomness(
        self,
        mu: &E::ScalarField,
        psi: E::ScalarField,
        chi: E::ScalarField,
        user_public_key: &UserPublicKey<E>,
        update_key: Option<&UpdateKey<E>>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>, UserPublicKey<E>), DelegationError> {
        let (signature, commitments, openings, uk, new_upk) = self.signature.change_rep(
            &self.commitments,
            &self.openings,
            user_public_key,
            update_key,
            issuer_public_key,
            mu,
            &psi,
            &chi,
            self.max_attributes_per_commitment,
            set_comm_srs,
        )?;
        Ok((
            Self {
                max_attributes_per_commitment: self.max_attributes_per_commitment,
                attributes: self.attributes,
                commitments,
                openings,
                signature,
            },
            uk,
            new_upk,
        ))
    }

    pub fn randomize_without_update_key_with_given_randomness(
        self,
        mu: &E::ScalarField,
        psi: E::ScalarField,
        chi: E::ScalarField,
        user_public_key: &UserPublicKey<E>,
        X_0: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, UserPublicKey<E>), DelegationError> {
        let (signature, commitments, openings, new_upk) =
            self.signature.change_rep_without_update_key(
                &self.commitments,
                &self.openings,
                user_public_key,
                X_0,
                mu,
                &psi,
                &chi,
                set_comm_srs,
            )?;
        Ok((
            Self {
                max_attributes_per_commitment: self.max_attributes_per_commitment,
                attributes: self.attributes,
                commitments,
                openings,
                signature,
            },
            new_upk,
        ))
    }

    pub fn verify(
        &self,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
        self.signature.verify(
            &self.commitments,
            self.attributes.clone(),
            &self.openings,
            user_public_key,
            issuer_public_key.clone(),
            set_comm_srs,
        )?;
        if let Some(uk) = update_key {
            uk.verify(
                &self.signature,
                issuer_public_key,
                self.max_attributes_per_commitment,
                set_comm_srs,
            )?;
        }
        Ok(())
    }

    pub fn convert_orphan_signature(
        &mut self,
        user_secret_key: &UserSecretKey<E>,
        X_0: &E::G1Affine,
    ) {
        self.signature = self.signature.from_orphan(user_secret_key, X_0);
    }

    /// Run by an entity after receiving a credential from the root issuer. See `Self::process_received` for more details.
    pub fn process_received_from_root<R: RngCore>(
        self,
        rng: &mut R,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        self.process_received(
            rng,
            update_key,
            user_public_key,
            user_secret_key,
            issuer_public_key,
            set_comm_srs,
        )
    }

    pub fn process_received_from_root_using_given_randomness(
        self,
        mu: &E::ScalarField,
        psi: E::ScalarField,
        chi: E::ScalarField,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        self.process_received_using_given_randomness(
            mu,
            psi,
            chi,
            update_key,
            user_public_key,
            user_secret_key,
            issuer_public_key,
            set_comm_srs,
        )
    }

    /// Run by an entity after receiving a credential from a delegated issuer. It attaches its public key to the
    /// orphan signature. Rest is same as `Self::process_received_from_root`.
    pub fn process_received_delegated<R: RngCore>(
        mut self,
        rng: &mut R,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
        self.convert_orphan_signature(user_secret_key, &issuer_public_key.X_0);
        self.process_received(
            rng,
            update_key,
            user_public_key,
            user_secret_key,
            issuer_public_key,
            set_comm_srs,
        )
    }

    pub fn process_received_delegated_using_given_randomness(
        mut self,
        mu: &E::ScalarField,
        psi: E::ScalarField,
        chi: E::ScalarField,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
        self.convert_orphan_signature(user_secret_key, &issuer_public_key.X_0);
        self.process_received_using_given_randomness(
            mu,
            psi,
            chi,
            update_key,
            user_public_key,
            user_secret_key,
            issuer_public_key,
            set_comm_srs,
        )
    }

    /// Verify the received credential and then randomize the credential, update key (if needed) and user's
    /// secret and public key
    fn process_received<R: RngCore>(
        self,
        rng: &mut R,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
        self.verify(
            update_key,
            user_public_key,
            issuer_public_key.clone(),
            set_comm_srs,
        )?;
        let (cred_rand, new_uk, nym, psi, chi) = self
            .randomize(
                rng,
                user_public_key,
                update_key,
                issuer_public_key,
                set_comm_srs,
            )
            .unwrap();
        let secret = user_secret_key.randomize(&psi, &chi);
        Ok((cred_rand, Pseudonym { nym, secret }, new_uk))
    }

    fn process_received_using_given_randomness(
        self,
        mu: &E::ScalarField,
        psi: E::ScalarField,
        chi: E::ScalarField,
        update_key: Option<&UpdateKey<E>>,
        user_public_key: &UserPublicKey<E>,
        user_secret_key: &UserSecretKey<E>,
        issuer_public_key: impl Into<PreparedRootIssuerPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Pseudonym<E>, Option<UpdateKey<E>>), DelegationError> {
        let issuer_public_key = issuer_public_key.into();
        self.verify(
            update_key,
            user_public_key,
            issuer_public_key.clone(),
            set_comm_srs,
        )?;
        let (cred_rand, new_uk, nym) = self
            .randomize_with_given_randomness(
                mu,
                psi,
                chi,
                user_public_key,
                update_key,
                issuer_public_key,
                set_comm_srs,
            )
            .unwrap();
        let secret = user_secret_key.randomize(&psi, &chi);
        Ok((cred_rand, Pseudonym { nym, secret }, new_uk))
    }
}

impl<E: Pairing> CredentialWithoutOpenings<E> {
    /// This resembles the root issuance protocol from Fig 3 from the paper except that it commits to only 1 attribute
    /// set and not 2. The commitment to dummy attribute set is missing.
    pub fn issue_root_with_given_commitment_to_randomness<R: RngCore>(
        rng: &mut R,
        trapdoor: &E::ScalarField,
        commitment_to_randomness: Vec<E::G1Affine>,
        commitment_to_randomness_proof: Vec<PokDiscreteLog<E::G1Affine>>,
        challenge: &E::ScalarField,
        attributes: Vec<Vec<E::ScalarField>>,
        user_public_key: &UserPublicKey<E>,
        update_key_index: Option<u32>,
        secret_key: &RootIssuerSecretKey<E>,
        max_attributes_per_commitment: u32,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(Self, Option<UpdateKey<E>>), DelegationError> {
        let (signature, commitments, uk) = Signature::new_with_given_commitment_to_randomness(
            rng,
            trapdoor,
            commitment_to_randomness,
            commitment_to_randomness_proof,
            challenge,
            attributes.clone(),
            user_public_key,
            update_key_index,
            secret_key,
            max_attributes_per_commitment,
            set_comm_srs,
        )?;
        Ok((
            Self {
                max_attributes_per_commitment: max_attributes_per_commitment,
                attributes,
                commitments,
                signature,
            },
            uk,
        ))
    }

    /// Done by the credential receiver
    pub fn to_credential(self, openings: Vec<SetCommitmentOpening<E>>) -> Credential<E> {
        Credential {
            max_attributes_per_commitment: self.max_attributes_per_commitment,
            attributes: self.attributes,
            commitments: self.commitments,
            openings,
            signature: self.signature,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::msbm::keys::{RootIssuerPublicKey, UserSecretKey};
    use ark_bls12_381::Bls12_381;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::{compute_random_oracle_challenge, discrete_log::PokDiscreteLogProtocol};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    pub fn setup(
        rng: &mut StdRng,
        max_attributes: u32,
    ) -> (
        SetCommitmentSRS<Bls12_381>,
        Fr,
        RootIssuerSecretKey<Bls12_381>,
        RootIssuerPublicKey<Bls12_381>,
    ) {
        let (set_comm_srs, td) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(rng, max_attributes + 20, None);

        let isk = RootIssuerSecretKey::<Bls12_381>::new::<StdRng>(rng, max_attributes).unwrap();
        let ipk = RootIssuerPublicKey::new(&isk, set_comm_srs.get_P1(), set_comm_srs.get_P2());
        (set_comm_srs, td, isk, ipk)
    }

    #[test]
    fn root_issuance() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_attributes = 15;

        let (set_comm_srs, td, isk, ipk) = setup(&mut rng, max_attributes);

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk);

        let msgs_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_2 = (0..max_attributes - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_3 = (0..max_attributes - 5)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        for msgs in vec![
            vec![msgs_1.clone()],
            vec![msgs_1.clone(), msgs_2.clone()],
            vec![msgs_1, msgs_2, msgs_3],
        ] {
            let l = msgs.len();
            let (cred, _) = Credential::issue_root(
                &mut rng,
                msgs.clone(),
                &upk,
                None,
                &isk,
                max_attributes,
                &set_comm_srs,
            )
            .unwrap();
            cred.verify(None, &upk, prep_ipk.clone(), &set_comm_srs)
                .unwrap();
            assert_eq!(cred.commitments.len(), l);

            let (cred_rand, pseudonym, _) = cred
                .process_received_from_root(
                    &mut rng,
                    None,
                    &upk,
                    &usk,
                    prep_ipk.clone(),
                    &set_comm_srs,
                )
                .unwrap();
            cred_rand
                .verify(None, &pseudonym.nym, prep_ipk.clone(), &set_comm_srs)
                .unwrap();
            assert_eq!(cred_rand.commitments.len(), l);

            assert_eq!(
                UserPublicKey::new(&pseudonym.secret, set_comm_srs.get_P1()),
                pseudonym.nym
            );

            // Root credential when given commitment to randomness
            let randoms = (0..l).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let blindings = (0..l).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let mut commit_to_rands = vec![];
            let mut protocols = vec![];
            let mut proofs = vec![];
            let mut challenge_bytes = vec![];
            let P1 = set_comm_srs.get_P1();

            for i in 0..l {
                commit_to_rands.push(P1.mul_bigint(randoms[i].into_bigint()).into_affine());
                protocols.push(PokDiscreteLogProtocol::init(randoms[i], blindings[i], P1));
                protocols[i]
                    .challenge_contribution(P1, &commit_to_rands[i], &mut challenge_bytes)
                    .unwrap();
            }

            let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&challenge_bytes);
            for proto in protocols.into_iter() {
                proofs.push(proto.gen_proof(&challenge));
            }

            let (cred, _) =
                CredentialWithoutOpenings::issue_root_with_given_commitment_to_randomness(
                    &mut rng,
                    &td,
                    commit_to_rands,
                    proofs,
                    &challenge,
                    msgs,
                    &upk,
                    None,
                    &isk,
                    max_attributes,
                    &set_comm_srs,
                )
                .unwrap();
            let openings = randoms
                .into_iter()
                .map(SetCommitmentOpening::SetWithoutTrapdoor)
                .collect::<Vec<_>>();
            let cred = cred.to_credential(openings);
            cred.verify(None, &upk, prep_ipk.clone(), &set_comm_srs)
                .unwrap();
            assert_eq!(cred.commitments.len(), l);
        }
    }

    #[test]
    fn delegated_issuance() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_attributes = 15;

        let (set_comm_srs, _, isk, ipk) = setup(&mut rng, max_attributes);

        let usk = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        let usk1 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk1 = UserPublicKey::new(&usk1, set_comm_srs.get_P1());

        let usk2 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk2 = UserPublicKey::new(&usk2, set_comm_srs.get_P1());

        let usk3 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk3 = UserPublicKey::new(&usk3, set_comm_srs.get_P1());

        let usk4 = UserSecretKey::<Bls12_381>::new::<StdRng>(&mut rng);
        let upk4 = UserPublicKey::new(&usk4, set_comm_srs.get_P1());

        let prep_ipk = PreparedRootIssuerPublicKey::from(ipk.clone());

        let msgs_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let msgs_2 = (0..max_attributes - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let (root_cred, uk) = Credential::issue_root(
            &mut rng,
            vec![msgs_1],
            &upk,
            Some(3),
            &isk,
            max_attributes,
            &set_comm_srs,
        )
        .unwrap();
        let uk = uk.unwrap();
        root_cred
            .verify(Some(&uk), &upk, prep_ipk.clone(), &set_comm_srs)
            .unwrap();
        assert_eq!(root_cred.commitments.len(), 1);

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
        assert_eq!(uk.start_index, 1);
        assert_eq!(uk.keys.len(), 3);
        root_cred_rand
            .verify(Some(&uk), &pseudonym.nym, prep_ipk.clone(), &set_comm_srs)
            .unwrap();

        // Delegate without attributes from root
        let (cred1, uk1) = root_cred_rand
            .clone()
            .delegate_without_new_attributes(&pseudonym.secret, &ipk.X_0, Some(3), &uk)
            .unwrap();
        assert_eq!(cred1.commitments.len(), 1);

        let uk1 = uk1.unwrap();
        assert_eq!(uk1.start_index, 1);
        assert_eq!(uk1.keys.len(), 3);

        let (cred1_rand, pseudonym1, uk1) = cred1
            .process_received_delegated(
                &mut rng,
                Some(&uk1),
                &upk1,
                &usk1,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();
        let uk1 = uk1.unwrap();

        cred1_rand
            .verify(Some(&uk1), &pseudonym1.nym, prep_ipk.clone(), &set_comm_srs)
            .unwrap();

        assert_eq!(uk1.start_index, 1);
        assert_eq!(uk1.keys.len(), 3);

        // Delegate with attributes from root
        let (cred2, uk2) = root_cred_rand
            .delegate_with_new_attributes(
                &mut rng,
                msgs_2.clone(),
                &pseudonym.secret,
                &ipk.X_0,
                Some(3),
                &uk,
                &set_comm_srs,
            )
            .unwrap();
        assert_eq!(cred2.commitments.len(), 2);

        let uk2 = uk2.unwrap();
        assert_eq!(uk2.start_index, 2);
        assert_eq!(uk2.keys.len(), 2);

        let (cred2_rand, pseudonym2, uk2) = cred2
            .process_received_delegated(
                &mut rng,
                Some(&uk2),
                &upk2,
                &usk2,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();

        let uk2 = uk2.unwrap();

        cred2_rand
            .verify(Some(&uk2), &pseudonym2.nym, prep_ipk.clone(), &set_comm_srs)
            .unwrap();

        assert_eq!(uk2.start_index, 2);
        assert_eq!(uk2.keys.len(), 2);

        // Delegate without attributes
        let (cred3, uk3) = cred1_rand
            .delegate_without_new_attributes(&pseudonym1.secret, &ipk.X_0, Some(3), &uk1)
            .unwrap();
        assert_eq!(cred3.commitments.len(), 1);

        let uk3 = uk3.unwrap();
        assert_eq!(uk3.start_index, 1);
        assert_eq!(uk3.keys.len(), 3);

        let (cred3_rand, pseudonym3, uk3) = cred3
            .process_received_delegated(
                &mut rng,
                Some(&uk3),
                &upk3,
                &usk3,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();

        let uk3 = uk3.unwrap();

        cred3_rand
            .verify(Some(&uk3), &pseudonym3.nym, prep_ipk.clone(), &set_comm_srs)
            .unwrap();

        assert_eq!(uk3.start_index, 1);
        assert_eq!(uk3.keys.len(), 3);

        // Delegate with attributes
        let (cred4, uk4) = cred2_rand
            .delegate_with_new_attributes(
                &mut rng,
                msgs_2,
                &pseudonym2.secret,
                &ipk.X_0,
                Some(3),
                &uk2,
                &set_comm_srs,
            )
            .unwrap();
        assert_eq!(cred4.commitments.len(), 3);

        let uk4 = uk4.unwrap();

        assert_eq!(uk4.start_index, 3);
        assert_eq!(uk4.keys.len(), 1);

        let (cred4_rand, pseudonym4, uk4) = cred4
            .process_received_delegated(
                &mut rng,
                Some(&uk4),
                &upk4,
                &usk4,
                prep_ipk.clone(),
                &set_comm_srs,
            )
            .unwrap();

        let uk4 = uk4.unwrap();

        cred4_rand
            .verify(Some(&uk4), &pseudonym4.nym, prep_ipk, &set_comm_srs)
            .unwrap();

        assert_eq!(uk4.start_index, 3);
        assert_eq!(uk4.keys.len(), 1);
    }
}
