//! Credential show (presentation) protocol when the signer (public key) is hidden from the verifier using
//! a set of decoy public keys and the user proves that the signature in the credential was created by an
//! issuer whose public key is present belongs to a set, like a ring signature.
//! This is what the paper calls Protego

use crate::accumulator::NonMembershipWitness;
use crate::auditor::AuditorPublicKey;
use crate::error::DelegationError;
use crate::one_of_n_proof::{OneOfNProof, OneOfNSrs};
use crate::protego::issuance::Credential;
use crate::protego::keys::{IssuerPublicKey, UserPublicKey, UserSecretKey};
use crate::protego::show::known_signer::{CredentialShow, CredentialShowProtocol};
use crate::set_commitment::SetCommitmentSRS;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use ark_std::UniformRand;

/// Contains the randomized issuer public key and a proof that this randomized key was created from a set
/// containing some decoy public keys and the issuer public key.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKeyAnonymityProof<E: PairingEngine> {
    pub randomized_pk: IssuerPublicKey<E>,
    pub proof: OneOfNProof<E>,
}

/// Protocol to create `CredentialShowWithHiddenPublicKey`
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShowProtocolWithHiddenPublicKey<E: PairingEngine> {
    pub credential_show_protocol: CredentialShowProtocol<E>,
    pub pubkey_anonymity_proof: PublicKeyAnonymityProof<E>,
}

/// Credential show where the public key is hidden among a set of decoys
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShowWithHiddenPublicKey<E: PairingEngine> {
    pub credential_show: CredentialShow<E>,
    pub pubkey_anonymity_proof: PublicKeyAnonymityProof<E>,
}

impl<E: PairingEngine> CredentialShowProtocolWithHiddenPublicKey<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::Fr>,
        issuer_public_key: &IssuerPublicKey<E>,
        decoy_public_keys: &[IssuerPublicKey<E>],
        one_of_n_srs: &OneOfNSrs<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        CredentialShowProtocol::check_key_compat(
            issuer_public_key,
            credential.auditable_sig,
            false,
        )?;
        Self::check_key_compat(decoy_public_keys, credential.auditable_sig, false)?;

        let (rho, pubkey_anonymity_proof) = Self::pk_proof(
            rng,
            issuer_public_key,
            decoy_public_keys,
            one_of_n_srs,
            set_comm_srs,
        )?;
        let c_show = CredentialShowProtocol::_init(
            rng,
            credential,
            disclosed_attributes,
            Some(&rho),
            None,
            None,
            None,
            user_pk,
            auditor_pk,
            None,
            set_comm_srs,
        )?;
        Ok(Self {
            credential_show_protocol: c_show,
            pubkey_anonymity_proof,
        })
    }

    pub fn init_with_revocation<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::Fr>,
        accumulated: &E::G1Affine,
        non_mem_wit: &NonMembershipWitness<E>,
        issuer_public_key: &IssuerPublicKey<E>,
        decoy_public_keys: &[IssuerPublicKey<E>],
        one_of_n_srs: &OneOfNSrs<E>,
        user_sk: &UserSecretKey<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        Q: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        CredentialShowProtocol::check_key_compat(
            issuer_public_key,
            credential.auditable_sig,
            true,
        )?;
        Self::check_key_compat(decoy_public_keys, credential.auditable_sig, true)?;
        let (rho, pubkey_anonymity_proof) = Self::pk_proof(
            rng,
            issuer_public_key,
            decoy_public_keys,
            one_of_n_srs,
            set_comm_srs,
        )?;
        let c_show = CredentialShowProtocol::_init(
            rng,
            credential,
            disclosed_attributes,
            Some(&rho),
            Some(accumulated),
            Some(non_mem_wit),
            Some(user_sk),
            user_pk,
            auditor_pk,
            Some(Q),
            set_comm_srs,
        )?;
        Ok(Self {
            credential_show_protocol: c_show,
            pubkey_anonymity_proof,
        })
    }

    pub fn gen_show(
        self,
        user_secret_key: Option<&UserSecretKey<E>>,
        challenge: &E::Fr,
    ) -> Result<CredentialShowWithHiddenPublicKey<E>, DelegationError> {
        Ok(CredentialShowWithHiddenPublicKey {
            credential_show: self
                .credential_show_protocol
                .gen_show(user_secret_key, challenge)?,
            pubkey_anonymity_proof: self.pubkey_anonymity_proof,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulated: Option<&E::G1Affine>,
        Q: Option<&E::G1Affine>,
        apk: Option<&AuditorPublicKey<E>>,
        P1: &E::G1Affine,
        context: &[u8],
        mut writer: W,
    ) -> Result<(), DelegationError> {
        self.credential_show_protocol.challenge_contribution(
            accumulated,
            Q,
            apk,
            P1,
            context,
            &mut writer,
        )?;
        Ok(())
    }

    /// Create a randomized version `issuer_public_key` and put the `issuer_public_key` along with the
    /// `decoy_public_keys` in a set and create a proof that the randomized `issuer_public_key` from created
    /// from the one of the set member
    fn pk_proof<R: RngCore>(
        rng: &mut R,
        issuer_public_key: &IssuerPublicKey<E>,
        decoy_public_keys: &[IssuerPublicKey<E>],
        one_of_n_srs: &OneOfNSrs<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(E::Fr, PublicKeyAnonymityProof<E>), DelegationError> {
        let rho = E::Fr::rand(rng);
        let randomized_pk = issuer_public_key.public_key.convert(&rho);
        let instance = &randomized_pk.0;
        let actual = &issuer_public_key.public_key.0;
        let decoys = decoy_public_keys
            .iter()
            .map(|pk| pk.public_key.0.as_slice())
            .collect::<Vec<_>>();
        let one_of_n_proof = OneOfNProof::new(
            rng,
            actual,
            decoys,
            instance,
            &rho,
            one_of_n_srs,
            set_comm_srs.get_P1(),
        )?;
        let randomized_pk = IssuerPublicKey {
            public_key: randomized_pk,
            supports_audit: issuer_public_key.supports_audit,
            supports_revocation: issuer_public_key.supports_revocation,
        };
        Ok((
            rho,
            PublicKeyAnonymityProof {
                randomized_pk,
                proof: one_of_n_proof,
            },
        ))
    }

    /// Check if public keys are compatible - same no of msgs, revocation and audit support
    fn check_key_compat(
        decoy_public_keys: &[IssuerPublicKey<E>],
        check_audit: bool,
        check_revocation: bool,
    ) -> Result<(), DelegationError> {
        for pk in decoy_public_keys {
            CredentialShowProtocol::check_key_compat(pk, check_audit, check_revocation)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> CredentialShowWithHiddenPublicKey<E> {
    pub fn verify(
        &self,
        challenge: &E::Fr,
        disclosed_attributes: Vec<E::Fr>,
        possible_public_keys: &[IssuerPublicKey<E>],
        one_of_n_srs: &OneOfNSrs<E>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.verify_decoy_pk_proof(possible_public_keys, one_of_n_srs, set_comm_srs)?;
        self.credential_show._verify(
            challenge,
            disclosed_attributes,
            &self.pubkey_anonymity_proof.randomized_pk,
            None,
            None,
            None,
            auditor_pk,
            set_comm_srs,
        )
    }

    pub fn verify_with_revocation(
        &self,
        challenge: &E::Fr,
        disclosed_attributes: Vec<E::Fr>,
        possible_public_keys: &[IssuerPublicKey<E>],
        accumulated: &E::G1Affine,
        Q: &E::G1Affine,
        accumulator_pk: &crate::accumulator::PublicKey<E>,
        one_of_n_srs: &OneOfNSrs<E>,
        auditor_pk: Option<&AuditorPublicKey<E>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        self.verify_decoy_pk_proof(possible_public_keys, one_of_n_srs, set_comm_srs)?;
        self.credential_show._verify(
            challenge,
            disclosed_attributes,
            &self.pubkey_anonymity_proof.randomized_pk,
            Some(accumulated),
            Some(Q),
            Some(accumulator_pk),
            auditor_pk,
            set_comm_srs,
        )
    }

    fn verify_decoy_pk_proof(
        &self,
        possible_public_keys: &[IssuerPublicKey<E>],
        one_of_n_srs: &OneOfNSrs<E>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), DelegationError> {
        let ipk = &self.pubkey_anonymity_proof.randomized_pk;
        self.pubkey_anonymity_proof.proof.verify(
            possible_public_keys
                .iter()
                .map(|p| p.public_key.0.as_slice())
                .collect::<Vec<_>>(),
            &ipk.public_key.0,
            one_of_n_srs,
            set_comm_srs.get_P1(),
        )
    }

    pub fn supports_revocation(&self) -> bool {
        self.credential_show.rev.is_some()
    }

    pub fn supports_audit(&self) -> bool {
        self.credential_show.ct.is_some()
    }
}
