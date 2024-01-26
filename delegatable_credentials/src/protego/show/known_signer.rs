//! Credential show (presentation) protocol when the signer (public key) is disclosed to the verifier

use crate::{
    accumulator::{NonMembershipWitness, RandomizedNonMembershipWitness},
    error::DelegationError,
    mercurial_sig::Signature,
    protego::{
        issuance::Credential,
        keys::{IssuerPublicKey, PreparedIssuerPublicKey, UserPublicKey, UserSecretKey},
    },
    set_commitment::{PreparedSetCommitmentSRS, SetCommitment, SetCommitmentSRS, SubsetWitness},
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    io::Write,
    ops::{Add, Mul, Sub},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use dock_crypto_utils::elgamal::{Ciphertext as ElgamalCiphertext, PublicKey as AuditorPublicKey};
use schnorr_pok::discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol};

/// Proof that ciphertext is correct, i.e. it encrypts the user's public key and the auditor can decrypt it.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CiphertextProof<E: Pairing> {
    pub C6: E::G1Affine,
    pub C7: E::G1Affine,
    pub com1: E::G1Affine,
    pub z1: E::ScalarField,
    pub ciphertext_rand_proof: PokDiscreteLog<E::G1Affine>,
    pub t1: E::G2Affine,
    pub t2: E::G2Affine,
    pub t3: E::G2Affine,
}

/// Protocol to create `CiphertextProof`
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CiphertextProofProtocol<E: Pairing> {
    pub C6: E::G1Affine,
    pub C7: E::G1Affine,
    pub alpha: E::ScalarField,
    /// Encrypts the user's public key
    pub ct: ElgamalCiphertext<E::G1Affine>,
    pub r1: E::ScalarField,
    pub r2: E::ScalarField,
    pub com1: E::G1Affine,
    pub ciphertext_rand_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    pub t1: E::G2Affine,
    pub t2: E::G2Affine,
    pub t3: E::G2Affine,
}

/// Proof that the credential contains commitment to the secret key and pseudonym and also share the randomized witness and accumulator
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RevocationShow<E: Pairing> {
    pub randomized_accum: E::G1Affine,
    pub randomized_witness: RandomizedNonMembershipWitness<E>,
    pub C4: E::G1Affine,
    pub C5: E::G1Affine,
    pub accum_rand_proof: PokDiscreteLog<E::G1Affine>,
    pub user_rev_secret_proof: PokDiscreteLog<E::G1Affine>,
    pub witness_rand_proof: PokDiscreteLog<E::G1Affine>,
}

/// Protocol to create `RevocationShow`
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RevocationShowProtocol<E: Pairing> {
    pub randomized_accum: E::G1Affine,
    pub randomized_witness: RandomizedNonMembershipWitness<E>,
    pub C4: E::G1Affine,
    pub C5: E::G1Affine,
    pub accum_rand_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    pub user_rev_secret_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    pub witness_rand_protocol: PokDiscreteLogProtocol<E::G1Affine>,
}

/// Protocol for creating `CoreCredentialShow`
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CoreCredentialShowProtocol<E: Pairing> {
    pub C1: E::G1Affine,
    pub C2: E::G1Affine,
    pub C3: E::G1Affine,
    pub signature: Signature<E>,
    pub attrib_comm_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    pub attrib_comm_rand_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    /// Present if any attributes are revealed.
    pub disclosed_attributes_witness: Option<SubsetWitness<E>>,
}

/// Credential show that convinces the verifier that the user has a signature from the
/// issuer on some attributes and optionally disclosing some of those attributes
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CoreCredentialShow<E: Pairing> {
    pub C1: E::G1Affine,
    pub C2: E::G1Affine,
    pub C3: E::G1Affine,
    pub signature: Signature<E>,
    pub attrib_comm_proof: PokDiscreteLog<E::G1Affine>,
    pub attrib_comm_rand_proof: PokDiscreteLog<E::G1Affine>,
    pub disclosed_attributes_witness: Option<SubsetWitness<E>>,
}

/// Protocol to show a credential which is optionally revocable and auditable
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShowProtocol<E: Pairing> {
    pub core: CoreCredentialShowProtocol<E>,
    pub rev: Option<RevocationShowProtocol<E>>,
    pub ct: Option<CiphertextProofProtocol<E>>,
}

/// Credential show including the core (mandatory) part and optional revocation and audit
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialShow<E: Pairing> {
    pub core: CoreCredentialShow<E>,
    pub rev: Option<RevocationShow<E>>,
    pub ct_proof: Option<CiphertextProof<E>>,
    /// The ciphertext encrypting the user key which can be given to the auditor to decrypt
    pub ct: Option<ElgamalCiphertext<E::G1Affine>>,
}

impl<E: Pairing> CredentialShowProtocol<E> {
    /// `user_pk` and `auditor_pk` must not be None if the credential is auditable.
    pub fn init<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::ScalarField>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        Self::_init(
            rng,
            credential,
            disclosed_attributes,
            None,
            None,
            None,
            None,
            user_pk,
            auditor_pk,
            None,
            set_comm_srs,
        )
    }

    /// Initialize the protocol when the credential is revocable. `user_pk` and `auditor_pk` must not be None if the credential is auditable.
    pub fn init_with_revocation<R: RngCore>(
        rng: &mut R,
        credential: Credential<E>,
        disclosed_attributes: Vec<E::ScalarField>,
        accumulated: &E::G1Affine,
        non_mem_wit: &NonMembershipWitness<E>,
        user_sk: &UserSecretKey<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        Q: &E::G1Affine,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        Self::_init(
            rng,
            credential,
            disclosed_attributes,
            None,
            Some(accumulated),
            Some(non_mem_wit),
            Some(user_sk),
            user_pk,
            auditor_pk,
            Some(Q),
            set_comm_srs,
        )
    }

    pub(super) fn _init<R: RngCore>(
        rng: &mut R,
        mut credential: Credential<E>,
        disclosed_attributes: Vec<E::ScalarField>,
        sig_converter: Option<&E::ScalarField>,
        accumulated: Option<&E::G1Affine>,
        non_mem_wit: Option<&NonMembershipWitness<E>>,
        user_sk: Option<&UserSecretKey<E>>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        Q: Option<&E::G1Affine>,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, DelegationError> {
        let P1 = set_comm_srs.get_P1();
        let P2 = set_comm_srs.get_P2();

        // TODO: Optimize with P1 and P2 tables

        let mut C = vec![
            credential.C1,
            credential
                .C1
                .mul_bigint(credential.opening.r4.into_bigint())
                .into_affine(),
            *P1,
        ];

        if let Some(rev) = &credential.rev {
            C.push(rev.C4);
            C.push(rev.C5);
        }

        if credential.auditable_sig {
            let upk = user_pk.ok_or(DelegationError::NeedUserPublicKey)?.0;
            let apk = auditor_pk.ok_or(DelegationError::NeedAuditorPublicKey)?.0;
            C.push(upk);
            C.push(apk);
        }

        let mu = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);

        // Randomizes the commitments `C1`, `C2`, .. using `mu`
        let (signature, C_prime) = if let Some(sig_c) = sig_converter {
            // If `sig_converter` is provided, randomize the signature as well using `mu`. This is needed when the public key of
            // the issuer is being hidden through some means. `sig_converter` will also be used to randomize the public key
            credential
                .signature
                .change_rep_with_given_sig_converter(rng, &mu, sig_c, &C)
        } else {
            credential.signature.change_rep(rng, &mu, &C)
        };
        credential.opening.set_comm_opening.randomize(mu);

        let subset_witness = if disclosed_attributes.is_empty() {
            None
        } else {
            // TODO: Needs refactoring
            let comm = SetCommitment(C_prime[0]);
            let subset = disclosed_attributes.iter().copied().collect();
            let set = credential.attributes.iter().copied().collect();
            // Expect the caller to pass valid subset and the correct opening
            Some(comm.open_subset_unchecked(
                &credential.opening.set_comm_opening,
                subset,
                set,
                set_comm_srs,
            )?)
        };

        let attrib_comm_protocol =
            PokDiscreteLogProtocol::init(credential.opening.r4, r1, &C_prime[0]);
        let attrib_comm_rand_protocol = PokDiscreteLogProtocol::init(mu, r2, P1);

        let rev = if credential.supports_revocation() {
            let r3 = E::ScalarField::rand(rng);
            let r4 = E::ScalarField::rand(rng);
            let r5 = E::ScalarField::rand(rng);
            let tau = E::ScalarField::rand(rng);
            let Q = Q.ok_or(DelegationError::AccumulatorPublicParamsNotProvided)?;
            let accum = accumulated.ok_or(DelegationError::NeedAccumulator)?;
            let wit = non_mem_wit.ok_or(DelegationError::NeedWitness)?;
            let usk_2 = user_sk
                .and_then(|u| u.1)
                .ok_or(DelegationError::NeedUserSecretKey)?;

            let r = mu * tau * usk_2;

            // randomized_accum = accum * mu * tau * usk_2
            let randomized_accum = accum.mul_bigint(r.into_bigint()).into_affine();
            let randomized_d = wit.1 * r;
            let randomized_witness = RandomizedNonMembershipWitness(
                wit.0.mul_bigint(tau.into_bigint()).into_affine(),
                P1.mul_bigint(randomized_d.into_bigint()).into_affine(),
            );

            let accum_rand_protocol = PokDiscreteLogProtocol::init(r, r3, accum);
            let user_rev_secret_protocol = PokDiscreteLogProtocol::init(usk_2 * mu, r4, Q);
            let witness_rand_protocol = PokDiscreteLogProtocol::init(randomized_d, r5, P1);

            Some(RevocationShowProtocol {
                randomized_accum,
                randomized_witness,
                C4: C_prime[3],
                C5: C_prime[4],
                accum_rand_protocol,
                user_rev_secret_protocol,
                witness_rand_protocol,
            })
        } else {
            None
        };

        let ct_proof_proto = if credential.auditable_sig {
            let r1 = E::ScalarField::rand(rng);
            let r2 = E::ScalarField::rand(rng);
            let beta = E::ScalarField::rand(rng);

            let upk = user_pk.ok_or(DelegationError::NeedUserPublicKey)?;
            let apk = auditor_pk.ok_or(DelegationError::NeedAuditorPublicKey)?;

            let (ct, alpha) = ElgamalCiphertext::<E::G1Affine>::new(rng, &upk.0, &apk.0, P1);

            let com1 = P1.mul(r1).add(&apk.0.mul(r2)).into_affine();
            let ciphertext_rand_protocol = PokDiscreteLogProtocol::init(alpha, r2, P1);

            let t1 = P2.mul(beta).into_affine();
            let t2 = P2.mul(beta * mu).into_affine();
            let t3 = P2.mul(beta * alpha).into_affine();

            Some(CiphertextProofProtocol {
                C6: C_prime[C_prime.len() - 2],
                C7: C_prime[C_prime.len() - 1],
                alpha,
                ct,
                r1,
                r2,
                com1,
                ciphertext_rand_protocol,
                t1,
                t2,
                t3,
            })
        } else {
            None
        };

        Ok(Self {
            core: CoreCredentialShowProtocol {
                C1: C_prime[0],
                C2: C_prime[1],
                C3: C_prime[2],
                signature,
                attrib_comm_protocol,
                attrib_comm_rand_protocol,
                disclosed_attributes_witness: subset_witness,
            },
            rev,
            ct: ct_proof_proto,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulated: Option<&E::G1Affine>,
        Q: Option<&E::G1Affine>,
        apk: Option<&AuditorPublicKey<E::G1Affine>>,
        P1: &E::G1Affine,
        context: &[u8],
        mut writer: W,
    ) -> Result<(), DelegationError> {
        writer.write(context).unwrap();
        self.core.attrib_comm_protocol.challenge_contribution(
            &self.core.C1,
            &self.core.C2,
            &mut writer,
        )?;
        self.core.attrib_comm_rand_protocol.challenge_contribution(
            P1,
            &self.core.C3,
            &mut writer,
        )?;
        if let Some(rev) = &self.rev {
            rev.accum_rand_protocol.challenge_contribution(
                accumulated.unwrap(),
                &rev.randomized_accum,
                &mut writer,
            )?;
            rev.user_rev_secret_protocol.challenge_contribution(
                Q.unwrap(),
                &rev.C5,
                &mut writer,
            )?;
            rev.witness_rand_protocol.challenge_contribution(
                P1,
                &rev.randomized_witness.1,
                &mut writer,
            )?;
        }

        if let Some(ct) = &self.ct {
            P1.serialize_compressed(&mut writer)?;
            apk.unwrap().serialize_compressed(&mut writer)?;
            ct.ct.enc1.serialize_compressed(&mut writer)?;
            ct.com1.serialize_compressed(&mut writer)?;
            ct.ciphertext_rand_protocol
                .challenge_contribution(P1, &ct.ct.enc2, &mut writer)?;
        }
        Ok(())
    }

    pub fn gen_show(
        self,
        user_secret_key: Option<&UserSecretKey<E>>,
        challenge: &E::ScalarField,
    ) -> Result<CredentialShow<E>, DelegationError> {
        let rev = match self.rev {
            Some(rev) => Some(RevocationShow {
                randomized_accum: rev.randomized_accum,
                randomized_witness: rev.randomized_witness,
                C4: rev.C4,
                C5: rev.C5,
                accum_rand_proof: rev.accum_rand_protocol.gen_proof(challenge),
                user_rev_secret_proof: rev.user_rev_secret_protocol.gen_proof(challenge),
                witness_rand_proof: rev.witness_rand_protocol.gen_proof(challenge),
            }),
            _ => None,
        };

        let (ct, ct_proof) = match self.ct {
            Some(ct_proto) => {
                let z1 = ct_proto.r1
                    + (user_secret_key.ok_or(DelegationError::NeedUserSecretKey)?.0 * challenge);
                let ciphertext_rand_proof = ct_proto.ciphertext_rand_protocol.gen_proof(challenge);
                (
                    Some(ct_proto.ct),
                    Some(CiphertextProof {
                        C6: ct_proto.C6,
                        C7: ct_proto.C7,
                        com1: ct_proto.com1,
                        z1,
                        ciphertext_rand_proof,
                        t1: ct_proto.t1,
                        t2: ct_proto.t2,
                        t3: ct_proto.t3,
                    }),
                )
            }
            _ => (None, None),
        };
        Ok(CredentialShow {
            core: CoreCredentialShow {
                C1: self.core.C1,
                C2: self.core.C2,
                C3: self.core.C3,
                signature: self.core.signature,
                attrib_comm_proof: self.core.attrib_comm_protocol.gen_proof(challenge),
                attrib_comm_rand_proof: self.core.attrib_comm_rand_protocol.gen_proof(challenge),
                disclosed_attributes_witness: self.core.disclosed_attributes_witness,
            },
            rev,
            ct,
            ct_proof,
        })
    }

    /// Check if public keys are compatible - same no of msgs, revocation and audit support
    pub(super) fn check_key_compat(
        issuer_public_key: &IssuerPublicKey<E>,
        check_audit: bool,
        check_revocation: bool,
    ) -> Result<(), DelegationError> {
        if check_audit && !issuer_public_key.supports_audit {
            return Err(DelegationError::IncompatiblePublicKey);
        }
        if check_revocation && !issuer_public_key.supports_revocation {
            return Err(DelegationError::IncompatiblePublicKey);
        }
        Ok(())
    }
}

impl<E: Pairing> CredentialShow<E> {
    pub fn verify(
        &self,
        challenge: &E::ScalarField,
        disclosed_attributes: Vec<E::ScalarField>,
        issuer_pk: impl Into<PreparedIssuerPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        self._verify(
            challenge,
            disclosed_attributes,
            issuer_pk,
            None,
            None,
            None::<crate::accumulator::PreparedPublicKey<E>>,
            auditor_pk,
            set_comm_srs,
        )
    }

    pub fn verify_with_revocation(
        &self,
        challenge: &E::ScalarField,
        disclosed_attributes: Vec<E::ScalarField>,
        issuer_pk: impl Into<PreparedIssuerPublicKey<E>>,
        accumulated: &E::G1Affine,
        Q: &E::G1Affine,
        accumulator_pk: impl Into<crate::accumulator::PreparedPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        self._verify(
            challenge,
            disclosed_attributes,
            issuer_pk,
            Some(accumulated),
            Some(Q),
            Some(accumulator_pk),
            auditor_pk,
            set_comm_srs,
        )
    }

    pub fn _verify(
        &self,
        challenge: &E::ScalarField,
        disclosed_attributes: Vec<E::ScalarField>,
        issuer_pk: impl Into<PreparedIssuerPublicKey<E>>,
        accumulated: Option<&E::G1Affine>,
        Q: Option<&E::G1Affine>,
        accumulator_pk: Option<impl Into<crate::accumulator::PreparedPublicKey<E>>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        let set_comm_srs = set_comm_srs.into();
        let P1 = set_comm_srs.get_P1();
        let prep_P2 = set_comm_srs.prepared_P2.clone();

        if !self
            .core
            .attrib_comm_proof
            .verify(&self.core.C2, &self.core.C1, challenge)
        {
            return Err(DelegationError::InvalidCredentialShow);
        }
        if !self
            .core
            .attrib_comm_rand_proof
            .verify(&self.core.C3, P1, challenge)
        {
            return Err(DelegationError::InvalidCredentialShow);
        }

        if !disclosed_attributes.is_empty() {
            let ss = disclosed_attributes.into_iter().collect();
            let comm = SetCommitment(self.core.C1);
            self.core
                .disclosed_attributes_witness
                .as_ref()
                .ok_or(DelegationError::InvalidCredentialShow)?
                .verify(ss, &comm, &set_comm_srs)?;
        }

        let mut C = vec![self.core.C1, self.core.C2, self.core.C3];

        if let Some(rev) = &self.rev {
            C.push(rev.C4);
            C.push(rev.C5);
        }

        if let Some(ct) = &self.ct_proof {
            C.push(ct.C6);
            C.push(ct.C7);
        }

        self.core
            .signature
            .verify(&C, issuer_pk.into().public_key, P1, prep_P2.clone())?;

        // If the show supports revocation
        match &self.rev {
            Some(rev) => {
                let Q = Q.ok_or(DelegationError::AccumulatorPublicParamsNotProvided)?;
                let accumulator_pk = accumulator_pk
                    .ok_or(DelegationError::AccumulatorPublicKeyNotProvided)?
                    .into();
                let accumulated = accumulated.ok_or(DelegationError::AccumulatorNotProvided)?;

                if !rev
                    .accum_rand_proof
                    .verify(&rev.randomized_accum, accumulated, challenge)
                {
                    return Err(DelegationError::InvalidRevocationShow);
                }

                if !rev.user_rev_secret_proof.verify(&rev.C5, Q, challenge) {
                    return Err(DelegationError::InvalidRevocationShow);
                }

                if !rev
                    .witness_rand_proof
                    .verify(&rev.randomized_witness.1, P1, challenge)
                {
                    return Err(DelegationError::InvalidRevocationShow);
                }

                if !rev.randomized_witness.verify(
                    &rev.randomized_accum,
                    &rev.C4,
                    accumulator_pk,
                    prep_P2,
                ) {
                    return Err(DelegationError::InvalidRevocationShow);
                }
            }
            _ => (),
        }
        match (&self.ct, &self.ct_proof) {
            (Some(ct), Some(ct_proof)) => {
                let apk = auditor_pk.ok_or(DelegationError::NeedAuditorPublicKey)?;

                if P1
                    .mul(ct_proof.z1)
                    .add(&apk.0.mul(ct_proof.ciphertext_rand_proof.response))
                    .sub(ct.enc1.mul_bigint(challenge.into_bigint()))
                    .into_affine()
                    != ct_proof.com1
                {
                    return Err(DelegationError::InvalidAuditShow);
                }

                if !ct_proof
                    .ciphertext_rand_proof
                    .verify(&ct.enc2, P1, challenge)
                {
                    return Err(DelegationError::InvalidAuditShow);
                }

                let t1_prep = E::G2Prepared::from(ct_proof.t1);
                let t2_prep = E::G2Prepared::from(ct_proof.t2);
                let t3_prep = E::G2Prepared::from(ct_proof.t3);

                if !E::multi_pairing(
                    [ct.enc2, (-P1.into_group()).into_affine()],
                    [t1_prep.clone(), t3_prep.clone()],
                )
                .is_zero()
                {
                    return Err(DelegationError::InvalidAuditShow);
                }
                if !E::multi_pairing(
                    [ct.enc2, (-self.core.C3.into_group()).into_affine()],
                    [t2_prep.clone(), t3_prep.clone()],
                )
                .is_zero()
                {
                    return Err(DelegationError::InvalidAuditShow);
                }
                if !E::multi_pairing(
                    [
                        (-ct.enc1.into_group()).into_affine(),
                        ct_proof.C6,
                        ct_proof.C7,
                    ],
                    [t2_prep, t1_prep, t3_prep],
                )
                .is_zero()
                {
                    return Err(DelegationError::InvalidAuditShow);
                }
            }
            _ => (),
        }

        Ok(())
    }

    pub fn supports_revocation(&self) -> bool {
        self.rev.is_some()
    }

    pub fn supports_audit(&self) -> bool {
        self.ct.is_some()
    }
}
