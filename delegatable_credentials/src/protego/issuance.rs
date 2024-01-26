//! Credential issuance as described in Fig 2 of the Protego paper. The user creates a
//! `SignatureRequest` in the Obtain phase of the protocol and sends it to the issuer which sends a signature
//! on the successful verification of the request. The user uses this signature and the original request to
//! create a credential

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use dock_crypto_utils::{elgamal::PublicKey as AuditorPublicKey, msm::WindowTable};

use schnorr_pok::discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol};

use crate::{
    error::DelegationError,
    mercurial_sig::Signature,
    protego::keys::{IssuerSecretKey, PreparedIssuerPublicKey, UserPublicKey, UserSecretKey},
    set_commitment::{
        PreparedSetCommitmentSRS, SetCommitment, SetCommitmentOpening, SetCommitmentSRS,
    },
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RevocationRequestProtocol<E: Pairing> {
    /// Schnorr protocol to prove knowledge of revocation secret key
    pub usk_rev_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    /// Schnorr protocol to prove knowledge of revocation secret key with base Q
    pub usk_rev_protocol_Q: PokDiscreteLogProtocol<E::G1Affine>,
    pub C4: E::G1Affine,
    pub C5: E::G1Affine,
    pub nym: E::ScalarField,
}

/// Part of signature request corresponding to revocation
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RevocationRequest<E: Pairing> {
    pub C4: E::G1Affine,
    pub C5: E::G1Affine,
    pub nym: E::ScalarField,
    /// Schnorr proof to prove knowledge of revocation secret key
    pub usk_rev_proof: PokDiscreteLog<E::G1Affine>,
    /// Schnorr proof to prove knowledge of revocation secret key with base Q
    pub usk_rev_proof_Q: PokDiscreteLog<E::G1Affine>,
}

/// Part of credential corresponding to revocation
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RevocationCredential<E: Pairing> {
    pub C4: E::G1Affine,
    pub C5: E::G1Affine,
    pub nym: E::ScalarField,
}

/// Protocol to request a signature from an issuer which will then be part of a credential.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureRequestProtocol<E: Pairing> {
    /// Schnorr protocol to prove knowledge of secret key
    pub usk_protocol: PokDiscreteLogProtocol<E::G1Affine>,
    pub rev: Option<RevocationRequestProtocol<E>>,
    /// Whether requesting an auditable signature, i.e. signer signs user's public key
    pub auditable_sig: bool,
}

/// A request to obtain a signature from a credential issuer.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureRequest<E: Pairing> {
    /// Commitment to all attributes
    pub C1: E::G1Affine,
    /// Randomized C1
    pub C2: E::G1Affine,
    /// Schnorr proof to prove knowledge of secret key
    pub usk_proof: PokDiscreteLog<E::G1Affine>,
    /// Only present when the signer is issuing a revocable credential
    pub rev: Option<RevocationRequest<E>>,
    /// Whether requesting an auditable signature, i.e. signer signs user's public key
    pub auditable_sig: bool,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureRequestOpening<E: Pairing> {
    pub r4: E::ScalarField,
    /// Opening to the commitment C1
    pub set_comm_opening: SetCommitmentOpening<E>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Credential<E: Pairing> {
    pub attributes: Vec<E::ScalarField>,
    /// Commitment to the attributes
    pub C1: E::G1Affine,
    pub opening: SignatureRequestOpening<E>,
    pub signature: Signature<E>,
    /// Only present when the credential is revocable
    pub rev: Option<RevocationCredential<E>>,
    /// Whether the signature is auditable, i.e. signer signs user's public key
    pub auditable_sig: bool,
}

impl<E: Pairing> SignatureRequestProtocol<E> {
    /// Initialize protocol for creating a signature request. The signature won't support revocation
    pub fn init<R: RngCore>(
        rng: &mut R,
        user_sk: &UserSecretKey<E>,
        auditable_sig: bool,
        P1: &E::G1Affine,
    ) -> Self {
        let r1 = E::ScalarField::rand(rng);
        Self {
            usk_protocol: PokDiscreteLogProtocol::init(user_sk.0, r1, P1),
            rev: None,
            auditable_sig,
        }
    }

    /// Initialize protocol for creating a signature request where the signature supports revocation
    pub fn init_with_revocation<R: RngCore>(
        rng: &mut R,
        nym: E::ScalarField,
        user_sk: &UserSecretKey<E>,
        auditable_sig: bool,
        P1: &E::G1Affine,
        s_P1: &E::G1Affine,
        Q: &E::G1Affine,
    ) -> Result<Self, DelegationError> {
        let usk2 = user_sk
            .1
            .ok_or_else(|| DelegationError::KeyDoesNotSupportRevocation)?;
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        // C4 = P1*usk2*(s - nym) where s is the trapdoor of the set commitment SRS
        let mut C4 = P1.mul_bigint(nym.into_bigint()).neg();
        C4 += s_P1;
        C4 *= usk2;
        Ok(Self {
            usk_protocol: PokDiscreteLogProtocol::init(user_sk.0, r1, P1),
            rev: Some(RevocationRequestProtocol {
                // Note: This deviates from the paper which uses a different `r3` as blinding for
                // `usk_rev_protocol_Q` but since it should be proven that same usk2 is the witness in
                // both `usk_rev_protocol` and `usk_rev_protocol_Q`, same blinding is used.
                usk_rev_protocol: PokDiscreteLogProtocol::init(usk2, r2, P1),
                usk_rev_protocol_Q: PokDiscreteLogProtocol::init(usk2, r2, Q),
                C4: C4.into_affine(),
                // C5 = usk2*Q
                C5: Q.mul_bigint(usk2.into_bigint()).into_affine(),
                nym,
            }),
            auditable_sig,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        user_pk: &UserPublicKey<E>,
        P1: &E::G1Affine,
        Q: Option<&E::G1Affine>,
        mut writer: W,
    ) -> Result<(), DelegationError> {
        Self::compute_challenge_contribution(
            self.auditable_sig,
            &self.usk_protocol,
            user_pk,
            P1,
            &mut writer,
        )?;
        if let Some(rev) = self.rev.as_ref() {
            let Q = Q.ok_or_else(|| DelegationError::AccumulatorPublicParamsNotProvided)?;
            Self::compute_challenge_contribution_for_revocable(
                &rev.usk_rev_protocol,
                &rev.usk_rev_protocol_Q,
                user_pk,
                &rev.C5,
                P1,
                Q,
                &mut writer,
            )?;
        }
        Ok(())
    }

    pub fn compute_challenge_contribution<W: Write>(
        auditable_sig: bool,
        usk_protocol: &PokDiscreteLogProtocol<E::G1Affine>,
        user_pk: &UserPublicKey<E>,
        P1: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), DelegationError> {
        auditable_sig.serialize_compressed(&mut writer)?;
        usk_protocol
            .challenge_contribution(P1, &user_pk.0, &mut writer)
            .map_err(|e| e.into())
    }

    pub fn compute_challenge_contribution_for_revocable<W: Write>(
        usk_rev_protocol: &PokDiscreteLogProtocol<E::G1Affine>,
        usk_rev_protocol2: &PokDiscreteLogProtocol<E::G1Affine>,
        user_pk: &UserPublicKey<E>,
        C5: &E::G1Affine,
        P1: &E::G1Affine,
        Q: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), DelegationError> {
        let upk_rev = user_pk
            .1
            .ok_or_else(|| DelegationError::KeyDoesNotSupportRevocation)?;
        usk_rev_protocol.challenge_contribution(P1, &upk_rev, &mut writer)?;
        usk_rev_protocol2
            .challenge_contribution(Q, C5, &mut writer)
            .map_err(|e| e.into())
    }

    /// Creates a signature request by committing the attributes in a set commitment and then signing that
    /// commitment along with other values. The attributes are expected to be unique as the are committed
    /// using a set commitment scheme. One approach is to encode attributes as pairs with 1st element of the
    /// pair as an index and the 2nd element as the actual attribute value like `(0, attribute[0]), (1, attribute[1]), (2, attribute[2]), (n, attribute[n])`
    pub fn gen_request<R: RngCore>(
        self,
        rng: &mut R,
        attributes: Vec<E::ScalarField>,
        user_sk: &UserSecretKey<E>,
        challenge: &E::ScalarField,
        set_comm_srs: &SetCommitmentSRS<E>,
    ) -> Result<(SignatureRequest<E>, SignatureRequestOpening<E>), DelegationError> {
        if attributes.len() > set_comm_srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                attributes.len(),
                set_comm_srs.size(),
            ));
        }
        let attr_set = attributes.into_iter().collect();
        let r4 = E::ScalarField::rand(rng);

        let (comm, opening) =
            SetCommitment::new_with_given_randomness(user_sk.0, attr_set, set_comm_srs)?;
        let C2 = comm.0.mul_bigint(r4.into_bigint()).into_affine();
        let req = SignatureRequest {
            C1: comm.0,
            C2,
            usk_proof: self.usk_protocol.gen_proof(challenge),
            rev: self.rev.map(|rev| RevocationRequest {
                C4: rev.C4,
                C5: rev.C5,
                nym: rev.nym,
                usk_rev_proof: rev.usk_rev_protocol.gen_proof(challenge),
                usk_rev_proof_Q: rev.usk_rev_protocol_Q.gen_proof(challenge),
            }),
            auditable_sig: self.auditable_sig,
        };
        Ok((
            req,
            SignatureRequestOpening {
                r4,
                set_comm_opening: opening,
            },
        ))
    }
}

impl<E: Pairing> SignatureRequest<E> {
    /// Signer verifies the signature request before creating a signature
    pub fn verify(
        &self,
        attributes: Vec<E::ScalarField>,
        user_public_key: &UserPublicKey<E>,
        challenge: &E::ScalarField,
        Q: Option<&E::G1Affine>,
        s_P2_from_accumulator: Option<&E::G2Affine>,
        set_comm_srs: impl Into<PreparedSetCommitmentSRS<E>>,
    ) -> Result<(), DelegationError> {
        let set_comm_srs = set_comm_srs.into();

        if attributes.len() > set_comm_srs.size() {
            return Err(DelegationError::InsufficientSetCommitmentSRSSize(
                attributes.len(),
                set_comm_srs.size(),
            ));
        }

        let P1_table = WindowTable::new(attributes.len(), set_comm_srs.get_P1().into_group());
        let s_P1 = set_comm_srs.get_s_P1().into_group();
        for s in attributes.iter() {
            if P1_table.multiply(s) == s_P1 {
                return Err(DelegationError::ShouldNotContainTrapdoor);
            }
        }

        let upk = &user_public_key.0;
        let prep_P2 = set_comm_srs.prepared_P2.clone();

        let attr_set = attributes.into_iter().collect();
        let e = E::G2Prepared::from(set_comm_srs.eval_P2(attr_set));
        // Check if `e(C1, P2) == (upk, Ch(attr_set)*P2)`
        if !E::multi_pairing(
            [self.C1, (-upk.into_group()).into_affine()],
            [prep_P2.clone(), e],
        )
        .is_zero()
        {
            return Err(DelegationError::InvalidSignatureRequest);
        }

        // Check if `upk == P1*usk`
        if !self.usk_proof.verify(upk, set_comm_srs.get_P1(), challenge) {
            return Err(DelegationError::InvalidSignatureRequest);
        }

        // For revocation
        if self.supports_revocation() {
            let rev = self.rev.as_ref().unwrap();
            let Q = Q.ok_or_else(|| DelegationError::AccumulatorPublicParamsNotProvided)?;
            let s_P2 = s_P2_from_accumulator
                .ok_or_else(|| DelegationError::AccumulatorPublicParamsNotProvided)?;
            let upk2 = user_public_key
                .1
                .ok_or_else(|| DelegationError::KeyDoesNotSupportRevocation)?;
            // e2 = P2 * (s - nym)
            let P2_nym = set_comm_srs
                .get_P2()
                .mul_bigint(rev.nym.into_bigint())
                .neg();
            let e2 = E::G2Prepared::from(P2_nym + s_P2);
            // Check if e(C4, P2) == (upk2, P2 * (s - nym)) => e(C4, P2) * (-upk2, P2 * (s - nym)) == 1
            if !E::multi_pairing([rev.C4, (-upk2.into_group()).into_affine()], [prep_P2, e2])
                .is_zero()
            {
                return Err(DelegationError::InvalidRevocationRequest);
            }

            // Check if `upk2 == P1*usk`
            if !rev
                .usk_rev_proof
                .verify(&upk2, set_comm_srs.get_P1(), challenge)
            {
                return Err(DelegationError::InvalidRevocationRequest);
            }

            // Check if `C5 == Q*usk`
            if !rev.usk_rev_proof_Q.verify(&rev.C5, Q, challenge) {
                return Err(DelegationError::InvalidRevocationRequest);
            }

            // Check if response is same in both Schnorr proofs to ensure same witness (secret key)
            if rev.usk_rev_proof.response != rev.usk_rev_proof_Q.response {
                return Err(DelegationError::InvalidRevocationRequest);
            }
        }

        Ok(())
    }

    /// After verifying the signature request, signer creates a signature using the request
    pub fn sign<R: RngCore>(
        self,
        rng: &mut R,
        issuer_sk: &IssuerSecretKey<E>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        P1: &E::G1Affine,
        P2: &E::G2Affine,
    ) -> Result<Signature<E>, DelegationError> {
        if self.auditable_sig & !issuer_sk.supports_audit {
            return Err(DelegationError::IssuerKeyDoesNotSupportAuditableSignature);
        }
        let messages = self.create_msgs(user_pk, auditor_pk, *P1)?;
        Signature::new(rng, &messages, &issuer_sk.secret_key, P1, P2)
    }

    /// Prepare messages (commitments) to sign
    pub fn create_msgs(
        self,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        P1: E::G1Affine,
    ) -> Result<Vec<E::G1Affine>, DelegationError> {
        let mut messages = vec![];
        messages.push(self.C1);
        messages.push(self.C2);
        messages.push(P1);
        if let Some(rev) = self.rev {
            messages.push(rev.C4);
            messages.push(rev.C5);
        }
        if self.auditable_sig {
            let upk = user_pk
                .map(|pk| pk.0)
                .ok_or(DelegationError::NeedUserPublicKey)?;
            messages.push(upk);
            let apk = auditor_pk
                .map(|pk| pk.0)
                .ok_or(DelegationError::NeedAuditorPublicKey)?;
            messages.push(apk);
        }
        Ok(messages)
    }

    pub fn supports_revocation(&self) -> bool {
        self.rev.is_some()
    }
}

impl<E: Pairing> Credential<E> {
    /// Create a new credential using the created signature request and the received signature. It will
    /// verify the signature before creating the credential.
    pub fn new(
        sig_req: SignatureRequest<E>,
        sig_req_opn: SignatureRequestOpening<E>,
        sig: Signature<E>,
        attributes: Vec<E::ScalarField>,
        issuer_pk: impl Into<PreparedIssuerPublicKey<E>>,
        user_pk: Option<&UserPublicKey<E>>,
        auditor_pk: Option<&AuditorPublicKey<E::G1Affine>>,
        P1: &E::G1Affine,
        P2: impl Into<E::G2Prepared>,
    ) -> Result<Self, DelegationError> {
        let C1 = sig_req.C1;
        let rev = sig_req.rev.as_ref().map(|rev| RevocationCredential {
            C4: rev.C4,
            C5: rev.C5,
            nym: rev.nym,
        });
        let auditable_sig = sig_req.auditable_sig;

        let msgs = sig_req.create_msgs(user_pk, auditor_pk, *P1)?;
        sig.verify(&msgs, issuer_pk.into().public_key, P1, P2.into())?;
        Ok(Self {
            attributes,
            C1,
            rev,
            opening: sig_req_opn,
            signature: sig,
            auditable_sig,
        })
    }

    pub fn supports_revocation(&self) -> bool {
        self.rev.is_some()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;

    use crate::protego::keys::IssuerPublicKey;
    use dock_crypto_utils::elgamal::SecretKey as AuditorSecretKey;
    use schnorr_pok::compute_random_oracle_challenge;

    pub fn keygen(
        rng: &mut StdRng,
        auditable: bool,
        supports_revocation: bool,
        set_comm_srs: &SetCommitmentSRS<Bls12_381>,
    ) -> (
        AuditorSecretKey<Fr>,
        AuditorPublicKey<G1Affine>,
        IssuerSecretKey<Bls12_381>,
        IssuerPublicKey<Bls12_381>,
        UserSecretKey<Bls12_381>,
        UserPublicKey<Bls12_381>,
    ) {
        let ask = AuditorSecretKey::new(rng);
        let apk = AuditorPublicKey::new(&ask, set_comm_srs.get_P1());

        let isk = IssuerSecretKey::<Bls12_381>::new::<StdRng>(rng, supports_revocation, auditable)
            .unwrap();
        let ipk = IssuerPublicKey::new(&isk, set_comm_srs.get_P2());

        let usk = UserSecretKey::new(rng, supports_revocation);
        let upk = UserPublicKey::new(&usk, set_comm_srs.get_P1());

        (ask, apk, isk, ipk, usk, upk)
    }

    pub fn setup(
        rng: &mut StdRng,
        max_attributes: u32,
        auditable: bool,
        supports_revocation: bool,
    ) -> (
        SetCommitmentSRS<Bls12_381>,
        Fr,
        AuditorSecretKey<Fr>,
        AuditorPublicKey<G1Affine>,
        IssuerSecretKey<Bls12_381>,
        IssuerPublicKey<Bls12_381>,
        UserSecretKey<Bls12_381>,
        UserPublicKey<Bls12_381>,
    ) {
        let (set_comm_srs, trapdoor) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(rng, max_attributes, Some("Protego".as_bytes()));
        let (ask, apk, isk, ipk, usk, upk) =
            keygen(rng, auditable, supports_revocation, &set_comm_srs);
        (set_comm_srs, trapdoor, ask, apk, isk, ipk, usk, upk)
    }

    pub fn issuance(
        rng: &mut StdRng,
        max_attributes: u32,
        attributes: Vec<Fr>,
        auditable: bool,
        Q: Option<&G1Affine>,
        nym: Option<&Fr>,
        s_P1_from_accumulator: Option<&G1Affine>,
        s_P2_from_accumulator: Option<&G2Affine>,
    ) -> Credential<Bls12_381> {
        assert!((Q.is_some() && nym.is_some()) || (Q.is_none() && nym.is_none()));
        let supports_revocation = Q.is_some() && nym.is_some();
        let (set_comm_srs, _, _, apk, isk, ipk, usk, upk) =
            setup(rng, max_attributes, auditable, supports_revocation);
        issuance_given_setup(
            rng,
            attributes,
            auditable,
            &apk,
            &isk,
            &ipk,
            &usk,
            &upk,
            Q,
            nym,
            s_P1_from_accumulator,
            s_P2_from_accumulator,
            &set_comm_srs,
        )
    }

    pub fn issuance_given_setup(
        rng: &mut StdRng,
        attributes: Vec<Fr>,
        auditable: bool,
        apk: &AuditorPublicKey<G1Affine>,
        isk: &IssuerSecretKey<Bls12_381>,
        ipk: &IssuerPublicKey<Bls12_381>,
        usk: &UserSecretKey<Bls12_381>,
        upk: &UserPublicKey<Bls12_381>,
        Q: Option<&G1Affine>,
        nym: Option<&Fr>,
        s_P1_from_accumulator: Option<&G1Affine>,
        s_P2_from_accumulator: Option<&G2Affine>,
        set_comm_srs: &SetCommitmentSRS<Bls12_381>,
    ) -> Credential<Bls12_381> {
        assert!((Q.is_some() && nym.is_some()) || (Q.is_none() && nym.is_none()));
        let supports_revocation = Q.is_some() && nym.is_some();

        let prep_set_comm_srs = PreparedSetCommitmentSRS::from(set_comm_srs.clone());
        let prep_ipk = PreparedIssuerPublicKey::from(ipk.clone());

        let sig_req_p = if supports_revocation {
            SignatureRequestProtocol::init_with_revocation(
                rng,
                *(nym.unwrap()),
                usk,
                auditable,
                set_comm_srs.get_P1(),
                s_P1_from_accumulator.unwrap(),
                Q.unwrap(),
            )
            .unwrap()
        } else {
            SignatureRequestProtocol::init(rng, usk, auditable, set_comm_srs.get_P1())
        };

        let mut chal_bytes = vec![];
        sig_req_p
            .challenge_contribution(upk, set_comm_srs.get_P1(), Q, &mut chal_bytes)
            .unwrap();
        let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes);
        let (sig_req, sig_req_opn) = sig_req_p
            .gen_request(rng, attributes.clone(), usk, &challenge, set_comm_srs)
            .unwrap();
        sig_req
            .verify(
                attributes.clone(),
                upk,
                &challenge,
                Q,
                s_P2_from_accumulator,
                prep_set_comm_srs.clone(),
            )
            .unwrap();
        assert!(!(sig_req.supports_revocation() ^ supports_revocation));
        assert!(!(sig_req.auditable_sig ^ auditable));

        let sig = sig_req
            .clone()
            .sign(
                rng,
                isk,
                auditable.then_some(upk),
                auditable.then_some(apk),
                set_comm_srs.get_P1(),
                set_comm_srs.get_P2(),
            )
            .unwrap();
        let cred = Credential::new(
            sig_req,
            sig_req_opn,
            sig,
            attributes,
            prep_ipk,
            auditable.then_some(upk),
            auditable.then_some(apk),
            set_comm_srs.get_P1(),
            prep_set_comm_srs.prepared_P2,
        )
        .unwrap();
        assert_eq!(cred.supports_revocation(), supports_revocation);
        assert_eq!(cred.auditable_sig, auditable);
        cred
    }

    #[test]
    fn issuance_without_revocation() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let max_attributes = 10;
        let attributes = (0..max_attributes)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let attributes_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        issuance(
            &mut rng,
            max_attributes,
            attributes.clone(),
            false,
            None,
            None,
            None,
            None,
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes_1.clone(),
            false,
            None,
            None,
            None,
            None,
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes,
            true,
            None,
            None,
            None,
            None,
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes_1,
            true,
            None,
            None,
            None,
            None,
        );
    }

    #[test]
    fn issuance_with_revocation() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let max_attributes = 10;
        let attributes = (0..max_attributes)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let attributes_1 = (0..max_attributes - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let Q = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let nym = Fr::rand(&mut rng);

        let (accum_srs, _) = SetCommitmentSRS::<Bls12_381>::generate_with_random_trapdoor::<
            StdRng,
            Blake2b512,
        >(&mut rng, 100, Some("Protego".as_bytes()));

        issuance(
            &mut rng,
            max_attributes,
            attributes.clone(),
            false,
            Some(&Q),
            Some(&nym),
            Some(accum_srs.get_s_P1()),
            Some(accum_srs.get_s_P2()),
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes_1.clone(),
            false,
            Some(&Q),
            Some(&nym),
            Some(accum_srs.get_s_P1()),
            Some(accum_srs.get_s_P2()),
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes,
            true,
            Some(&Q),
            Some(&nym),
            Some(accum_srs.get_s_P1()),
            Some(accum_srs.get_s_P2()),
        );
        issuance(
            &mut rng,
            max_attributes,
            attributes_1,
            true,
            Some(&Q),
            Some(&nym),
            Some(accum_srs.get_s_P1()),
            Some(accum_srs.get_s_P2()),
        );
    }
}
