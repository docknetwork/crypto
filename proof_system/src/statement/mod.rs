use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

pub mod accumulator;
pub mod bbs_23;
pub mod bbs_23_ietf;
#[macro_use]
pub mod bbs_plus;
pub mod bbdt16_kvac;
pub mod bound_check_bpp;
pub mod bound_check_legogroth16;
pub mod bound_check_smc;
pub mod bound_check_smc_with_kv;
pub mod inequality;
pub mod ped_comm;
pub mod ps_signature;
pub mod r1cs_legogroth16;
pub mod saver;
pub mod verifiable_encryption_tz_21;

/// Type of relation being proved and the public values for the relation
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Statement<E: Pairing> {
    /// Statement used by prover for proof of knowledge of BBS+ signature
    PoKBBSSignatureG1Prover(bbs_plus::PoKBBSSignatureG1Prover<E>),
    /// For proof of knowledge of committed elements in a Pedersen commitment in group G1
    PedersenCommitment(ped_comm::PedersenCommitment<E::G1Affine>),
    /// For proof of knowledge of an accumulator member and its corresponding witness
    VBAccumulatorMembership(accumulator::VBAccumulatorMembership<E>),
    /// For proof of knowledge of an accumulator non-member and its corresponding witness
    VBAccumulatorNonMembership(accumulator::VBAccumulatorNonMembership<E>),
    /// Used by prover to create proof of verifiable encryption using SAVER
    SaverProver(saver::SaverProver<E>),
    /// Used by verifier to verify proof of verifiable encryption using SAVER
    SaverVerifier(saver::SaverVerifier<E>),
    /// Used by prover to create proof that witness satisfies publicly known bounds [min, max) using LegoGroth16
    BoundCheckLegoGroth16Prover(bound_check_legogroth16::BoundCheckLegoGroth16Prover<E>),
    /// Used by verifier to verify proof that witness satisfies publicly known bounds [min, max) using LegoGroth16
    BoundCheckLegoGroth16Verifier(bound_check_legogroth16::BoundCheckLegoGroth16Verifier<E>),
    /// Used by prover to create proof that witness satisfies constraints given by an R1CS (generated by Circom), using LegoGroth16
    R1CSCircomProver(r1cs_legogroth16::R1CSCircomProver<E>),
    /// Used by verifier to verify proof that witness satisfies constraints given by an R1CS (generated by Circom), using LegoGroth16
    R1CSCircomVerifier(r1cs_legogroth16::R1CSCircomVerifier<E>),
    /// For proof of knowledge of Pointcheval-Sanders signature.
    PoKPSSignature(ps_signature::PoKPSSignatureStatement<E>),
    /// Statement used by prover for proof of knowledge of BBS signature
    PoKBBSSignature23G1Prover(bbs_23::PoKBBSSignature23G1Prover<E>),
    /// For bound check using Bulletproofs++ protocol
    BoundCheckBpp(bound_check_bpp::BoundCheckBpp<E::G1Affine>),
    /// For bound check using set-membership check based protocols
    BoundCheckSmc(bound_check_smc::BoundCheckSmc<E>),
    /// Used by the prover for bound check using set-membership check with keyed verification based protocols
    BoundCheckSmcWithKVProver(bound_check_smc_with_kv::BoundCheckSmcWithKVProver<E::G1Affine>),
    /// Used by the verifier for bound check using set-membership check with keyed verification based protocols
    BoundCheckSmcWithKVVerifier(bound_check_smc_with_kv::BoundCheckSmcWithKVVerifier<E::G1Affine>),
    /// To prove inequality of a signed message with a public value
    PublicInequality(inequality::PublicInequality<E::G1Affine>),
    DetachedAccumulatorMembershipProver(accumulator::DetachedAccumulatorMembershipProver<E>),
    DetachedAccumulatorMembershipVerifier(accumulator::DetachedAccumulatorMembershipVerifier<E>),
    DetachedAccumulatorNonMembershipProver(accumulator::DetachedAccumulatorNonMembershipProver<E>),
    DetachedAccumulatorNonMembershipVerifier(
        accumulator::DetachedAccumulatorNonMembershipVerifier<E>,
    ),
    KBUniversalAccumulatorMembership(accumulator::KBUniversalAccumulatorMembership<E>),
    KBUniversalAccumulatorNonMembership(accumulator::KBUniversalAccumulatorNonMembership<E>),
    VBAccumulatorMembershipCDHProver(accumulator::cdh::VBAccumulatorMembershipCDHProver<E>),
    VBAccumulatorMembershipCDHVerifier(accumulator::cdh::VBAccumulatorMembershipCDHVerifier<E>),
    VBAccumulatorNonMembershipCDHProver(accumulator::cdh::VBAccumulatorNonMembershipCDHProver<E>),
    VBAccumulatorNonMembershipCDHVerifier(
        accumulator::cdh::VBAccumulatorNonMembershipCDHVerifier<E>,
    ),
    KBUniversalAccumulatorMembershipCDHProver(
        accumulator::cdh::KBUniversalAccumulatorMembershipCDHProver<E>,
    ),
    KBUniversalAccumulatorMembershipCDHVerifier(
        accumulator::cdh::KBUniversalAccumulatorMembershipCDHVerifier<E>,
    ),
    KBUniversalAccumulatorNonMembershipCDHProver(
        accumulator::cdh::KBUniversalAccumulatorNonMembershipCDHProver<E>,
    ),
    KBUniversalAccumulatorNonMembershipCDHVerifier(
        accumulator::cdh::KBUniversalAccumulatorNonMembershipCDHVerifier<E>,
    ),
    KBPositiveAccumulatorMembership(accumulator::KBPositiveAccumulatorMembership<E>),
    KBPositiveAccumulatorMembershipCDH(accumulator::cdh::KBPositiveAccumulatorMembershipCDH<E>),
    /// Statement used by verifier for proof of knowledge of BBS+ signature
    PoKBBSSignatureG1Verifier(bbs_plus::PoKBBSSignatureG1Verifier<E>),
    /// Statement used by verifier for proof of knowledge of BBS signature
    PoKBBSSignature23G1Verifier(bbs_23::PoKBBSSignature23G1Verifier<E>),
    /// For proof of knowledge of BBDT16 MAC.
    PoKBBDT16MAC(bbdt16_kvac::PoKOfMAC<E::G1Affine>),
    /// Statement used by verifier for proof of knowledge of BBDT16 MAC when it knows the secret key
    PoKBBDT16MACFullVerifier(bbdt16_kvac::PoKOfMACFullVerifier<E::G1Affine>),
    /// For proof of knowledge of committed elements in a Pedersen commitment in group G1
    PedersenCommitmentG2(ped_comm::PedersenCommitment<E::G2Affine>),
    /// For proof of membership in VB accumulator in keyed verification model.
    VBAccumulatorMembershipKV(
        accumulator::keyed_verification::VBAccumulatorMembershipKV<E::G1Affine>,
    ),
    /// Statement used by verifier for proof of membership in VB accumulator when it knows the secret key
    VBAccumulatorMembershipKVFullVerifier(
        accumulator::keyed_verification::VBAccumulatorMembershipKVFullVerifier<E::G1Affine>,
    ),
    /// For proof of membership in KB universal accumulator in keyed verification model.
    KBUniversalAccumulatorMembershipKV(
        accumulator::keyed_verification::KBUniversalAccumulatorMembershipKV<E::G1Affine>,
    ),
    /// Statement used by verifier for proof of membership in KB universal when it knows the secret key
    KBUniversalAccumulatorMembershipKVFullVerifier(
        accumulator::keyed_verification::KBUniversalAccumulatorMembershipKVFullVerifier<
            E::G1Affine,
        >,
    ),
    /// For proof of non-membership in KB universal accumulator in keyed verification model.
    KBUniversalAccumulatorNonMembershipKV(
        accumulator::keyed_verification::KBUniversalAccumulatorNonMembershipKV<E::G1Affine>,
    ),
    /// Statement used by verifier for proof of non-membership in KB universal when it knows the secret key
    KBUniversalAccumulatorNonMembershipKVFullVerifier(
        accumulator::keyed_verification::KBUniversalAccumulatorNonMembershipKVFullVerifier<
            E::G1Affine,
        >,
    ),
    PoKBBSSignature23IETFG1Prover(bbs_23_ietf::PoKBBSSignature23IETFG1Prover<E>),
    PoKBBSSignature23IETFG1Verifier(bbs_23_ietf::PoKBBSSignature23IETFG1Verifier<E>),
    /// Verifiable Encryption using DKGith protocol in the scheme TZ21
    // TODO: This should have the const generics used by the corresponding protocol
    VeTZ21(verifiable_encryption_tz_21::VerifiableEncryptionTZ21<E::G1Affine>),
    /// Verifiable Encryption using Robust DKGith protocol in the scheme TZ21
    // TODO: This should have the const generics used by the corresponding protocol
    VeTZ21Robust(verifiable_encryption_tz_21::VerifiableEncryptionTZ21<E::G1Affine>),
}

/// A collection of statements
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Statements<E: Pairing>(pub Vec<Statement<E>>);

impl<E: Pairing> Statements<E> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Statement<E>) -> usize {
        self.0.push(item);
        self.0.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

macro_rules! delegate {
    ($([$idx: ident])? $self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self $([$idx 0u8])? =>
                PoKBBSSignatureG1Prover,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                SaverProver,
                SaverVerifier,
                BoundCheckLegoGroth16Prover,
                BoundCheckLegoGroth16Verifier,
                R1CSCircomProver,
                R1CSCircomVerifier,
                PoKPSSignature,
                PoKBBSSignature23G1Prover,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKVProver,
                BoundCheckSmcWithKVVerifier,
                PublicInequality,
                DetachedAccumulatorMembershipProver,
                DetachedAccumulatorMembershipVerifier,
                DetachedAccumulatorNonMembershipProver,
                DetachedAccumulatorNonMembershipVerifier,
                KBUniversalAccumulatorMembership,
                KBUniversalAccumulatorNonMembership,
                VBAccumulatorMembershipCDHProver,
                VBAccumulatorMembershipCDHVerifier,
                VBAccumulatorNonMembershipCDHProver,
                VBAccumulatorNonMembershipCDHVerifier,
                KBUniversalAccumulatorMembershipCDHProver,
                KBUniversalAccumulatorMembershipCDHVerifier,
                KBUniversalAccumulatorNonMembershipCDHProver,
                KBUniversalAccumulatorNonMembershipCDHVerifier,
                KBPositiveAccumulatorMembership,
                KBPositiveAccumulatorMembershipCDH,
                PoKBBSSignatureG1Verifier,
                PoKBBSSignature23G1Verifier,
                PoKBBDT16MAC,
                PoKBBDT16MACFullVerifier,
                PedersenCommitmentG2,
                VBAccumulatorMembershipKV,
                VBAccumulatorMembershipKVFullVerifier,
                KBUniversalAccumulatorMembershipKV,
                KBUniversalAccumulatorMembershipKVFullVerifier,
                KBUniversalAccumulatorNonMembershipKV,
                KBUniversalAccumulatorNonMembershipKVFullVerifier,
                PoKBBSSignature23IETFG1Prover,
                PoKBBSSignature23IETFG1Verifier,
                VeTZ21,
                VeTZ21Robust
            : $($tt)+
        }
    }}
}

macro_rules! delegate_reverse {
    ($val: ident or else $err: expr => $($tt: tt)+) => {{
        $crate::delegate_indexed_reverse! {
            $val[_idx 0u8] =>
                PoKBBSSignatureG1Prover,
                VBAccumulatorMembership,
                VBAccumulatorNonMembership,
                PedersenCommitment,
                SaverProver,
                SaverVerifier,
                BoundCheckLegoGroth16Prover,
                BoundCheckLegoGroth16Verifier,
                R1CSCircomProver,
                R1CSCircomVerifier,
                PoKPSSignature,
                PoKBBSSignature23G1Prover,
                BoundCheckBpp,
                BoundCheckSmc,
                BoundCheckSmcWithKVProver,
                BoundCheckSmcWithKVVerifier,
                PublicInequality,
                DetachedAccumulatorMembershipProver,
                DetachedAccumulatorMembershipVerifier,
                DetachedAccumulatorNonMembershipProver,
                DetachedAccumulatorNonMembershipVerifier,
                KBUniversalAccumulatorMembership,
                KBUniversalAccumulatorNonMembership,
                VBAccumulatorMembershipCDHProver,
                VBAccumulatorMembershipCDHVerifier,
                VBAccumulatorNonMembershipCDHProver,
                VBAccumulatorNonMembershipCDHVerifier,
                KBUniversalAccumulatorMembershipCDHProver,
                KBUniversalAccumulatorMembershipCDHVerifier,
                KBUniversalAccumulatorNonMembershipCDHProver,
                KBUniversalAccumulatorNonMembershipCDHVerifier,
                KBPositiveAccumulatorMembership,
                KBPositiveAccumulatorMembershipCDH,
                PoKBBSSignatureG1Verifier,
                PoKBBSSignature23G1Verifier,
                PoKBBDT16MAC,
                PoKBBDT16MACFullVerifier,
                PedersenCommitmentG2,
                VBAccumulatorMembershipKV,
                VBAccumulatorMembershipKVFullVerifier,
                KBUniversalAccumulatorMembershipKV,
                KBUniversalAccumulatorMembershipKVFullVerifier,
                KBUniversalAccumulatorNonMembershipKV,
                KBUniversalAccumulatorNonMembershipKVFullVerifier,
                PoKBBSSignature23IETFG1Prover,
                PoKBBSSignature23IETFG1Verifier,
                VeTZ21,
                VeTZ21Robust
            : $($tt)+
        }

        $err
    }}
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, Valid, Validate};

    impl<E: Pairing> Valid for Statement<E> {
        fn check(&self) -> Result<(), SerializationError> {
            delegate!(self.check())
        }
    }

    impl<E: Pairing> CanonicalSerialize for Statement<E> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            delegate!([index]self with variant as statement {
                CanonicalSerialize::serialize_with_mode(&index, &mut writer, compress)?;
                CanonicalSerialize::serialize_with_mode(statement, &mut writer, compress)?;

                Ok(())
            })
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            delegate!([index]self with variant as statement {
                index.serialized_size(compress) + CanonicalSerialize::serialized_size(statement, compress)
            })
        }
    }

    impl<E: Pairing> CanonicalDeserialize for Statement<E> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let idx: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

            delegate_reverse!(
                idx or else Err(SerializationError::InvalidData) => with variant as build
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate).map(build)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj, Bls12_381};
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{
        collections::BTreeMap,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use test_utils::{
        accumulators::{setup_positive_accum, setup_universal_accum},
        bbs::{bbs_plus_sig_setup, bbs_sig_setup},
        test_serialization,
    };
    use vb_accumulator::prelude::{Accumulator, MembershipProvingKey, NonMembershipProvingKey};

    #[test]
    fn statement_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (_, params_1, keypair_1, _) = bbs_plus_sig_setup(&mut rng, 5);
        let (_, params_23, keypair_23, _) = bbs_sig_setup(&mut rng, 5);
        let (pos_params, pos_keypair, pos_accumulator, _) = setup_positive_accum(&mut rng);
        let (uni_params, uni_keypair, uni_accumulator, _, _) = setup_universal_accum(&mut rng, 100);
        let mem_prk =
            MembershipProvingKey::<<Bls12_381 as Pairing>::G1Affine>::generate_using_rng(&mut rng);
        let non_mem_prk =
            NonMembershipProvingKey::<<Bls12_381 as Pairing>::G1Affine>::generate_using_rng(
                &mut rng,
            );

        let mut statements: Statements<Bls12_381> = Statements::new();

        let stmt_1 = bbs_plus::PoKBBSSignatureG1Prover::new_statement_from_params(
            params_1.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_1);

        statements.add(stmt_1);
        test_serialization!(Statements<Bls12_381>, statements);

        let stmt_2 = accumulator::VBAccumulatorMembership::new_statement_from_params(
            pos_params,
            pos_keypair.public_key.clone(),
            mem_prk,
            *pos_accumulator.value(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_2);

        statements.add(stmt_2);
        test_serialization!(Statements<Bls12_381>, statements);

        let stmt_3 = accumulator::VBAccumulatorNonMembership::new_statement_from_params(
            uni_params,
            uni_keypair.public_key.clone(),
            non_mem_prk,
            *uni_accumulator.value(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_3);

        statements.add(stmt_3);
        test_serialization!(Statements<Bls12_381>, statements);

        let bases = (0..5)
            .map(|_| G1Proj::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let commitment = G1Proj::msm_unchecked(&bases, &scalars).into_affine();
        let stmt_4 = ped_comm::PedersenCommitment::new_statement_from_params(bases, commitment);
        test_serialization!(Statement<Bls12_381>, stmt_4);

        statements.add(stmt_4);
        test_serialization!(Statements<Bls12_381>, statements);

        let stmt_5 = bbs_23::PoKBBSSignature23G1Prover::new_statement_from_params(
            params_23.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_5);

        statements.add(stmt_5);
        test_serialization!(Statements<Bls12_381>, statements);

        let stmt_6 = bbs_plus::PoKBBSSignatureG1Verifier::new_statement_from_params(
            params_1,
            keypair_1.public_key.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_6);

        statements.add(stmt_6);
        test_serialization!(Statements<Bls12_381>, statements);

        let stmt_7 = bbs_23::PoKBBSSignature23G1Verifier::new_statement_from_params(
            params_23,
            keypair_23.public_key.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381>, stmt_7);

        statements.add(stmt_7);
        test_serialization!(Statements<Bls12_381>, statements);
    }
}
