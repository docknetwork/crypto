use ark_ec::{AffineCurve, PairingEngine};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Read, Write},
    vec::Vec,
};

use bbs_plus::setup::{PublicKeyG2 as BBSPublicKeyG2, SignatureParamsG1 as BBSSignatureParamsG1};
use dock_crypto_utils::serde_utils::*;
use legogroth16::ProvingKey as LegoProvingKey;
use saver::keygen::EncryptionKey;
use saver::setup::{ChunkedCommitmentGens, EncryptionGens};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};
use vb_accumulator::{
    proofs::{MembershipProvingKey, NonMembershipProvingKey},
    setup::{PublicKey as AccumPublicKey, SetupParams as AccumParams},
};

use crate::error::ProofSystemError;
pub use serialization::*;

/// Type of proof and the public values (known to both prover and verifier) for the proof
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Statement<E: PairingEngine, G: AffineCurve> {
    /// Proof of knowledge of BBS+ signature
    PoKBBSSignatureG1(PoKBBSSignatureG1<E>),
    /// Membership in Accumulator
    AccumulatorMembership(AccumulatorMembership<E>),
    /// Non-membership in Accumulator
    AccumulatorNonMembership(AccumulatorNonMembership<E>),
    /// Proof of knowledge of committed elements in a Pedersen commitment
    PedersenCommitment(PedersenCommitment<G>),
    Saver(Saver<E>),
    BoundCheckLegoGroth16(BoundCheckLegoGroth16<E>),
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Statements<E, G>(pub Vec<Statement<E, G>>)
where
    E: PairingEngine,
    G: AffineCurve;

/// Public values like setup params, public key and revealed messages for proving knowledge of BBS+ signature.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PoKBBSSignatureG1<E: PairingEngine> {
    pub params: BBSSignatureParamsG1<E>,
    pub public_key: BBSPublicKeyG2<E>,
    /// Messages being revealed.
    #[serde_as(as = "BTreeMap<Same, FieldBytes>")]
    pub revealed_messages: BTreeMap<usize, E::Fr>,
}

/// Public values like setup params, public key, proving key and accumulator for proving membership
/// in positive and universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: MembershipProvingKey<E::G1Affine>,
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
}

/// Public values like setup params, public key, proving key and accumulator for proving non-membership
/// in universal accumulator.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct AccumulatorNonMembership<E: PairingEngine> {
    pub params: AccumParams<E>,
    pub public_key: AccumPublicKey<E::G2Affine>,
    pub proving_key: NonMembershipProvingKey<E::G1Affine>,
    #[serde_as(as = "AffineGroupBytes")]
    pub accumulator_value: E::G1Affine,
}

/// Proving knowledge of scalars `s_i` in Pedersen commitment `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct PedersenCommitment<G: AffineCurve> {
    /// The bases `g_i` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "Vec<AffineGroupBytes>")]
    pub bases: Vec<G>,
    /// The Pedersen commitment `C` in `g_0 * s_0 + g_1 * s_1 + ... + g_{n-1} * s_{n-1} = C`
    #[serde_as(as = "AffineGroupBytes")]
    pub commitment: G,
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct Saver<E: PairingEngine> {
    pub chunk_bit_size: u8,
    pub encryption_gens: EncryptionGens<E>,
    pub chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
    pub encryption_key: EncryptionKey<E>,
    pub snark_proving_key: saver::saver_groth16::ProvingKey<E>,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct BoundCheckLegoGroth16<E: PairingEngine> {
    #[serde_as(as = "FieldBytes")]
    pub min: E::Fr,
    #[serde_as(as = "FieldBytes")]
    pub max: E::Fr,
    #[serde_as(as = "LegoProvingKeyBytes")]
    pub snark_proving_key: LegoProvingKey<E>,
}

impl<E, G> Statements<E, G>
where
    E: PairingEngine,
    G: AffineCurve,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, item: Statement<E, G>) -> usize {
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

/// Create a `Statement` variant for proving knowledge of BBS+ signature
impl<E: PairingEngine> PoKBBSSignatureG1<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: BBSSignatureParamsG1<E>,
        public_key: BBSPublicKeyG2<E>,
        revealed_messages: BTreeMap<usize, E::Fr>,
    ) -> Statement<E, G> {
        Statement::PoKBBSSignatureG1(Self {
            params,
            public_key,
            revealed_messages,
        })
    }
}

/// Create a `Statement` variant for proving membership in accumulator
impl<E: PairingEngine> AccumulatorMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: MembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving non-membership in accumulator
impl<E: PairingEngine> AccumulatorNonMembership<E> {
    pub fn new_as_statement<G: AffineCurve>(
        params: AccumParams<E>,
        public_key: AccumPublicKey<E::G2Affine>,
        proving_key: NonMembershipProvingKey<E::G1Affine>,
        accumulator: E::G1Affine,
    ) -> Statement<E, G> {
        Statement::AccumulatorNonMembership(Self {
            params,
            public_key,
            proving_key,
            accumulator_value: accumulator,
        })
    }
}

/// Create a `Statement` variant for proving knowledge of committed elements in a Pedersen commitment
impl<G: AffineCurve> PedersenCommitment<G> {
    pub fn new_as_statement<E: PairingEngine>(bases: Vec<G>, commitment: G) -> Statement<E, G> {
        Statement::PedersenCommitment(Self { bases, commitment })
    }
}

impl<E: PairingEngine> Saver<E> {
    pub fn new_as_statement<G: AffineCurve>(
        chunk_bit_size: u8,
        encryption_gens: EncryptionGens<E>,
        chunked_commitment_gens: ChunkedCommitmentGens<E::G1Affine>,
        encryption_key: EncryptionKey<E>,
        snark_proving_key: saver::saver_groth16::ProvingKey<E>,
    ) -> Result<Statement<E, G>, ProofSystemError> {
        if encryption_key.supported_chunks_count()?
            != saver::utils::chunks_count::<E::Fr>(chunk_bit_size)
        {
            return Err(ProofSystemError::SaverError(
                saver::error::SaverError::IncompatibleEncryptionKey(
                    saver::utils::chunks_count::<E::Fr>(chunk_bit_size) as usize,
                    encryption_key.supported_chunks_count()? as usize,
                ),
            ));
        }
        Ok(Statement::Saver(Self {
            chunk_bit_size,
            encryption_gens,
            chunked_commitment_gens,
            encryption_key,
            snark_proving_key,
        }))
    }
}

impl<E: PairingEngine> BoundCheckLegoGroth16<E> {
    pub fn new_as_statement<G: AffineCurve>(
        min: E::Fr,
        max: E::Fr,
        snark_proving_key: LegoProvingKey<E>,
    ) -> Result<Statement<E, G>, ProofSystemError> {
        if snark_proving_key.vk.gamma_abc_g1.len() < 4 {
            return Err(ProofSystemError::LegoGroth16Error(
                legogroth16::error::Error::SynthesisError(SynthesisError::MalformedVerifyingKey),
            ));
        }
        Ok(Statement::BoundCheckLegoGroth16(Self {
            min,
            max,
            snark_proving_key,
        }))
    }
}

mod serialization {
    use super::*;
    use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    impl<E: PairingEngine, G: AffineCurve> CanonicalSerialize for Statement<E, G> {
        impl_serialize!();
    }

    impl<E: PairingEngine, G: AffineCurve> CanonicalDeserialize for Statement<E, G> {
        impl_deserialize!();
    }

    impl_for_groth16_struct!(
        LegoProvingKeyBytes,
        LegoProvingKey,
        "expected LegoProvingKey"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_serialization;
    use crate::test_utils::{setup_positive_accum, setup_universal_accum, sig_setup};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{fr::Fr, g1::G1Projective as G1Proj};
    use ark_ec::msm::VariableBaseMSM;
    use ark_ec::ProjectiveCurve;
    use ark_ff::fields::PrimeField;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use vb_accumulator::prelude::Accumulator;

    #[test]
    fn statement_serialization_deserialization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let (_, params_1, keypair_1, _) = sig_setup(&mut rng, 5);
        let (pos_params, pos_keypair, pos_accumulator, _) = setup_positive_accum(&mut rng);
        let (uni_params, uni_keypair, uni_accumulator, _, _) = setup_universal_accum(&mut rng, 100);
        let mem_prk =
            MembershipProvingKey::<<Bls12_381 as PairingEngine>::G1Affine>::generate_using_rng(
                &mut rng,
            );
        let non_mem_prk =
            NonMembershipProvingKey::<<Bls12_381 as PairingEngine>::G1Affine>::generate_using_rng(
                &mut rng,
            );

        let mut statements: Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine> =
            Statements::new();

        let stmt_1 = PoKBBSSignatureG1::new_as_statement(
            params_1.clone(),
            keypair_1.public_key.clone(),
            BTreeMap::new(),
        );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_1);

        statements.add(stmt_1);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_2 =
            AccumulatorMembership::new_as_statement::<<Bls12_381 as PairingEngine>::G1Affine>(
                pos_params.clone(),
                pos_keypair.public_key.clone(),
                mem_prk.clone(),
                pos_accumulator.value().clone(),
            );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_2);

        statements.add(stmt_2);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let stmt_3 =
            AccumulatorNonMembership::new_as_statement::<<Bls12_381 as PairingEngine>::G1Affine>(
                uni_params.clone(),
                uni_keypair.public_key.clone(),
                non_mem_prk.clone(),
                uni_accumulator.value().clone(),
            );
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_3);

        statements.add(stmt_3);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);

        let bases = (0..5)
            .map(|_| G1Proj::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let scalars = (0..5).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &bases,
            &scalars.iter().map(|s| s.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let stmt_4 = Statement::PedersenCommitment(PedersenCommitment { bases, commitment });
        test_serialization!(Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, stmt_4);

        statements.add(stmt_4);
        test_serialization!(Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>, statements);
    }
}
