//! Membership proof in VB positive accumulator and KB universal accumulator with keyed-verification

use crate::{error::ProofSystemError, statement_proof::StatementProof};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::{io::Write, rand::RngCore};
use vb_accumulator::{
    kb_universal_accumulator::proofs_keyed_verification::{
        KBUniversalAccumulatorMembershipProof, KBUniversalAccumulatorMembershipProofProtocol,
        KBUniversalAccumulatorNonMembershipProof, KBUniversalAccumulatorNonMembershipProofProtocol,
    },
    proofs_keyed_verification::{MembershipProof, MembershipProofProtocol},
    setup::SecretKey,
};

macro_rules! impl_struct_and_funcs {
    ($(#[$doc:meta])*
    $sub_protocol:ident, $protocol: ident, $proof: ident, $witness: ident, $sp_variant: ident, $error_variant: ident) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $sub_protocol<G: AffineRepr> {
            pub id: usize,
            pub accumulator_value: G,
            pub protocol: Option<$protocol<G>>,
        }

        impl<G: AffineRepr> $sub_protocol<G> {
            pub fn new(id: usize, accumulator_value: G) -> Self {
                Self {
                    id,
                    accumulator_value,
                    protocol: None,
                }
            }

            pub fn init<R: RngCore>(
                &mut self,
                rng: &mut R,
                blinding: Option<G::ScalarField>,
                witness: crate::witness::$witness<G>,
            ) -> Result<(), ProofSystemError> {
                if self.protocol.is_some() {
                    return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
                }
                self.protocol = Some($protocol::init(
                    rng,
                    witness.element,
                    blinding,
                    &witness.witness,
                    &self.accumulator_value,
                ));
                Ok(())
            }

            pub fn challenge_contribution<W: Write>(
                &self,
                writer: W,
            ) -> Result<(), ProofSystemError> {
                if self.protocol.is_none() {
                    return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                        self.id,
                    ));
                }
                self.protocol
                    .as_ref()
                    .unwrap()
                    .challenge_contribution(&self.accumulator_value, writer)?;
                Ok(())
            }

            pub fn gen_proof_contribution<E: Pairing<G1Affine = G>>(
                &mut self,
                challenge: &G::ScalarField,
            ) -> Result<StatementProof<E>, ProofSystemError> {
                if self.protocol.is_none() {
                    return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                        self.id,
                    ));
                }
                let protocol = self.protocol.take().unwrap();
                let proof = protocol.gen_proof(challenge)?;
                Ok(StatementProof::$sp_variant(proof))
            }

            pub fn verify_proof_contribution(
                &self,
                challenge: &G::ScalarField,
                proof: &$proof<G>,
            ) -> Result<(), ProofSystemError> {
                proof
                    .verify_schnorr_proof(&self.accumulator_value, challenge)
                    .map_err(|e| ProofSystemError::$error_variant(self.id as u32, e))
            }

            pub fn verify_full_proof_contribution(
                &self,
                challenge: &G::ScalarField,
                proof: &$proof<G>,
                secret_key: &SecretKey<G::ScalarField>,
            ) -> Result<(), ProofSystemError> {
                proof
                    .verify(&self.accumulator_value, secret_key, challenge)
                    .map_err(|e| ProofSystemError::$error_variant(self.id as u32, e))
            }
        }
    };
}

impl_struct_and_funcs!(
    VBAccumulatorMembershipKVSubProtocol,
    MembershipProofProtocol,
    MembershipProof,
    Membership,
    VBAccumulatorMembershipKV,
    VBAccumProofContributionFailed
);
impl_struct_and_funcs!(
    KBUniversalAccumulatorMembershipKVSubProtocol,
    KBUniversalAccumulatorMembershipProofProtocol,
    KBUniversalAccumulatorMembershipProof,
    KBUniMembership,
    KBUniversalAccumulatorMembershipKV,
    KBAccumProofContributionFailed
);
impl_struct_and_funcs!(
    KBUniversalAccumulatorNonMembershipKVSubProtocol,
    KBUniversalAccumulatorNonMembershipProofProtocol,
    KBUniversalAccumulatorNonMembershipProof,
    KBUniNonMembership,
    KBUniversalAccumulatorNonMembershipKV,
    KBAccumProofContributionFailed
);
