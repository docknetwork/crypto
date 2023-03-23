pub mod accumulator;
pub mod bbs_plus;
pub mod bound_check_legogroth16;
pub mod ps_signature;
pub mod r1cs_legogorth16;
pub mod saver;
pub mod schnorr;

use crate::error::ProofSystemError;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::io::Write;

use crate::statement_proof::StatementProof;
use crate::sub_protocols::bound_check_legogroth16::BoundCheckProtocol;
use crate::sub_protocols::r1cs_legogorth16::R1CSLegogroth16Protocol;
use accumulator::{AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol};

/// Various sub-protocols that are executed to create a `StatementProof` which are then combined to
/// form a `Proof`
#[derive(Clone, Debug, PartialEq)]
pub enum SubProtocol<'a, E: Pairing, G: AffineRepr> {
    PoKBBSSignatureG1(self::bbs_plus::PoKBBSSigG1SubProtocol<'a, E>),
    AccumulatorMembership(AccumulatorMembershipSubProtocol<'a, E>),
    AccumulatorNonMembership(AccumulatorNonMembershipSubProtocol<'a, E>),
    PoKDiscreteLogs(self::schnorr::SchnorrProtocol<'a, G>),
    /// For verifiable encryption using SAVER
    Saver(self::saver::SaverProtocol<'a, E>),
    /// For range proof using LegoGroth16
    BoundCheckProtocol(BoundCheckProtocol<'a, E>),
    R1CSLegogroth16Protocol(R1CSLegogroth16Protocol<'a, E>),
    PSSignaturePoK(self::ps_signature::PSSignaturePoK<'a, E>),
}

macro_rules! delegate {
    ($self: ident $($tt: tt)+) => {{
        $crate::delegate_indexed! {
            $self =>
                PoKBBSSignatureG1,
                AccumulatorMembership,
                AccumulatorNonMembership,
                PoKDiscreteLogs,
                Saver,
                BoundCheckProtocol,
                R1CSLegogroth16Protocol,
                PSSignaturePoK
            : $($tt)+
        }
    }};
}

pub trait ProofSubProtocol<E: Pairing, G: AffineRepr<ScalarField = E::ScalarField>> {
    fn challenge_contribution(&self, target: &mut [u8]) -> Result<(), ProofSystemError>;
    fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError>;
}

impl<'a, E: Pairing, G: AffineRepr<ScalarField = E::ScalarField>> SubProtocol<'a, E, G> {
    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        delegate!(self.challenge_contribution(writer))
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &E::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        delegate!(self.gen_proof_contribution(challenge))
    }
}
