pub mod accumulator;
pub mod bbs_plus;
pub mod saver;
pub mod schnorr;

use crate::error::ProofSystemError;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::io::Write;

use crate::statement_proof::StatementProof;
use accumulator::{AccumulatorMembershipSubProtocol, AccumulatorNonMembershipSubProtocol};
use ark_ff::{PrimeField, SquareRootField};

/// Various sub-protocols that are executed to create a `StatementProof` which are then combined to
/// form a `Proof`
#[derive(Clone, Debug, PartialEq)]
pub enum SubProtocol<E: PairingEngine, G: AffineCurve> {
    PoKBBSSignatureG1(self::bbs_plus::PoKBBSSigG1SubProtocol<E>),
    AccumulatorMembership(AccumulatorMembershipSubProtocol<E>),
    AccumulatorNonMembership(AccumulatorNonMembershipSubProtocol<E>),
    PoKDiscreteLogs(self::schnorr::SchnorrProtocol<G>),
    Saver(self::saver::SaverProtocol<E>),
}

pub trait ProofSubProtocol<
    F: PrimeField + SquareRootField,
    E: PairingEngine<Fr = F>,
    G: AffineCurve<ScalarField = F>,
>
{
    fn challenge_contribution(&self, target: &mut [u8]) -> Result<(), ProofSystemError>;
    fn gen_proof_contribution(
        &mut self,
        challenge: &F,
    ) -> Result<StatementProof<E, G>, ProofSystemError>;
    fn verify_proof_contribution(
        &self,
        challenge: &F,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError>;
}

impl<
        F: PrimeField + SquareRootField,
        E: PairingEngine<Fr = F>,
        G: AffineCurve<ScalarField = F>,
    > SubProtocol<E, G>
{
    pub fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.challenge_contribution(writer),
            SubProtocol::AccumulatorMembership(s) => s.challenge_contribution(writer),
            SubProtocol::AccumulatorNonMembership(s) => s.challenge_contribution(writer),
            SubProtocol::PoKDiscreteLogs(s) => s.challenge_contribution(writer),
            SubProtocol::Saver(s) => s.challenge_contribution(writer),
        }
    }

    pub fn gen_proof_contribution(
        &mut self,
        challenge: &F,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.gen_proof_contribution(challenge),
            SubProtocol::AccumulatorMembership(s) => s.gen_proof_contribution(challenge),
            SubProtocol::AccumulatorNonMembership(s) => s.gen_proof_contribution(challenge),
            SubProtocol::PoKDiscreteLogs(s) => s.gen_proof_contribution(challenge),
            SubProtocol::Saver(s) => s.gen_proof_contribution(challenge),
        }
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &F,
        proof: &StatementProof<E, G>,
    ) -> Result<(), ProofSystemError> {
        match self {
            SubProtocol::PoKBBSSignatureG1(s) => s.verify_proof_contribution(challenge, proof),
            SubProtocol::AccumulatorMembership(s) => s.verify_proof_contribution(challenge, proof),
            SubProtocol::AccumulatorNonMembership(s) => {
                s.verify_proof_contribution(challenge, proof)
            }
            SubProtocol::PoKDiscreteLogs(s) => s.verify_proof_contribution(challenge, proof),
            SubProtocol::Saver(s) => s.verify_proof_contribution(challenge, proof),
        }
    }
}
