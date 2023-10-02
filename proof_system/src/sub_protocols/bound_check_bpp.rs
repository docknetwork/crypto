use crate::{
    error::ProofSystemError,
    prelude::StatementProof,
    statement_proof::BoundCheckBppProof,
    sub_protocols::{enforce_and_get_u64, schnorr::SchnorrProtocol},
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, io::Write, rand::RngCore, vec, UniformRand};
use bulletproofs_plus_plus::{prelude::ProofArbitraryRange, setup::SetupParams};
use dock_crypto_utils::transcript::Transcript;

/// Runs the Bulletproofs++ protocol for proving bounds of a witness and a Schnorr protocol for proving
/// knowledge of the witness committed in the commitments accompanying the proof.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundCheckBppProtocol<'a, G: AffineRepr> {
    pub id: usize,
    pub min: u64,
    pub max: u64,
    pub setup_params: &'a SetupParams<G>,
    pub bpp_proof: Option<ProofArbitraryRange<G>>,
    pub sp1: Option<SchnorrProtocol<'a, G>>,
    pub sp2: Option<SchnorrProtocol<'a, G>>,
}

impl<'a, G: AffineRepr> BoundCheckBppProtocol<'a, G> {
    pub fn new(id: usize, min: u64, max: u64, setup_params: &'a SetupParams<G>) -> Self {
        Self {
            id,
            min,
            max,
            setup_params,
            bpp_proof: None,
            sp1: None,
            sp2: None,
        }
    }

    pub fn init<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
        transcript: &mut impl Transcript,
    ) -> Result<(), ProofSystemError> {
        if self.sp1.is_some() || self.sp2.is_some() {
            return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
        }
        let msg_as_u64 = enforce_and_get_u64::<G::ScalarField>(&message)?;

        // blindings for the commitments in the Bulletproofs++ proof, there will be 2 Bulletproofs++ proofs, for ranges `(message - min)` and `(max - message)`
        let bpp_randomness = vec![G::ScalarField::rand(rng), G::ScalarField::rand(rng)];
        let proof = ProofArbitraryRange::new(
            rng,
            Self::get_num_bits(self.max),
            vec![(msg_as_u64, self.min, self.max)],
            bpp_randomness.clone(),
            self.setup_params.clone(),
            transcript,
        )?;
        assert_eq!(proof.num_proofs(), 1);
        self.init_schnorr_protocol(
            rng,
            comm_key,
            message,
            blinding,
            (bpp_randomness[0], bpp_randomness[1]),
            proof,
        )
    }

    fn init_schnorr_protocol<R: RngCore>(
        &mut self,
        rng: &mut R,
        comm_key: &'a [G],
        message: G::ScalarField,
        blinding: Option<G::ScalarField>,
        blindings_for_bpp: (G::ScalarField, G::ScalarField),
        bpp_proof: ProofArbitraryRange<G>,
    ) -> Result<(), ProofSystemError> {
        // blinding used to prove knowledge of message in `snark_proof.d`. The caller of this method ensures
        // that this will be same as the one used proving knowledge of the corresponding message in BBS+
        // signature, thus allowing them to be proved equal.
        let blinding = if blinding.is_none() {
            G::ScalarField::rand(rng)
        } else {
            blinding.unwrap()
        };
        let mut blindings = BTreeMap::new();
        blindings.insert(0, blinding);

        let (r1, r2) = blindings_for_bpp;
        let (comm_1, comm_2) = self.get_commitments_to_values(&bpp_proof)?;
        // NOTE: value of id is dummy
        let mut sp1 = SchnorrProtocol::new(10000, comm_key, comm_1);
        let mut sp2 = SchnorrProtocol::new(10000, comm_key, comm_2);
        sp1.init(rng, blindings.clone(), vec![message, r1])?;
        sp2.init(rng, blindings, vec![message, -r2])?;
        self.bpp_proof = Some(bpp_proof);
        self.sp1 = Some(sp1);
        self.sp2 = Some(sp2);
        Ok(())
    }

    /// Generate challenge contribution for both the Schnorr protocols
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.sp1.is_none() || self.sp2.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.sp1
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        self.sp2
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }

    /// Generate responses for both the Schnorr protocols
    pub fn gen_proof_contribution<E: Pairing>(
        &mut self,
        challenge: &G::ScalarField,
    ) -> Result<StatementProof<E, G>, ProofSystemError> {
        if self.sp1.is_none() || self.sp2.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                self.id,
            ));
        }
        Ok(StatementProof::BoundCheckBpp(BoundCheckBppProof {
            bpp_proof: self.bpp_proof.take().unwrap(),
            sp1: self
                .sp1
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
            sp2: self
                .sp2
                .take()
                .unwrap()
                .gen_proof_contribution_as_struct(challenge)?,
        }))
    }

    pub fn verify_proof_contribution(
        &self,
        challenge: &G::ScalarField,
        proof: &BoundCheckBppProof<G>,
        comm_key: &[G],
        transcript: &mut impl Transcript,
    ) -> Result<(), ProofSystemError> {
        proof
            .bpp_proof
            .verify(Self::get_num_bits(self.max), &self.setup_params, transcript)?;
        if !proof.check_schnorr_responses_consistency()? {
            return Err(ProofSystemError::DifferentResponsesForSchnorrProtocolInBpp(
                self.id,
            ));
        }
        let (comm_1, comm_2) = self.get_commitments_to_values(&proof.bpp_proof)?;

        // NOTE: value of id is dummy
        let sp1 = SchnorrProtocol::new(10000, comm_key, comm_1);
        let sp2 = SchnorrProtocol::new(10000, comm_key, comm_2);

        sp1.verify_proof_contribution_as_struct(challenge, &proof.sp1)?;
        sp2.verify_proof_contribution_as_struct(challenge, &proof.sp2)
    }

    pub fn compute_challenge_contribution<W: Write>(
        min: u64,
        max: u64,
        comm_key: &[G],
        proof: &BoundCheckBppProof<G>,
        mut writer: W,
    ) -> Result<(), ProofSystemError> {
        let mut comms = proof
            .bpp_proof
            .get_commitments_to_values_given_g(vec![(min, max)], &comm_key[0])?;
        let (comm_1, comm_2) = comms.remove(0);
        comm_key.serialize_compressed(&mut writer)?;
        comm_1.serialize_compressed(&mut writer)?;
        proof.sp1.t.serialize_compressed(&mut writer)?;
        // Serializing `comm_key` twice to match what happens in `Self::challenge_contribution`
        comm_key.serialize_compressed(&mut writer)?;
        comm_2.serialize_compressed(&mut writer)?;
        proof.sp2.t.serialize_compressed(&mut writer)?;
        Ok(())
    }

    fn get_commitments_to_values(
        &self,
        proof: &ProofArbitraryRange<G>,
    ) -> Result<(G, G), ProofSystemError> {
        let mut comms =
            proof.get_commitments_to_values(vec![(self.min, self.max)], &self.setup_params)?;
        Ok(comms.remove(0))
    }

    fn get_num_bits(_max: u64) -> u16 {
        64
    }
}
