use crate::{
    error::ProofSystemError,
    prelude::{ElgamalEncryptionParams, StatementProof},
    statement_proof::{VeTZ21Proof, VeTZ21RobustProof},
    sub_protocols::schnorr::SchnorrProtocol,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    rand::RngCore,
    vec::Vec,
    UniformRand,
};
use digest::Digest;
use dock_crypto_utils::{
    aliases::FullDigest, elgamal::BatchedHashedElgamalCiphertext, transcript::Transcript,
};
use sha3::Shake256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO: The parameters used for both protocols are hardcoded here but they should be generic as
// different curves or different applications might need different values than these.

pub mod dkgith_decls {
    use super::BatchedHashedElgamalCiphertext;
    use verifiable_encryption::tz_21::dkgith::{CompressedCiphertext, DkgithProof};

    pub const NUM_PARTIES: usize = 16;
    pub const NUM_REPS: usize = 32;
    pub const SUBSET_SIZE: usize = 30;

    pub const SEED_SIZE: usize = 16;
    pub const SALT_SIZE: usize = 32;

    pub type Proof<G> = DkgithProof<
        G,
        BatchedHashedElgamalCiphertext<G>,
        NUM_PARTIES,
        NUM_REPS,
        SEED_SIZE,
        SALT_SIZE,
    >;
    pub type Ciphertext<G> =
        CompressedCiphertext<G, BatchedHashedElgamalCiphertext<G>, SUBSET_SIZE>;
}

pub mod rdkgith_decls {
    use dock_crypto_utils::elgamal::BatchedHashedElgamalCiphertext;
    use verifiable_encryption::tz_21::rdkgith::{CompressedCiphertext, RdkgithProof};

    pub const NUM_PARTIES: usize = 192;
    pub const THRESHOLD: usize = 36;
    pub const SUBSET_SIZE: usize = 145;

    pub type Proof<G> = RdkgithProof<G, BatchedHashedElgamalCiphertext<G>, NUM_PARTIES, THRESHOLD>;
    pub type Ciphertext<G> =
        CompressedCiphertext<G, BatchedHashedElgamalCiphertext<G>, SUBSET_SIZE>;
}

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VeTZ21Protocol<'a, G: AffineRepr> {
    #[zeroize(skip)]
    pub id: usize,
    #[zeroize(skip)]
    pub comm_key: &'a [G],
    #[zeroize(skip)]
    pub enc_params: &'a ElgamalEncryptionParams<G>,
    pub sp: Option<SchnorrProtocol<'a, G>>,
    #[zeroize(skip)]
    pub variant_type: bool,
}

macro_rules! impl_common_funcs {
    ($group: ident, $proof_gen_func: path, $proof_ver_func: path, $variant_type: expr, $proof_struct_name: ident, $sp_variant: ident, $init_fn_name: ident, $chal_fn_name: ident, $proof_gen_fn_name: ident, $proof_ver_fn_name: ident) => {
        pub fn $init_fn_name<R: RngCore>(
            &mut self,
            rng: &mut R,
            mut witnesses: Vec<$group::ScalarField>,
            mut blindings: Vec<$group::ScalarField>,
        ) -> Result<(), ProofSystemError> {
            if self.sp.is_some() {
                return Err(ProofSystemError::SubProtocolAlreadyInitialized(self.id));
            }
            // witnesses will be the messages from signature(s) that need to be encrypted. Since the VE
            // protocol requires a commitment to them, add randomness to the commitment to make it perfectly
            // hiding.
            witnesses.push($group::ScalarField::rand(rng));
            blindings.push($group::ScalarField::rand(rng));
            // Commit to the witneses
            let comm_key = &self.comm_key[..witnesses.len()];
            let commitment = $group::Group::msm_unchecked(comm_key, &witnesses).into_affine();
            self.variant_type = $variant_type;
            self.init_schnorr_protocol(witnesses, blindings, commitment, comm_key)
        }

        pub fn $chal_fn_name<W: Write>(
            enc_params: &'a ElgamalEncryptionParams<G>,
            comm_key: &[G],
            proof: &$proof_struct_name<$group>,
            mut writer: W,
        ) -> Result<(), ProofSystemError> {
            enc_params.serialize_compressed(&mut writer)?;
            let ck = comm_key[0..proof.ve_proof.witness_count()].as_ref();
            ck.serialize_compressed(&mut writer)?;
            proof.commitment.serialize_compressed(&mut writer)?;
            proof.sp.t.serialize_compressed(&mut writer)?;
            Ok(())
        }

        pub fn $proof_gen_fn_name<
            E: Pairing<G1Affine = $group>,
            R: RngCore,
            D: FullDigest + Digest,
        >(
            &mut self,
            rng: &mut R,
            challenge: &$group::ScalarField,
            transcript: &mut impl Transcript,
        ) -> Result<StatementProof<E>, ProofSystemError> {
            if self.sp.is_none() {
                return Err(ProofSystemError::SubProtocolNotReadyToGenerateProof(
                    self.id,
                ));
            }
            let witness_count = self.sp.as_ref().unwrap().commitment_key.len();
            let witnesses = self.sp.as_ref().unwrap().witnesses.clone().unwrap();
            let comm_key = &self.comm_key[..witness_count];
            // Generate the VE proof
            let ve_proof = $proof_gen_func(
                rng,
                witnesses,
                comm_key,
                &self.enc_params.public_key,
                &self.enc_params.g,
                transcript,
            )?;
            // Don't generate response for all indices except for the last one since their response will come from proofs of one of the signatures.
            let skip_for = BTreeSet::from_iter(0..(witness_count - 1));
            Ok(StatementProof::$sp_variant($proof_struct_name {
                ve_proof: ve_proof,
                commitment: self.sp.as_ref().unwrap().commitment.clone(),
                sp: self
                    .sp
                    .take()
                    .unwrap()
                    .gen_partial_proof_contribution_as_struct(challenge, &skip_for)?,
            }))
        }

        pub fn $proof_ver_fn_name<D: FullDigest + Digest>(
            &self,
            challenge: &$group::ScalarField,
            proof: &$proof_struct_name<$group>,
            transcript: &mut impl Transcript,
            missing_resps: BTreeMap<usize, $group::ScalarField>,
        ) -> Result<(), ProofSystemError> {
            let witness_count = proof.ve_proof.witness_count();
            let comm_key = &self.comm_key[..witness_count];
            $proof_ver_func(
                &proof.ve_proof,
                &proof.commitment,
                comm_key,
                &self.enc_params.public_key,
                &self.enc_params.g,
                transcript,
            )
            .map_err(|e| ProofSystemError::VerifiableEncryptionFailed(self.id as u32, e))?;
            // NOTE: value of id is dummy
            let sp = SchnorrProtocol::new(10000, comm_key, proof.commitment);
            sp.verify_partial_proof_contribution(challenge, &proof.sp, missing_resps)
                .map_err(|e| ProofSystemError::SchnorrProofContributionFailed(self.id as u32, e))
        }
    };
}

impl<'a, G: AffineRepr> VeTZ21Protocol<'a, G> {
    pub fn new(id: usize, comm_key: &'a [G], enc_params: &'a ElgamalEncryptionParams<G>) -> Self {
        Self {
            id,
            comm_key,
            enc_params,
            sp: None,
            variant_type: false,
        }
    }

    // TODO: Make XOF generic by making `Proof::new` and `Proof::verify` accept it
    impl_common_funcs!(
        G,
        dkgith_decls::Proof::new::<R, D, Shake256>,
        dkgith_decls::Proof::verify::<D, Shake256>,
        true,
        VeTZ21Proof,
        VeTZ21,
        init,
        compute_challenge_contribution,
        gen_proof_contribution,
        verify_proof_contribution
    );

    impl_common_funcs!(
        G,
        rdkgith_decls::Proof::new::<R, D>,
        rdkgith_decls::Proof::verify::<D>,
        false,
        VeTZ21RobustProof,
        VeTZ21Robust,
        init_robust,
        compute_challenge_contribution_robust,
        gen_proof_contribution_robust,
        verify_proof_contribution_robust
    );

    fn init_schnorr_protocol(
        &mut self,
        witnesses: Vec<G::ScalarField>,
        blindings: Vec<G::ScalarField>,
        commitment: G,
        comm_key: &'a [G],
    ) -> Result<(), ProofSystemError> {
        let mut sp = SchnorrProtocol::new(10000, &comm_key, commitment);
        sp.init_with_all_blindings_given(blindings, witnesses)?;
        self.sp = Some(sp);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), ProofSystemError> {
        if self.sp.is_none() {
            return Err(ProofSystemError::SubProtocolNotReadyToGenerateChallenge(
                self.id,
            ));
        }
        self.enc_params.serialize_compressed(&mut writer)?;
        self.sp
            .as_ref()
            .unwrap()
            .challenge_contribution(&mut writer)?;
        Ok(())
    }
}
