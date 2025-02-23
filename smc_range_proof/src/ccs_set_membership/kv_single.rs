//! Check membership of a single element in the set using keyed-verification, i.e. verifier knows
//! the secret key for BB sig

use crate::{
    ccs_set_membership::setup::SetMembershipCheckParamsKV, common::MemberCommitmentKey,
    error::SmcRangeProofError,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, rand::RngCore, vec::Vec, UniformRand};
use schnorr_pok::{
    discrete_log::PokPedersenCommitmentProtocol, partial::Partial2PokPedersenCommitment,
};
use short_group_sig::{
    weak_bb_sig::SecretKey,
    weak_bb_sig_pok_kv::{PoKOfSignatureG1KV, PoKOfSignatureG1KVProtocol},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetMembershipCheckWithKVProtocol<G: AffineRepr> {
    pub pok_sig: PoKOfSignatureG1KVProtocol<G>,
    pub sc: PokPedersenCommitmentProtocol<G>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckWithKVProof<G: AffineRepr> {
    pub pok_sig: PoKOfSignatureG1KV<G>,
    pub sc: Partial2PokPedersenCommitment<G>,
}

impl<G: AffineRepr> SetMembershipCheckWithKVProtocol<G> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        member: G::ScalarField,
        r: G::ScalarField,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
    ) -> Result<Self, SmcRangeProofError> {
        let sig = params.get_sig_for_member(&member)?;
        let blinding = G::ScalarField::rand(rng);
        let m = G::ScalarField::rand(rng);
        let pok_sig = PoKOfSignatureG1KVProtocol::init(
            rng,
            sig,
            member,
            Some(blinding),
            &params.bb_sig_params,
        );
        let sc =
            PokPedersenCommitmentProtocol::init(member, blinding, &comm_key.g, r, m, &comm_key.h);
        Ok(Self { pok_sig, sc })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.pok_sig
            .challenge_contribution(&params.bb_sig_params, &mut writer)?;
        self.sc
            .challenge_contribution(&comm_key.g, &comm_key.h, commitment, writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &G::ScalarField) -> SetMembershipCheckWithKVProof<G> {
        SetMembershipCheckWithKVProof {
            pok_sig: self.pok_sig.gen_proof(challenge),
            sc: self.sc.gen_partial2_proof(challenge),
        }
    }
}

impl<G: AffineRepr> SetMembershipCheckWithKVProof<G> {
    pub fn verify(
        &self,
        commitment: &G,
        challenge: &G::ScalarField,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        secret_key: &SecretKey<G::ScalarField>,
    ) -> Result<(), SmcRangeProofError> {
        // Check commitment * challenge + g * z_sigma + h * z_r == D
        self.pok_sig
            .verify(challenge, secret_key, &params.bb_sig_params)?;
        if !self.sc.verify(
            commitment,
            &comm_key.g,
            &comm_key.h,
            challenge,
            self.pok_sig.get_resp_for_message().unwrap(),
        ) {
            return Err(SmcRangeProofError::InvalidSetMembershipProof);
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        commitment: &G,
        comm_key: &MemberCommitmentKey<G>,
        params: &SetMembershipCheckParamsKV<G>,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.pok_sig
            .challenge_contribution(&params.bb_sig_params, &mut writer)?;
        self.sc
            .challenge_contribution(&comm_key.g, &comm_key.h, commitment, writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::misc::n_rand;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn membership_check() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let set_size = 10;

        let set = n_rand(&mut rng, set_size).collect::<Vec<Fr>>();
        let (params, sk) = SetMembershipCheckParamsKV::<G1Affine>::new::<_, Blake2b512>(
            &mut rng,
            b"test",
            set.clone(),
        );

        let comm_key = MemberCommitmentKey::generate_using_rng(&mut rng);
        let member = set[3].clone();
        let randomness = Fr::rand(&mut rng);
        let commitment = comm_key.commit(&member, &randomness);

        let protocol = SetMembershipCheckWithKVProtocol::init(
            &mut rng, member, randomness, &comm_key, &params,
        )
        .unwrap();

        let mut chal_bytes_prover = vec![];
        protocol
            .challenge_contribution(&commitment, &comm_key, &params, &mut chal_bytes_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

        let proof = protocol.gen_proof(&challenge_prover);

        let mut chal_bytes_verifier = vec![];
        proof
            .challenge_contribution(&commitment, &comm_key, &params, &mut chal_bytes_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        proof
            .verify(&commitment, &challenge_verifier, &comm_key, &params, &sk)
            .unwrap();
    }
}
