//! Semi-honest protocol for distributed discrete log check

use crate::{
    common,
    common::{Share, ShareId},
    error::SSError,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Commitment to the share of the secret
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ShareCommitment<G: AffineRepr> {
    pub id: ShareId,
    #[serde_as(as = "ArkObjectBytes")]
    pub commitment: G,
}

/// Share of the computation, i.e. scalar multiplication operation in the group
#[serde_as]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ComputationShare<G: AffineRepr> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[serde_as(as = "ArkObjectBytes")]
    pub share: G,
}

/// Proof that the computation on the share was done correctly
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ComputationShareProof<G: AffineRepr> {
    pub id: ShareId,
    pub sc_share: PokDiscreteLog<G>,
    pub sc_comm: PokDiscreteLog<G>,
}

impl<G: AffineRepr> ComputationShare<G> {
    /// Create a share of the computation. The shares will later be combined with other shares
    /// to get the result.
    pub fn new(share: &Share<G::ScalarField>, base: &G) -> Self {
        Self {
            id: share.id,
            threshold: share.threshold,
            share: (*base * share.share).into_affine(),
        }
    }

    /// Create a share of the computation and the proof that the computation was done correctly.
    /// The shares will later be combined with other shares to get the result.
    pub fn new_with_proof<'a, R: RngCore, D: Digest>(
        rng: &mut R,
        share: &Share<G::ScalarField>,
        share_commitment: &ShareCommitment<G>,
        share_comm_ck: impl Into<&'a G>,
        base: &G,
    ) -> (Self, ComputationShareProof<G>) {
        let cs = Self::new(share, base);
        let share_comm_ck = share_comm_ck.into();
        let share_blinding = G::ScalarField::rand(rng);
        let sc_share = PokDiscreteLogProtocol::init(share.share, share_blinding, base);
        let sc_comm = PokDiscreteLogProtocol::init(share.share, share_blinding, share_comm_ck);
        let mut challenge_bytes = vec![];
        sc_share
            .challenge_contribution(base, &cs.share, &mut challenge_bytes)
            .unwrap();
        sc_comm
            .challenge_contribution(
                share_comm_ck,
                &share_commitment.commitment,
                &mut challenge_bytes,
            )
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let sc_share = sc_share.gen_proof(&challenge);
        let sc_comm = sc_comm.gen_proof(&challenge);
        let proof = ComputationShareProof {
            id: cs.id,
            sc_share,
            sc_comm,
        };
        (cs, proof)
    }

    /// Combine shares to get the result
    /// Assumes all shares have unique ids and same threshold
    pub fn combine(shares: Vec<ComputationShare<G>>) -> Result<G, SSError> {
        let threshold = shares[0].threshold;
        let len = shares.len() as ShareId;
        if threshold > len {
            return Err(SSError::BelowThreshold(threshold, len));
        }
        let share_ids = shares[0..threshold as usize]
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>();
        let basis = common::lagrange_basis_at_0_for_all::<G::ScalarField>(share_ids)?;
        let shares = &shares[0..threshold as usize]
            .iter()
            .map(|s| s.share)
            .collect::<Vec<_>>();
        Ok(G::Group::msm_unchecked(&shares, &basis).into_affine())
    }
}

impl<G: AffineRepr> ShareCommitment<G> {
    pub fn new<'a>(share: &Share<G::ScalarField>, ck: impl Into<&'a G>) -> Self {
        Self {
            id: share.id,
            commitment: (*ck.into() * share.share).into_affine(),
        }
    }
}

impl<G: AffineRepr> ComputationShareProof<G> {
    pub fn verify<'a, D: Digest>(
        &self,
        share: &ComputationShare<G>,
        share_commitment: &ShareCommitment<G>,
        share_comm_ck: impl Into<&'a G>,
        base: &G,
    ) -> Result<(), SSError> {
        let share_comm_ck = share_comm_ck.into();
        let challenge = Self::pre_verify::<D>(&self, share, share_commitment, share_comm_ck, base)?;
        if !self.sc_share.verify(&share.share, base, &challenge) {
            return Err(SSError::InvalidComputationShareProof(self.id));
        }
        if !self
            .sc_comm
            .verify(&share_commitment.commitment, share_comm_ck, &challenge)
        {
            return Err(SSError::InvalidComputationShareProof(self.id));
        }
        Ok(())
    }

    pub fn verify_many<'a, D: Digest>(
        _proofs: &[Self],
        _shares: &[ComputationShare<G>],
        _share_commitments: &[ShareCommitment<G>],
        _share_comm_ck: impl Into<&'a G>,
        _base: &G,
    ) -> Result<(), SSError> {
        // TODO: This can be implemented using a multi-scalar multiplication (MSM).
        // Say we want to verify 2 Schnorr proofs with `t_{0, 1}` being the random commitment in step1, `c` being the challenge,
        // `s_{0, 1}` being the response in step 3. Now we want to prove
        // `base * s1 - y1 * c = t1`
        // `base * s2 - y2 * c = t2`
        // The verifier can pick a random `r` and instead prove
        // `base * s1 - y1 * c + (base * s2 - y2 * c) * r = t1 + t2 * r` which can be done with a single MSM
        todo!()
    }

    fn pre_verify<D: Digest>(
        proof: &Self,
        share: &ComputationShare<G>,
        share_commitment: &ShareCommitment<G>,
        share_comm_ck: &G,
        base: &G,
    ) -> Result<G::ScalarField, SSError> {
        if share_commitment.id != share.id {
            return Err(
                SSError::IdMismatchInComputationShareShareAndShareCommitment(
                    share_commitment.id,
                    share.id,
                ),
            );
        }
        if proof.id != share.id {
            return Err(SSError::IdMismatchInComputationShareAndItsProof(
                proof.id, share.id,
            ));
        }
        if proof.sc_share.response != proof.sc_comm.response {
            return Err(SSError::InvalidComputationShareProof(proof.id));
        }
        let mut challenge_bytes = vec![];
        proof
            .sc_share
            .challenge_contribution(base, &share.share, &mut challenge_bytes)
            .unwrap();
        proof
            .sc_comm
            .challenge_contribution(
                share_comm_ck,
                &share_commitment.commitment,
                &mut challenge_bytes,
            )
            .unwrap();
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        Ok(challenge)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::feldman_vss::deal_secret;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        One, UniformRand,
    };
    use blake2::Blake2b512;
    use test_utils::test_serialization;

    #[test]
    fn compute() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Affine::rand(&mut rng);
        let g2 = G2Affine::rand(&mut rng);

        fn check<G: AffineRepr>(rng: &mut StdRng, ck: &G) {
            let base = G::rand(rng);
            let share_comm_ck = G::rand(rng);
            let mut checked_serialization = false;
            for (threshold, total) in vec![
                (2, 2),
                (2, 3),
                (2, 4),
                (2, 5),
                (3, 3),
                (3, 4),
                (3, 5),
                (4, 5),
                (4, 8),
                (4, 9),
                (4, 12),
                (5, 5),
                (5, 7),
                (5, 10),
                (5, 13),
                (7, 10),
                (7, 15),
            ] {
                let secret = G::ScalarField::rand(rng);
                let (shares, commitments, _) =
                    deal_secret::<_, G>(rng, secret, threshold as ShareId, total as ShareId, ck)
                        .unwrap();

                for share in &shares.0 {
                    // Wrong share fails to verify
                    let mut wrong_share = share.clone();
                    wrong_share.share += G::ScalarField::one();
                    assert!(wrong_share.verify(&commitments, ck).is_err());

                    // Correct share verifies
                    share.verify(&commitments, ck).unwrap();
                }

                assert_eq!(shares.reconstruct_secret().unwrap(), secret);
                let expected_result = (base * secret).into_affine();

                let computation_shares = shares
                    .0
                    .iter()
                    .map(|s| ComputationShare::new(s, &base))
                    .collect::<Vec<_>>();

                if !checked_serialization {
                    test_serialization!(ComputationShare<G>, computation_shares[0]);
                }

                let result = ComputationShare::combine(computation_shares.clone()).unwrap();
                assert_eq!(result, expected_result);

                let share_comms = shares
                    .0
                    .iter()
                    .map(|s| ShareCommitment::new(s, &share_comm_ck))
                    .collect::<Vec<_>>();
                let computation_shares_with_proof = shares
                    .0
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        ComputationShare::new_with_proof::<_, Blake2b512>(
                            rng,
                            s,
                            &share_comms[i],
                            &share_comm_ck,
                            &base,
                        )
                    })
                    .collect::<Vec<_>>();

                for (i, (share, proof)) in computation_shares_with_proof.into_iter().enumerate() {
                    assert_eq!(share, computation_shares[i]);
                    proof
                        .verify::<Blake2b512>(&share, &share_comms[i], &share_comm_ck, &base)
                        .unwrap();
                    if i == 1 {
                        // Verification with incorrect commitment to the secret share fails
                        assert!(proof
                            .verify::<Blake2b512>(
                                &share,
                                &share_comms[i - 1],
                                &share_comm_ck,
                                &base
                            )
                            .is_err());

                        // Verification with incorrect secret share fails
                        assert!(proof
                            .verify::<Blake2b512>(
                                &computation_shares[0],
                                &share_comms[i],
                                &share_comm_ck,
                                &base
                            )
                            .is_err());

                        // if !checked_serialization {
                        //     test_serialization!(ComputationShareProof<G>, proof);
                        //     test_serialization!(ShareCommitment<G>, share_comms[i]);
                        // }
                    }
                }
                checked_serialization = true;
            }
        }

        check(&mut rng, &g1);
        check(&mut rng, &g2);
    }
}
