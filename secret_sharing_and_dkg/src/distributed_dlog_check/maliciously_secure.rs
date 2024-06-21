//! Maliciously secure protocol for distributed discrete log check

use crate::{
    common,
    common::{CommitmentToCoefficients, ShareId},
    error::SSError,
    feldman_vss::deal_secret,
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{
    expect_equality, ff::powers, msm::WindowTable, pair_g1_g2, pair_g2_g1,
    randomized_pairing_check::RandomizedPairingChecker, serde_utils::ArkObjectBytes,
};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log_pairing::{
        PokG1DiscreteLogInPairing, PokG1DiscreteLogInPairingProtocol, PokG2DiscreteLogInPairing,
        PokG2DiscreteLogInPairingProtocol,
    },
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

macro_rules! impl_protocol {
    (
            $(#[$protocol_doc:meta])*
            $secret_share: ident, $secret_share_comm: ident, $computation_share: ident, $computation_share_proof: ident, $deal_secret: ident, $discrete_log_protocol: ident, $discrete_log_proof: ident, $secret_group: ty, $other_group: ty, $pairing: tt) => {

        $(#[$protocol_doc])*
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
        pub struct $secret_share<E: Pairing> {
            #[zeroize(skip)]
            pub id: ShareId,
            #[zeroize(skip)]
            pub threshold: ShareId,
            #[serde_as(as = "ArkObjectBytes")]
            pub share: $secret_group,
        }

        /// Commitment to the share of the secret
        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct $secret_share_comm<E: Pairing> {
            pub id: ShareId,
            #[serde_as(as = "ArkObjectBytes")]
            pub commitment: PairingOutput<E>,
        }

        /// Share of the computation, i.e. result of the pairing
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
        pub struct $computation_share<E: Pairing> {
            #[zeroize(skip)]
            pub id: ShareId,
            #[zeroize(skip)]
            pub threshold: ShareId,
            #[serde_as(as = "ArkObjectBytes")]
            pub share: PairingOutput<E>,
        }

        /// Proof that the computation on the share was done correctly
        #[serde_as]
        #[derive(
            Default,
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct $computation_share_proof<E: Pairing> {
            pub id: ShareId,
            pub sc_share: $discrete_log_proof<E>,
            pub sc_comm: $discrete_log_proof<E>,
        }

        impl<E: Pairing> $secret_share<E> {
            pub fn verify<'a>(
                &self,
                commitment_coeffs: &CommitmentToCoefficients<$other_group>,
                ck_secret: impl Into<&'a $secret_group>,
                ck_poly: impl Into<&'a $other_group>,
            ) -> Result<(), SSError> {
                let len = commitment_coeffs.0.len() as ShareId;
                if self.threshold > len {
                    return Err(SSError::BelowThreshold(self.threshold, len));
                }
                let powers = powers(&E::ScalarField::from(self.id as u64), self.threshold as u32);
                if !self
                    .pairing_check(commitment_coeffs, powers, ck_secret, ck_poly)
                    .is_zero()
                {
                    return Err(SSError::InvalidShare);
                }
                Ok(())
            }
        }

        impl<E: Pairing> $secret_share_comm<E> {
            pub fn new(share: &$secret_share<E>, ck: &$other_group) -> Self {
                Self {
                    id: share.id,
                    commitment: $pairing!(E::pairing, ck, share.share),
                }
            }
        }

        impl<E: Pairing> $computation_share<E> {
            /// Create a share of the computation. The shares will later be combined with other shares
            /// to get the result.
            pub fn new(share: &$secret_share<E>, base: &$other_group) -> Self {
                Self {
                    id: share.id,
                    threshold: share.threshold,
                    share: $pairing!(E::pairing, base, share.share),
                }
            }

            /// Create a share of the computation and the proof that the computation was done correctly.
            /// The shares will later be combined with other shares to get the result.
            pub fn new_with_proof<R: RngCore, D: Digest>(
                rng: &mut R,
                share: &$secret_share<E>,
                share_commitment: &$secret_share_comm<E>,
                share_comm_ck: &$other_group,
                base: &$other_group,
            ) -> (Self, $computation_share_proof<E>) {
                let cs = Self::new(share, base);
                let share_blinding = <$secret_group as UniformRand>::rand(rng);
                let sc_share = $discrete_log_protocol::init(share.share, share_blinding, base);
                let sc_comm =
                    $discrete_log_protocol::init(share.share, share_blinding, share_comm_ck);
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
                let challenge =
                    compute_random_oracle_challenge::<E::ScalarField, D>(&challenge_bytes);
                let sc_share = sc_share.gen_proof(&challenge);
                let sc_comm = sc_comm.gen_proof(&challenge);
                let proof = $computation_share_proof {
                    id: share.id,
                    sc_share,
                    sc_comm,
                };
                (cs, proof)
            }

            /// Combine shares to get the result
            /// Assumes all shares have unique ids and same threshold
            pub fn combine(shares: Vec<Self>) -> Result<PairingOutput<E>, SSError> {
                let threshold = shares[0].threshold;
                let len = shares.len() as ShareId;
                if threshold > len {
                    return Err(SSError::BelowThreshold(threshold, len));
                }
                let share_ids = shares[0..threshold as usize]
                    .iter()
                    .map(|s| s.id)
                    .collect::<Vec<_>>();
                let basis = common::lagrange_basis_at_0_for_all::<E::ScalarField>(share_ids)?;
                Ok(cfg_into_iter!(basis).zip(cfg_into_iter!(shares)).map(|(b, s)| s.share * b).sum::<PairingOutput<E>>())
            }
        }

        impl<E: Pairing> $computation_share_proof<E> {
            /// Verify a single proof of the share of the computation
            pub fn verify<D: Digest>(
                &self,
                share: &$computation_share<E>,
                share_commitment: &$secret_share_comm<E>,
                share_comm_ck: &$other_group,
                base: &$other_group,
            ) -> Result<(), SSError> {
                let challenge =
                    Self::pre_verify::<D>(&self, share, share_commitment, share_comm_ck, base)?;
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

            /// Verify a batch of proofs of the shares of the computation. This is less expensive than
            /// verifying each proof one by one.
            pub fn verify_many<D: Digest>(
                proofs: &[Self],
                shares: &[$computation_share<E>],
                share_commitments: &[$secret_share_comm<E>],
                share_comm_ck: &$other_group,
                base: &$other_group,
                pairing_checker: &mut RandomizedPairingChecker<E>,
            ) -> Result<(), SSError> {
                expect_equality!(
                    proofs.len(),
                    shares.len(),
                    SSError::UnequalNoOfProofsAndShares
                );
                expect_equality!(
                    proofs.len(),
                    share_commitments.len(),
                    SSError::UnequalNoOfProofsAndCommitments
                );
                for i in 0..proofs.len() {
                    let proof = &proofs[i];
                    let share = &shares[i];
                    let share_commitment = &share_commitments[i];
                    let challenge =
                        Self::pre_verify::<D>(proof, share, share_commitment, share_comm_ck, base)?;
                    proof.sc_share.verify_with_randomized_pairing_checker(
                        &share.share,
                        base,
                        &challenge,
                        pairing_checker,
                    );
                    proof.sc_comm.verify_with_randomized_pairing_checker(
                        &share_commitment.commitment,
                        share_comm_ck,
                        &challenge,
                        pairing_checker,
                    );
                }
                Ok(())
            }

            fn pre_verify<D: Digest>(
                proof: &Self,
                share: &$computation_share<E>,
                share_commitment: &$secret_share_comm<E>,
                share_comm_ck: &$other_group,
                base: &$other_group,
            ) -> Result<E::ScalarField, SSError> {
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
                let challenge =
                    compute_random_oracle_challenge::<E::ScalarField, D>(&challenge_bytes);
                Ok(challenge)
            }
        }

        /// Generate shares of the given secret and return the scalar multiplication of the share and commitment
        /// key and thus returning a commitment to the share of the form `comm_key * share`.
        /// At least `threshold` number of share-commitment are needed to reconstruct the commitment to secret.
        /// Returns the share-commitments, commitments to coefficients of the polynomials for
        /// the secret and the polynomial
        pub fn $deal_secret<'a, R: RngCore, E: Pairing>(
            rng: &mut R,
            secret: E::ScalarField,
            threshold: ShareId,
            total: ShareId,
            ck_secret: impl Into<&'a $secret_group>,
            ck_poly: impl Into<&'a $other_group>,
        ) -> Result<
            (
                Vec<$secret_share<E>>,
                CommitmentToCoefficients<$other_group>,
                DensePolynomial<E::ScalarField>,
            ),
            SSError,
        > {
            let (shares, comm, poly) =
                deal_secret::<R, $other_group>(rng, secret, threshold, total, ck_poly)?;
            let ck_secret = ck_secret.into();
            let table = WindowTable::new(shares.0.len(), ck_secret.into_group());
            let shares = cfg_into_iter!(shares.0)
                .map(|s| $secret_share {
                    id: s.id,
                    threshold: s.threshold,
                    share: table.multiply(&s.share).into_affine(),
                })
                .collect::<Vec<_>>();
            Ok((shares, comm, poly))
        }
    };
}

type G1Af<E: Pairing> = E::G1Affine;
type G2Af<E: Pairing> = E::G2Affine;

impl_protocol!(
    /// Share of the secret when the elements to check the discrete log relation are in group G1
    SecretShareG1,
    SecretShareG1Commitment,
    ComputationShareG1,
    ComputationShareG1Proof,
    deal_secret_in_g1,
    PokG1DiscreteLogInPairingProtocol,
    PokG1DiscreteLogInPairing,
    G1Af<E>,
    G2Af<E>,
    pair_g2_g1
);

impl_protocol!(
    /// Share of the secret when the elements to check the discrete log relation are in group G2
    SecretShareG2,
    SecretShareG2Commitment,
    ComputationShareG2,
    ComputationShareG2Proof,
    deal_secret_in_g2,
    PokG2DiscreteLogInPairingProtocol,
    PokG2DiscreteLogInPairing,
    G2Af<E>,
    G1Af<E>,
    pair_g1_g2
);

impl<E: Pairing> SecretShareG2<E> {
    fn pairing_check<'a>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<E::G1Affine>,
        powers: Vec<E::ScalarField>,
        ck_secret: impl Into<&'a E::G2Affine>,
        ck_poly: impl Into<&'a E::G1Affine>,
    ) -> PairingOutput<E> {
        E::multi_pairing(
            [
                E::G1Prepared::from(ck_poly.into()),
                E::G1Prepared::from(E::G1::msm_unchecked(&commitment_coeffs.0, &powers).neg()),
            ],
            [
                E::G2Prepared::from(self.share),
                E::G2Prepared::from(ck_secret.into()),
            ],
        )
    }
}

impl<E: Pairing> SecretShareG1<E> {
    fn pairing_check<'a>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<E::G2Affine>,
        powers: Vec<E::ScalarField>,
        ck_secret: impl Into<&'a E::G1Affine>,
        ck_poly: impl Into<&'a E::G2Affine>,
    ) -> PairingOutput<E> {
        E::multi_pairing(
            [
                E::G1Prepared::from(self.share),
                E::G1Prepared::from(ck_secret.into()),
            ],
            [
                E::G2Prepared::from(ck_poly.into()),
                E::G2Prepared::from(E::G2::msm_unchecked(&commitment_coeffs.0, &powers).neg()),
            ],
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::{Duration, Instant};
    use test_utils::test_serialization;

    #[test]
    fn compute() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let ck_poly_g1 = G1Affine::rand(&mut rng);
        let ck_secret_g1 = G1Affine::rand(&mut rng);
        let ck_poly_g2 = G2Affine::rand(&mut rng);
        let ck_secret_g2 = G2Affine::rand(&mut rng);

        macro_rules! check {
            ($secret_share: ident, $secret_share_comm: ident, $comp_share: ident, $comp_share_proof: ident, $deal_func: ident, $secret_group: ident, $other_group: ident, $pairing: tt, $ck_secret: expr, $ck_poly: expr) => {
                let base = $other_group::rand(&mut rng);
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
                    let secret = Fr::rand(&mut rng);
                    let expected_result = $pairing!(Bls12_381::pairing, base, *$ck_secret * secret);

                    let (shares, commitments, _) =
                        $deal_func(&mut rng, secret, threshold, total, $ck_secret, $ck_poly).unwrap();

                    if !checked_serialization {
                     test_serialization!($secret_share<Bls12_381>, shares[0]);
                    }

                    for share in &shares {
                        // Wrong share fails to verify
                        let mut wrong_share = share.clone();
                        wrong_share.share =
                            (wrong_share.share * Fr::rand(&mut rng)).into_affine() as $secret_group;
                        assert!(wrong_share
                            .verify(&commitments, $ck_secret, $ck_poly)
                            .is_err());

                        // Correct share verifies
                        share.verify(&commitments, $ck_secret, $ck_poly).unwrap();
                    }

                    let computation_shares = cfg_into_iter!(shares.clone())
                        .map(|s| $comp_share::new(&s, &base))
                        .collect::<Vec<_>>();

                    if !checked_serialization {
                     test_serialization!($comp_share<Bls12_381>, computation_shares[0]);
                    }

                    let result = $comp_share::combine(computation_shares.clone()).unwrap();
                    assert_eq!(result, expected_result);

                    let share_comm_ck = $other_group::rand(&mut rng);
                    let share_comms = shares
                        .iter()
                        .map(|s| $secret_share_comm::new(s, &share_comm_ck))
                        .collect::<Vec<_>>();
                    let computation_shares_with_proof = shares
                        .iter()
                        .enumerate()
                        .map(|(i, s)| {
                            $comp_share::new_with_proof::<_, Blake2b512>(
                                &mut rng,
                                s,
                                &share_comms[i],
                                &share_comm_ck,
                                &base,
                            )
                        })
                        .collect::<Vec<_>>();

                    let mut shares = vec![];
                    let mut proofs = vec![];
                    let mut time_one_by_one = Duration::default();
                    for (i, (share, proof)) in computation_shares_with_proof.into_iter().enumerate() {
                        assert_eq!(share, computation_shares[i]);
                        let start = Instant::now();
                        proof
                            .verify::<Blake2b512>(&share, &share_comms[i], &share_comm_ck, &base)
                            .unwrap();
                        time_one_by_one += start.elapsed();

                        // Check some invalid conditions - not checking for all shares and proofs but just one
                        if i == 1 {
                            // Verification with incorrect commitment to the secret share fails
                            assert!(proof.verify::<Blake2b512>(&share, &share_comms[i-1], &share_comm_ck, &base).is_err());

                            // Verification with incorrect secret share fails
                            assert!(proof.verify::<Blake2b512>(&shares[0], &share_comms[i], &share_comm_ck, &base).is_err());

                            // if !checked_serialization {
                            //  test_serialization!($comp_share_proof<Bls12_381>, proof);
                            //  test_serialization!($secret_share_comm<Bls12_381>, share_comms[i]);
                            // }
                        }

                        shares.push(share);
                        proofs.push(proof);
                    }

                    println!(
                        "Time to verify {} proofs one by one: {:?}",
                        proofs.len(),
                        time_one_by_one
                    );

                    for lazy in [true, false] {
                        let mut checker = RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
                        let start = Instant::now();
                        $comp_share_proof::verify_many::<Blake2b512>(
                            &proofs,
                            &shares,
                            &share_comms,
                            &share_comm_ck,
                            &base,
                            &mut checker,
                        )
                        .unwrap();
                        println!("Time to verify {} proofs using randomized pairing checker with lazy={}: {:?}", proofs.len(), lazy, start.elapsed());
                        assert!(checker.verify());
                    }

                    checked_serialization = true;
                }
            }
        }

        check!(
            SecretShareG1,
            SecretShareG1Commitment,
            ComputationShareG1,
            ComputationShareG1Proof,
            deal_secret_in_g1,
            G1Affine,
            G2Affine,
            pair_g2_g1,
            &ck_secret_g1,
            &ck_poly_g2
        );

        check!(
            SecretShareG2,
            SecretShareG2Commitment,
            ComputationShareG2,
            ComputationShareG2Proof,
            deal_secret_in_g2,
            G2Affine,
            G1Affine,
            pair_g1_g2,
            &ck_secret_g2,
            &ck_poly_g1
        );
    }
}
