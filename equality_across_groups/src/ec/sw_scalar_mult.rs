//! Proof of scalar multiplication on short Weierstrass curve. The protocol, called CDLSD, is described in section 4.2, construction 4.1 of the paper [CDLS: Proving Knowledge of Committed Discrete Logarithms with Soundness](https://eprint.iacr.org/2023/1595)
//!
//! The protocol proves that for committed curve point `S` and committed scalar `omega` and public curve point `R`, `S = R * omega`.
//! The verifier only has commitments to `S`'s coordinates `x` and `y` and `omega` but knows `R`.
//!
//! The idea is the prover generates a random point say `J = R * alpha` and the point `K` such that `K = (alpha - omega) * R`
//! Now it proves using the protocol of point addition that sum of points `S` and `K` is point `J` and it knows
//! the opening of these points. `alpha` is chosen to not be either of `(0, omega, 2*omega)` to avoid point doubling or points
//! at infinity in point addition protocol. The prover repeats this protocol several times as per the security parameter of the protocol
//!

use crate::{
    ec::{
        commitments::{
            point_coords_as_scalar_field_elements, CommitmentWithOpening, PointCommitment,
            PointCommitmentWithOpening,
        },
        sw_point_addition::{PointAdditionProof, PointAdditionProtocol},
    },
    error::Error,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, io::Write, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, msm::WindowTable,
    randomized_mult_checker::RandomizedMultChecker,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Protocol for proving scalar multiplication with committed point and committed scalar.
/// `P` is the curve where the points live and `C` is the curve where commitments (to their coordinates) live.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScalarMultiplicationProtocol<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize = 128> {
    /// The scalar
    pub omega: P::ScalarField,
    /// Randomness in the commitment to the scalar
    pub omega_rand: P::ScalarField,
    sub_protocols: Vec<ScalarMultiplicationProtocolSingleRep<P, C>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScalarMultiplicationProtocolSingleRep<P: AffineRepr, C: AffineRepr> {
    /// Commitment to `alpha`
    pub comm_alpha: CommitmentWithOpening<P>,
    /// Commitment to the point `alpha * R`
    pub comm_alpha_point: PointCommitmentWithOpening<C>,
    /// Commitment to the point `(alpha - omega) * R`
    pub comm_alpha_minus_omega_point: PointCommitmentWithOpening<C>,
    pub add: PointAdditionProtocol<P, C>,
}

/// Proof of scalar multiplication with committed point and committed scalar.
/// `P` is the curve where the points live and `C` is the curve where commitments (to their coordinates) live.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScalarMultiplicationProof<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize = 128>(
    Vec<ScalarMultiplicationProofSingleRep<P, C>>,
);

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScalarMultiplicationProofSingleRep<P: AffineRepr, C: AffineRepr> {
    /// Commitment to `alpha`
    pub comm_alpha: P,
    /// Commitment to the point `alpha * R`
    pub comm_alpha_point: PointCommitment<C>,
    /// Commitment to the point `(alpha - omega) * R`
    pub comm_alpha_minus_omega_point: PointCommitment<C>,
    pub add: PointAdditionProof<P, C>,
    pub z1: P::ScalarField,
    pub z2: P::ScalarField,
    pub z3: C::ScalarField,
    pub z4: C::ScalarField,
}

impl<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize>
    ScalarMultiplicationProtocol<P, C, NUM_REPS>
{
    /// For proving `base * scalar = result` where `comm_scalar` and `comm_result` are commitments to `scalar`
    /// and `result` respectively
    pub fn init<R: RngCore>(
        rng: &mut R,
        comm_scalar: CommitmentWithOpening<P>,
        comm_result: PointCommitmentWithOpening<C>,
        result: P,
        base: P,
        comm_key_1: &PedersenCommitmentKey<P>,
        comm_key_2: &PedersenCommitmentKey<C>,
    ) -> Result<Self, Error> {
        let mut protocols = Vec::with_capacity(NUM_REPS);
        let twice_omega = comm_scalar.value.double();
        // Ensure that alpha is neither 0 nor omega (the scalar) nor 2*omega to avoid point doubling or points at infinity in point addition protocol
        let mut alpha = Vec::with_capacity(NUM_REPS);
        while alpha.len() < NUM_REPS {
            let alpha_i = P::ScalarField::rand(rng);
            if alpha_i.is_zero() || alpha_i == comm_scalar.value || alpha_i == twice_omega {
                continue;
            } else {
                alpha.push(alpha_i);
            }
        }

        // Randomness for the commitments to alpha and the points
        let beta_1 = (0..NUM_REPS)
            .map(|_| P::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let beta_2 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let beta_3 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let beta_4 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let beta_5 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let base_table = WindowTable::new(NUM_REPS, base.into_group());
        // Points base * alpha_i
        let alpha_point = base_table.multiply_many(&alpha);
        // Point base * - omega
        let minus_omega_point = result.into_group().neg();
        // Points base * (alpha_i - omega)
        let alpha_minus_omega_point = cfg_iter!(alpha_point)
            .map(|a| minus_omega_point + a)
            .collect::<Vec<_>>();

        let alpha_point = P::Group::normalize_batch(&alpha_point);
        let alpha_minus_omega_point = P::Group::normalize_batch(&alpha_minus_omega_point);

        // Commit to alpha_i
        let mut comm_alpha = cfg_into_iter!(0..NUM_REPS)
            .map(|i| CommitmentWithOpening::new_given_randomness(alpha[i], beta_1[i], comm_key_1))
            .collect::<Vec<_>>();

        // Commit to base * alpha_i
        let comm_alpha_point_ = cfg_into_iter!(0..NUM_REPS)
            .map(|i| {
                PointCommitmentWithOpening::<C>::new_given_randomness::<P>(
                    &alpha_point[i],
                    beta_2[i],
                    beta_3[i],
                    comm_key_2,
                )
            })
            .collect::<Vec<_>>();
        let mut comm_alpha_point = Vec::with_capacity(NUM_REPS);
        for c in comm_alpha_point_ {
            comm_alpha_point.push(c?);
        }

        // Commit to base * (alpha_i - omega)
        let comm_alpha_minus_omega_point_ = cfg_into_iter!(0..NUM_REPS)
            .map(|i| {
                PointCommitmentWithOpening::<C>::new_given_randomness::<P>(
                    &alpha_minus_omega_point[i],
                    beta_4[i],
                    beta_5[i],
                    comm_key_2,
                )
            })
            .collect::<Vec<_>>();
        let mut comm_alpha_minus_omega_point = Vec::with_capacity(NUM_REPS);
        for c in comm_alpha_minus_omega_point_ {
            comm_alpha_minus_omega_point.push(c?);
        }

        // Following can be parallelized if PointAdditionProtocol and its sub-protocols accept randomness
        for i in 0..NUM_REPS {
            let add = PointAdditionProtocol::<P, C>::init(
                rng,
                comm_result.clone(),
                comm_alpha_minus_omega_point[0].clone(), // using index 0 because these are mutated below
                comm_alpha_point[0].clone(), // using index 0 because these are mutated below
                result,
                alpha_minus_omega_point[i],
                alpha_point[i],
                comm_key_2,
            )?;
            protocols.push(ScalarMultiplicationProtocolSingleRep {
                comm_alpha: comm_alpha.remove(0),
                comm_alpha_point: comm_alpha_point.remove(0),
                comm_alpha_minus_omega_point: comm_alpha_minus_omega_point.remove(0),
                add,
            });
        }
        Ok(Self {
            omega: comm_scalar.value,
            omega_rand: comm_scalar.randomness,
            sub_protocols: protocols,
        })
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        for i in 0..NUM_REPS {
            self.sub_protocols[i]
                .comm_alpha
                .comm
                .serialize_compressed(&mut writer)?;
            self.sub_protocols[i]
                .comm_alpha_point
                .comm
                .serialize_compressed(&mut writer)?;
            self.sub_protocols[i]
                .comm_alpha_minus_omega_point
                .comm
                .serialize_compressed(&mut writer)?;
            self.sub_protocols[i]
                .add
                .challenge_contribution(&mut writer)?;
        }
        Ok(())
    }

    pub fn gen_proof(self, challenge: &[u8]) -> ScalarMultiplicationProof<P, C, NUM_REPS> {
        // This assert should generally pass but can be avoided by enlarging the given challenge with an XOF
        assert!((challenge.len() * 8) >= NUM_REPS);
        let one = C::ScalarField::one();
        let minus_one = one.neg();
        let proofs = cfg_into_iter!(self.sub_protocols)
            .enumerate()
            .map(|(i, p)| {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                let c = (challenge[byte_idx] >> bit_idx) & 1;
                // If c = 0, send opening of point alpha * base else send opening of (alpha-omega) * base
                // If c = 0, the point addition protocol gets a challenge value of "-1" else it gets the value "1"
                if c == 0 {
                    ScalarMultiplicationProofSingleRep {
                        comm_alpha: p.comm_alpha.comm,
                        comm_alpha_point: p.comm_alpha_point.comm,
                        comm_alpha_minus_omega_point: p.comm_alpha_minus_omega_point.comm,
                        add: p.add.gen_proof(&minus_one),
                        z1: p.comm_alpha.value,
                        z2: p.comm_alpha.randomness,
                        z3: p.comm_alpha_point.r_x,
                        z4: p.comm_alpha_point.r_y,
                    }
                } else {
                    ScalarMultiplicationProofSingleRep {
                        comm_alpha: p.comm_alpha.comm,
                        comm_alpha_point: p.comm_alpha_point.comm,
                        comm_alpha_minus_omega_point: p.comm_alpha_minus_omega_point.comm,
                        add: p.add.gen_proof(&one),
                        z1: p.comm_alpha.value - self.omega,
                        z2: p.comm_alpha.randomness - self.omega_rand,
                        z3: p.comm_alpha_minus_omega_point.r_x,
                        z4: p.comm_alpha_minus_omega_point.r_y,
                    }
                }
            })
            .collect::<Vec<_>>();
        ScalarMultiplicationProof(proofs)
    }
}

impl<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize>
    ScalarMultiplicationProof<P, C, NUM_REPS>
{
    /// For verifying `base * scalar = result` where `comm_scalar` and `comm_result` are commitments to `scalar`
    /// and `result` respectively
    pub fn verify(
        &self,
        comm_scalar: &P,
        comm_result: &PointCommitment<C>,
        base: &P,
        challenge: &[u8],
        comm_key_1: &PedersenCommitmentKey<P>,
        comm_key_2: &PedersenCommitmentKey<C>,
    ) -> Result<(), Error> {
        if self.0.len() != NUM_REPS {
            return Err(Error::InsufficientNumberOfRepetitions(
                self.0.len(),
                NUM_REPS,
            ));
        }
        if (challenge.len() * 8) < NUM_REPS {
            return Err(Error::InsufficientChallengeSize(
                challenge.len() * 8,
                NUM_REPS,
            ));
        }
        let base_table = WindowTable::new(NUM_REPS, base.into_group());
        let one = C::ScalarField::one();
        let minus_one = one.neg();
        let comm_minus_scalar = comm_scalar.into_group().neg();
        // Following can be parallelized
        for i in 0..NUM_REPS {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let c = (challenge[byte_idx] >> bit_idx) & 1;
            let p = base_table.multiply(&self.0[i].z1).into_affine();
            let p_comm = PointCommitmentWithOpening::new_given_randomness(
                &p,
                self.0[i].z3,
                self.0[i].z4,
                comm_key_2,
            )?;
            // If c = 0, expect opening of point alpha * base else expect opening of (alpha-omega) * base
            // If c = 0, the point addition protocol gets a challenge value of "-1" else it gets the value "1"
            if c == 0 {
                if self.0[i].comm_alpha
                    != CommitmentWithOpening::new_given_randomness(
                        self.0[i].z1,
                        self.0[i].z2,
                        comm_key_1,
                    )
                    .comm
                {
                    return Err(Error::IncorrectScalarOpeningAtIndex(i));
                }
                if p_comm.comm != self.0[i].comm_alpha_point {
                    return Err(Error::IncorrectPointOpeningAtIndex(i));
                }
                self.0[i].add.verify(
                    comm_result,
                    &self.0[i].comm_alpha_minus_omega_point,
                    &self.0[i].comm_alpha_point,
                    &minus_one,
                    comm_key_2,
                )?;
            } else {
                if (self.0[i].comm_alpha + comm_minus_scalar).into_affine()
                    != CommitmentWithOpening::new_given_randomness(
                        self.0[i].z1,
                        self.0[i].z2,
                        comm_key_1,
                    )
                    .comm
                {
                    return Err(Error::IncorrectScalarOpeningAtIndex(i));
                }
                if p_comm.comm != self.0[i].comm_alpha_minus_omega_point {
                    return Err(Error::IncorrectPointOpeningAtIndex(i));
                }
                self.0[i].add.verify(
                    comm_result,
                    &self.0[i].comm_alpha_minus_omega_point,
                    &self.0[i].comm_alpha_point,
                    &one,
                    comm_key_2,
                )?;
            }
        }
        Ok(())
    }

    /// Same as `Self::verify` but delegated the scalar multiplication checks to `RandomizedMultChecker`
    pub fn verify_using_randomized_mult_checker(
        &self,
        comm_scalar: P,
        comm_result: PointCommitment<C>,
        base: P,
        challenge: &[u8],
        comm_key_1: PedersenCommitmentKey<P>,
        comm_key_2: PedersenCommitmentKey<C>,
        rmc_1: &mut RandomizedMultChecker<P>,
        rmc_2: &mut RandomizedMultChecker<C>,
    ) -> Result<(), Error> {
        if self.0.len() != NUM_REPS {
            return Err(Error::InsufficientNumberOfRepetitions(
                self.0.len(),
                NUM_REPS,
            ));
        }
        if (challenge.len() * 8) < NUM_REPS {
            return Err(Error::InsufficientChallengeSize(
                challenge.len() * 8,
                NUM_REPS,
            ));
        }
        let base_table = WindowTable::new(NUM_REPS, base.into_group());
        let one = C::ScalarField::one();
        let minus_one = one.neg();
        let comm_minus_scalar = comm_scalar.into_group().neg();
        for i in 0..NUM_REPS {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let c = (challenge[byte_idx] >> bit_idx) & 1;
            let p = base_table.multiply(&self.0[i].z1).into_affine();
            let (p_x, p_y) = point_coords_as_scalar_field_elements::<P, C>(&p)?;
            if c == 0 {
                rmc_1.add_2(
                    comm_key_1.g,
                    &self.0[i].z1,
                    comm_key_1.h,
                    &self.0[i].z2,
                    self.0[i].comm_alpha,
                );
                rmc_2.add_2(
                    comm_key_2.g,
                    &p_x,
                    comm_key_2.h,
                    &self.0[i].z3,
                    self.0[i].comm_alpha_point.x,
                );
                rmc_2.add_2(
                    comm_key_2.g,
                    &p_y,
                    comm_key_2.h,
                    &self.0[i].z4,
                    self.0[i].comm_alpha_point.y,
                );
                self.0[i].add.verify_using_randomized_mult_checker(
                    comm_result,
                    self.0[i].comm_alpha_minus_omega_point,
                    self.0[i].comm_alpha_point,
                    &minus_one,
                    comm_key_2,
                    rmc_2,
                )?;
            } else {
                rmc_1.add_2(
                    comm_key_1.g,
                    &self.0[i].z1,
                    comm_key_1.h,
                    &self.0[i].z2,
                    (self.0[i].comm_alpha + comm_minus_scalar).into_affine(),
                );
                rmc_2.add_2(
                    comm_key_2.g,
                    &p_x,
                    comm_key_2.h,
                    &self.0[i].z3,
                    self.0[i].comm_alpha_minus_omega_point.x,
                );
                rmc_2.add_2(
                    comm_key_2.g,
                    &p_y,
                    comm_key_2.h,
                    &self.0[i].z4,
                    self.0[i].comm_alpha_minus_omega_point.y,
                );
                self.0[i].add.verify_using_randomized_mult_checker(
                    comm_result,
                    self.0[i].comm_alpha_minus_omega_point,
                    self.0[i].comm_alpha_point,
                    &one,
                    comm_key_2,
                    rmc_2,
                )?;
            }
        }
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        for i in 0..NUM_REPS {
            self.0[i].comm_alpha.serialize_compressed(&mut writer)?;
            self.0[i]
                .comm_alpha_point
                .serialize_compressed(&mut writer)?;
            self.0[i]
                .comm_alpha_minus_omega_point
                .serialize_compressed(&mut writer)?;
            self.0[i].add.challenge_contribution(&mut writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tom256::Affine as tomAff;
    use ark_secp256r1::{Affine as secpAff, Fr as secpFr};
    use ark_std::UniformRand;
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
    use rand_core::OsRng;
    use std::time::Instant;
    use test_utils::statistics::statistics;

    #[test]
    fn scalar_mult() {
        let mut rng = OsRng::default();

        let comm_key_1 = PedersenCommitmentKey::<secpAff>::new::<Blake2b512>(b"test1");
        let comm_key_2 = PedersenCommitmentKey::<tomAff>::new::<Blake2b512>(b"test2");

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let mut ver_rmc_time = vec![];
        let num_iters = 10;
        const NUM_REPS: usize = 128;
        for i in 0..num_iters {
            let base = secpAff::rand(&mut rng);
            let scalar = secpFr::rand(&mut rng);
            let result = (base * scalar).into_affine();

            let comm_scalar = CommitmentWithOpening::new(&mut rng, scalar, &comm_key_1);
            let comm_result =
                PointCommitmentWithOpening::new(&mut rng, &result, &comm_key_2).unwrap();

            let start = Instant::now();
            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key_1", &comm_key_1);
            prover_transcript.append(b"comm_key_2", &comm_key_2);
            prover_transcript.append(b"comm_scalar", &comm_scalar.comm);
            prover_transcript.append(b"comm_result", &comm_result.comm);

            let protocol = ScalarMultiplicationProtocol::<secpAff, tomAff, NUM_REPS>::init(
                &mut rng,
                comm_scalar.clone(),
                comm_result.clone(),
                result,
                base,
                &comm_key_1,
                &comm_key_2,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let mut challenge_prover = [0_u8; NUM_REPS / 8];
            prover_transcript.challenge_bytes(b"challenge", &mut challenge_prover);
            let proof = protocol.gen_proof(&challenge_prover);
            prov_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_1", &comm_key_1);
            verifier_transcript.append(b"comm_key_2", &comm_key_2);
            verifier_transcript.append(b"comm_scalar", &comm_scalar.comm);
            verifier_transcript.append(b"comm_result", &comm_result.comm);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();

            let mut challenge_verifier = [0_u8; NUM_REPS / 8];
            verifier_transcript.challenge_bytes(b"challenge", &mut challenge_verifier);
            assert_eq!(challenge_prover, challenge_verifier);

            proof
                .verify(
                    &comm_scalar.comm,
                    &comm_result.comm,
                    &base,
                    &challenge_verifier,
                    &comm_key_1,
                    &comm_key_2,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key_1", &comm_key_1);
            verifier_transcript.append(b"comm_key_2", &comm_key_2);
            verifier_transcript.append(b"comm_scalar", &comm_scalar.comm);
            verifier_transcript.append(b"comm_result", &comm_result.comm);
            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();

            let mut challenge_verifier = [0_u8; NUM_REPS / 8];
            verifier_transcript.challenge_bytes(b"challenge", &mut challenge_verifier);
            assert_eq!(challenge_prover, challenge_verifier);

            let mut checker_1 = RandomizedMultChecker::<secpAff>::new_using_rng(&mut rng);
            let mut checker_2 = RandomizedMultChecker::<tomAff>::new_using_rng(&mut rng);

            proof
                .verify_using_randomized_mult_checker(
                    comm_scalar.comm,
                    comm_result.comm,
                    base,
                    &challenge_verifier,
                    comm_key_1,
                    comm_key_2,
                    &mut checker_1,
                    &mut checker_2,
                )
                .unwrap();
            assert!(checker_1.verify());
            assert!(checker_2.verify());
            ver_rmc_time.push(start.elapsed());

            if i == 0 {
                println!("Proof size = {} bytes", proof.compressed_size());
            }
        }
        println!("For {num_iters} iterations");
        println!("Proving time: {:?}", statistics(prov_time));
        println!("Verifying time: {:?}", statistics(ver_time));
        println!(
            "Verifying time with randomized multiplication check: {:?}",
            statistics(ver_rmc_time)
        );
    }
}
