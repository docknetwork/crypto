//! Proof of point addition on short Weierstrass curve. The protocol, called CDLSS, is described in section 4.1 of the paper [CDLS: Proving Knowledge of Committed Discrete Logarithms with Soundness](https://eprint.iacr.org/2023/1595)
//!
//! Proof that points `a + b = t` with coordinates `a = (ax, ay), b = (bx, by), t = (tx, ty)`. The prover and verifier both have
//! Pedersen commitments to each of the 6 coordinates, `ax, ay, bx, by, tx, ty`.

use crate::{
    ec::commitments::{
        CommitmentWithOpening, PointCommitment, PointCommitmentWithOpening, SWPoint,
    },
    error::Error,
};
use ark_ec::{short_weierstrass::Affine, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, marker::PhantomData, ops::Neg, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker,
};
use schnorr_pok::{
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
    inequality::{DiscreteLogInequalityProtocol, InequalityProof},
    mult_relations::{ProductProof, ProductProtocol, SquareProof, SquareProtocol},
};

/// Protocol for point addition when only the commitments to the points being added is known to the verifier.
/// `P` is the curve where the points live and `C` is the curve where commitments (to their coordinates) live.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PointAdditionProtocol<P: SWPoint, C: SWPoint> {
    /// Commitment to `tau = (by - ay) / (bx - ax)`
    pub comm_tau: CommitmentWithOpening<C>,
    /// To prove `tau` is properly created
    pub tau: ProductProtocol<Affine<C>>,
    /// To prove `tau^2` is properly created
    pub tau_sqr: SquareProtocol<Affine<C>>,
    /// To prove `tau*(ax - tx)` is properly created
    pub tau_ax_minus_tx: ProductProtocol<Affine<C>>,
    /// To prove `(bx - ax)` is not zero
    pub bx_minus_ax: DiscreteLogInequalityProtocol<Affine<C>>,
    /// To prove opening of commitment to `ay`
    pub ay: PokPedersenCommitmentProtocol<Affine<C>>,
    _phantom: PhantomData<P>,
}

/// Proof of point addition when only the commitments to the points being added is known to the verifier.
/// `P` is the curve where the points live and `C` is the curve where commitments (to their coordinates) live.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PointAdditionProof<P: SWPoint, C: SWPoint> {
    /// Commitment to `tau = (by - ay) / (bx - ax)`
    pub comm_tau: Affine<C>,
    /// To prove `tau` is properly created
    pub tau: ProductProof<Affine<C>>,
    /// To prove `tau^2` is properly created
    pub tau_sqr: SquareProof<Affine<C>>,
    /// To prove `tau*(ax - tx)` is properly created
    pub tau_ax_minus_tx: ProductProof<Affine<C>>,
    /// To prove `(bx - ax)` is not zero
    pub bx_minus_ax: InequalityProof<Affine<C>>,
    /// To prove opening of commitment to `ay`
    pub ay: PokPedersenCommitment<Affine<C>>,
    _phantom: PhantomData<P>,
}

impl<P: SWPoint, C: SWPoint> PointAdditionProtocol<P, C> {
    /// Prove that `a + b = t`. `comm_a`, `comm_b` and `comm_t` are commitments to `a`, `b` and `t` respectively.
    pub fn init<R: RngCore>(
        rng: &mut R,
        comm_a: PointCommitmentWithOpening<C>,
        comm_b: PointCommitmentWithOpening<C>,
        comm_t: PointCommitmentWithOpening<C>,
        a: Affine<P>,
        b: Affine<P>,
        t: Affine<P>,
        comm_key: &PedersenCommitmentKey<Affine<C>>,
    ) -> Result<Self, Error> {
        Self::ensure_addition_possible(&a, &b, &t)?;
        if (a + b) != t.into_group() {
            return Err(Error::InvalidPointAddResult);
        }

        // Commitment to b - a
        let comm_b_minus_a = &comm_b - &comm_a;
        // Commitment to a + t
        let comm_a_plus_t = &comm_a + &comm_t;
        let by_minus_ay = comm_b_minus_a.y;
        let bx_minus_ax = comm_b_minus_a.x;
        let bx_minus_ax_inv = bx_minus_ax.inverse().unwrap();
        // tau = (by - ay)/(bx - ax)
        let tau = by_minus_ay * bx_minus_ax_inv;
        let tau_sqr = tau.square();

        let comm_tau = CommitmentWithOpening::new(rng, tau, comm_key);
        let tau_prot = ProductProtocol::init(
            rng,
            &comm_b_minus_a.comm.x,
            bx_minus_ax,
            tau,
            by_minus_ay,
            comm_b_minus_a.r_x,
            comm_tau.randomness,
            comm_b_minus_a.r_y,
            comm_key,
        )?;
        let tau_sqr_prot = SquareProtocol::init(
            rng,
            &comm_tau.comm,
            tau,
            tau_sqr,
            comm_tau.randomness,
            comm_a_plus_t.r_x + comm_b.r_x,
            comm_key,
        )?;
        let tau_ax_minus_tx = ProductProtocol::init(
            rng,
            &comm_tau.comm,
            tau,
            comm_a.x - comm_t.x,
            comm_a_plus_t.y,
            comm_tau.randomness,
            comm_a.r_x - comm_t.r_x,
            comm_a_plus_t.r_y,
            comm_key,
        )?;
        // To prove that (ba - ax) ≠ 0
        let bx_minus_ax = DiscreteLogInequalityProtocol::init_for_inequality_with_public_value(
            rng,
            comm_b_minus_a.x,
            comm_b_minus_a.r_x,
            &comm_b_minus_a.comm.x,
            &C::ScalarField::zero(),
            comm_key,
        )?;
        let ay = PokPedersenCommitmentProtocol::init(
            comm_a.y,
            C::ScalarField::rand(rng),
            &comm_key.g,
            comm_a.r_y,
            C::ScalarField::rand(rng),
            &comm_key.h,
        );

        Ok(Self {
            comm_tau,
            tau: tau_prot,
            tau_sqr: tau_sqr_prot,
            tau_ax_minus_tx,
            bx_minus_ax,
            ay,
            _phantom: Default::default(),
        })
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.comm_tau.comm.serialize_compressed(&mut writer)?;
        self.tau.challenge_contribution(&mut writer)?;
        self.tau_sqr.challenge_contribution(&mut writer)?;
        self.tau_ax_minus_tx.challenge_contribution(&mut writer)?;
        // Following 2 are still following the old pattern of generating challenge contribution so
        // passing zero (default) values. This is ugly but not wrong as the expected arguments are already
        // being added to the challenge contribution
        let zero = Affine::<C>::zero();
        self.bx_minus_ax
            .challenge_contribution_for_public_inequality(
                &zero,
                &C::ScalarField::zero(),
                &PedersenCommitmentKey { g: zero, h: zero },
                &mut writer,
            )?;
        self.ay
            .challenge_contribution(&zero, &zero, &zero, &mut writer)?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &C::ScalarField) -> PointAdditionProof<P, C> {
        let tau = self.tau.gen_proof(challenge);
        let tau_sqr = self.tau_sqr.gen_proof(challenge);
        let tau_ax_minus_tx = self.tau_ax_minus_tx.gen_proof(challenge);
        let bx_minus_ax = self.bx_minus_ax.gen_proof(challenge);
        let ay = self.ay.gen_proof(challenge);
        PointAdditionProof {
            comm_tau: self.comm_tau.comm,
            tau,
            tau_sqr,
            tau_ax_minus_tx,
            bx_minus_ax,
            ay,
            _phantom: Default::default(),
        }
    }

    pub fn ensure_addition_possible(
        a: &Affine<P>,
        b: &Affine<P>,
        t: &Affine<P>,
    ) -> Result<(), Error> {
        if a.is_zero() || b.is_zero() || t.is_zero() {
            return Err(Error::PointAtInfinity);
        }
        if a == b {
            return Err(Error::CannotAddEqualPoints);
        }
        if a.x().unwrap() == b.x().unwrap() {
            return Err(Error::XCoordCantBeSame);
        }
        Ok(())
    }
}

impl<P: SWPoint, C: SWPoint> PointAdditionProof<P, C> {
    /// Check the proof that `a + b = t`
    /// Its assumed that verifier "trusts" that commitment to point `a`, `b` and `t` are `comm_a`, `comm_b` and `comm_t` respectively
    pub fn verify(
        &self,
        comm_a: &PointCommitment<C>,
        comm_b: &PointCommitment<C>,
        comm_t: &PointCommitment<C>,
        challenge: &C::ScalarField,
        comm_key: &PedersenCommitmentKey<Affine<C>>,
    ) -> Result<(), Error> {
        let comm_b_minus_a = comm_b - comm_a;
        let comm_a_plus_t = comm_a + comm_t;

        if !self.tau.verify(
            comm_b_minus_a.x,
            self.comm_tau,
            comm_b_minus_a.y,
            challenge,
            comm_key,
        ) {
            return Err(Error::TauProofFailed);
        }

        if !self.tau_sqr.verify(
            self.comm_tau,
            (comm_a_plus_t.x + comm_b.x).into_affine(),
            &challenge,
            comm_key,
        ) {
            return Err(Error::TauSquareProofFailed);
        }

        if !self.tau_ax_minus_tx.verify(
            self.comm_tau,
            (comm_a.x + comm_t.x.into_group().neg()).into_affine(),
            comm_a_plus_t.y,
            &challenge,
            comm_key,
        ) {
            return Err(Error::TxProofFailed);
        }

        self.bx_minus_ax.verify_for_inequality_with_public_value(
            &comm_b_minus_a.x,
            &C::ScalarField::zero(),
            &challenge,
            comm_key,
        )?;

        if !self
            .ay
            .verify(&comm_a.y, &comm_key.g, &comm_key.h, &challenge)
        {
            return Err(Error::TyProofFailed);
        }

        Ok(())
    }

    /// Same as `Self::verify` but delegated the scalar multiplication checks to `RandomizedMultChecker`
    pub fn verify_using_randomized_mult_checker(
        &self,
        comm_a: PointCommitment<C>,
        comm_b: PointCommitment<C>,
        comm_t: PointCommitment<C>,
        challenge: &C::ScalarField,
        comm_key: PedersenCommitmentKey<Affine<C>>,
        rmc: &mut RandomizedMultChecker<Affine<C>>,
    ) -> Result<(), Error> {
        let comm_b_minus_a = &comm_b - &comm_a;
        let comm_a_plus_t = &comm_a + &comm_t;
        self.tau.verify_using_randomized_mult_checker(
            comm_b_minus_a.x,
            self.comm_tau,
            comm_b_minus_a.y,
            challenge,
            comm_key,
            rmc,
        );
        self.tau_sqr.verify_using_randomized_mult_checker(
            self.comm_tau,
            (comm_a_plus_t.x + comm_b.x).into_affine(),
            &challenge,
            comm_key,
            rmc,
        );
        self.tau_ax_minus_tx.verify_using_randomized_mult_checker(
            self.comm_tau,
            (comm_a.x + comm_t.x.into_group().neg()).into_affine(),
            comm_a_plus_t.y,
            &challenge,
            comm_key,
            rmc,
        );
        self.bx_minus_ax
            .verify_for_inequality_with_public_value_using_randomized_mult_checker(
                comm_b_minus_a.x,
                &C::ScalarField::zero(),
                &challenge,
                comm_key,
                rmc,
            )?;
        self.ay.verify_using_randomized_mult_checker(
            comm_a.y, comm_key.g, comm_key.h, &challenge, rmc,
        );
        Ok(())
    }

    /// Assumes that the public commitments and commitment key have already been included in the challenge
    pub fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.comm_tau.serialize_compressed(&mut writer)?;
        self.tau.challenge_contribution(&mut writer)?;
        self.tau_sqr.challenge_contribution(&mut writer)?;
        self.tau_ax_minus_tx.challenge_contribution(&mut writer)?;
        // Following 2 are still following the old pattern of generating challenge contribution so
        // passing zero (default) values. This is ugly but not wrong as the expected arguments are already
        // being added to the challenge contribution
        let zero = Affine::<C>::zero();
        self.bx_minus_ax
            .challenge_contribution_for_public_inequality(
                &zero,
                &C::ScalarField::zero(),
                &PedersenCommitmentKey { g: zero, h: zero },
                &mut writer,
            )?;
        self.ay
            .challenge_contribution(&zero, &zero, &zero, &mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tom256::{Affine as tomAff, Config as tomConfig};
    use ark_ec::{CurveGroup, Group};
    use ark_secp256r1::{Affine as secpAff, Config as secpConfig};
    use ark_std::UniformRand;
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
    use rand_core::OsRng;
    use std::time::Instant;
    use test_utils::statistics::statistics;

    #[test]
    fn point_addition() {
        let mut rng = OsRng::default();

        let comm_key = PedersenCommitmentKey::<tomAff>::new::<Blake2b512>(b"test");

        let mut prov_time = vec![];
        let mut ver_time = vec![];
        let mut ver_rmc_time = vec![];
        let num_iters = 100;
        for i in 0..num_iters {
            let a = secpAff::rand(&mut rng);
            let b = secpAff::rand(&mut rng);
            let t = (a + b).into_affine();

            let comm_a = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &a, &comm_key,
            )
            .unwrap();
            let comm_b = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &b, &comm_key,
            )
            .unwrap();
            let comm_t = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &t, &comm_key,
            )
            .unwrap();

            let start = Instant::now();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            prover_transcript.append(b"comm_a", &comm_a.comm);
            prover_transcript.append(b"comm_b", &comm_b.comm);
            prover_transcript.append(b"comm_t", &comm_t.comm);

            let protocol = PointAdditionProtocol::<secpConfig, tomConfig>::init(
                &mut rng,
                comm_a.clone(),
                comm_b.clone(),
                comm_t.clone(),
                a,
                b,
                t,
                &comm_key,
            )
            .unwrap();
            protocol
                .challenge_contribution(&mut prover_transcript)
                .unwrap();
            let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
            let proof = protocol.gen_proof(&challenge_prover);
            prov_time.push(start.elapsed());

            let start = Instant::now();

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"comm_a", &comm_a.comm);
            verifier_transcript.append(b"comm_b", &comm_b.comm);
            verifier_transcript.append(b"comm_t", &comm_t.comm);

            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
            assert_eq!(challenge_prover, challenge_verifier);
            proof
                .verify(
                    &comm_a.comm,
                    &comm_b.comm,
                    &comm_t.comm,
                    &challenge_verifier,
                    &comm_key,
                )
                .unwrap();
            ver_time.push(start.elapsed());

            let start = Instant::now();

            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"comm_a", &comm_a.comm);
            verifier_transcript.append(b"comm_b", &comm_b.comm);
            verifier_transcript.append(b"comm_t", &comm_t.comm);

            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");
            assert_eq!(challenge_prover, challenge_verifier);
            let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
            proof
                .verify_using_randomized_mult_checker(
                    comm_a.comm,
                    comm_b.comm,
                    comm_t.comm,
                    &challenge_verifier,
                    comm_key,
                    &mut checker,
                )
                .unwrap();
            assert!(checker.verify());
            ver_rmc_time.push(start.elapsed());

            if i == 0 {
                println!("Proof size = {} bytes", proof.compressed_size());
            }

            // Sum of a and -a should give error
            let minus_a = a.neg();
            let comm_minus_a = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &minus_a, &comm_key,
            )
            .unwrap();
            let comm_zero = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &minus_a, &comm_key,
            )
            .unwrap();

            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            assert!(PointAdditionProtocol::<secpConfig, tomConfig>::init(
                &mut rng,
                comm_a.clone(),
                comm_minus_a.clone(),
                comm_zero,
                a,
                minus_a,
                secpAff::zero(),
                &comm_key,
            )
            .is_err());

            // Sum of a and a should give error
            let a_dbl = a.into_group().double().into_affine();
            let comm_a_dbl = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng, &a_dbl, &comm_key,
            )
            .unwrap();
            let mut prover_transcript = new_merlin_transcript(b"test");
            prover_transcript.append(b"comm_key", &comm_key);
            assert!(PointAdditionProtocol::<secpConfig, tomConfig>::init(
                &mut rng,
                comm_a.clone(),
                comm_a.clone(),
                comm_a_dbl,
                a,
                a,
                a_dbl,
                &comm_key,
            )
            .is_err());

            // Verifying with incorrect sum fails
            let random_point = secpAff::rand(&mut rng);
            let comm_rand = PointCommitmentWithOpening::<tomConfig>::new::<_, secpConfig>(
                &mut rng,
                &random_point,
                &comm_key,
            )
            .unwrap();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            verifier_transcript.append(b"comm_key", &comm_key);
            verifier_transcript.append(b"comm_a", &comm_a.comm);
            verifier_transcript.append(b"comm_b", &comm_b.comm);
            verifier_transcript.append(b"comm_t", &comm_rand.comm);

            proof
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            assert!(proof
                .verify(
                    &comm_a.comm,
                    &comm_b.comm,
                    &comm_rand.comm,
                    &challenge_verifier,
                    &comm_key,
                )
                .is_err());
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
