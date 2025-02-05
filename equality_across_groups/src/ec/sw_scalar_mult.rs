//! Proof of scalar multiplication on short Weierstrass curve. Is a variation of the protocol described in section 5 of the paper [ZKAttest Ring and Group Signatures for Existing ECDSA Keys](https://eprint.iacr.org/2021/1183)
//!
//! The protocol proves that for committed curve point `r` and committed scalar `lambda` and public curve point `g`, `r = g * lambda`.
//! The verifier only has commitments to `r`'s coordinates `x` and `y` and `lambda` but knows `g`.
//!
//! The idea is the prover generates a random point say `j = g * alpha` where coordinates of `j` are `(gamma_1, gamma_2)`.
//! Now it proves using the protocol of point addition that sum of points `r` and `j` is another point say `l` and it knows
//! the opening of point `l`. The prover repeats this protocol several times as per the security parameter of the protocol
//!
//! The protocol in the paper commits to point `l` and later reveals its opening but the implementation here
//! does not commit to it, it simply reveals `l`.
//!
//! Following is the description (one repetition)
//! - Prover creates random scalar `alpha` and corresponding point `g * alpha` with coordinates `(gamma_1, gamma_2)`.
//! - Prover commits to `alpha, gamma_1, gamma_2` and sends to verifier (appends in the proof transcript)
//! - Prover generates a challenge bit and if it's 0, it sends the verifier openings of the commitments to `alpha, gamma_1, gamma_2`.
//! - If challenge bit is 1, it sends the sum of points `g * alpha` and `g * lambda` and openings `alpha + lambda` and randomness
//!   in the commitments to `lambda` and `alpha`.
//! - The verifier accordingly checks these.

use crate::{
    ec::{
        commitments::{CommitmentWithOpening, PointCommitment, PointCommitmentWithOpening},
        sw_point_addition::PointAdditionProof,
    },
    error::Error,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, msm::WindowTable, transcript::Transcript,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Proof in the repetition where challenge bit is even. Contains opening to the commitments
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct EvenRep<P: AffineRepr, C: AffineRepr> {
    pub alpha: P::ScalarField,
    pub beta_1: P::ScalarField,
    pub beta_2: C::ScalarField,
    pub beta_3: C::ScalarField,
}

/// Proof in the repetition where challenge bit is odd
#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct OddRep<P: AffineRepr, C: AffineRepr> {
    pub z1: P::ScalarField,
    pub z2: P::ScalarField,
    /// The sum of points `g * alpha` and `g * lambda`, i.e. `t = g * (alpha + lambda)`
    pub t: P,
    pub addition_proof: PointAdditionProof<P, C>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OddEvenRep<P: AffineRepr, C: AffineRepr> {
    EvenRep(EvenRep<P, C>),
    OddRep(OddRep<P, C>),
}

/// Single repetition of proof of scalar multiplication.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScalarMultiplicationProofSingleRep<P: AffineRepr, C: AffineRepr> {
    /// Commitment to random scalar `alpha`
    pub a1: P,
    /// Commitment to coordinates of the point formed by scalar multiplication with random scalar `alpha`
    pub a2_a3: PointCommitment<C>,
    pub odd_even_rep: OddEvenRep<P, C>,
}

/// Proof of scalar multiplication.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ScalarMultiplicationProof<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize = 128>(
    // Creating an array overflows the stack at 128 reps.
    // pub [ScalarMultiplicationProofSingleRep<P, C>; NUM_REPS],
    pub Vec<ScalarMultiplicationProofSingleRep<P, C>>,
);

impl<P: AffineRepr, C: AffineRepr, const NUM_REPS: usize>
    ScalarMultiplicationProof<P, C, NUM_REPS>
{
    /// For proving `base * scalar = result` where `comm_scalar` and `comm_result` are commitments to `scalar`
    /// and `result` respectively
    pub fn new<R: RngCore>(
        mut rng: &mut R,
        comm_scalar: CommitmentWithOpening<P>,
        comm_result: PointCommitmentWithOpening<C>,
        result: P,
        base: P,
        comm_key_1: &PedersenCommitmentKey<P>,
        comm_key_2: &PedersenCommitmentKey<C>,
        transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<Self, Error> {
        let mut proofs = Vec::<ScalarMultiplicationProofSingleRep<P, C>>::with_capacity(NUM_REPS);
        // Random scalars
        let alpha = (0..NUM_REPS)
            .map(|_| P::ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();

        // Randomness for the commitment
        let beta_1 = (0..NUM_REPS)
            .map(|_| P::ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let beta_2 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();
        let beta_3 = (0..NUM_REPS)
            .map(|_| C::ScalarField::rand(&mut rng))
            .collect::<Vec<_>>();

        let base_table = WindowTable::new(NUM_REPS, base.into_group());
        // Points base * alpha_i
        let gamma = P::Group::normalize_batch(&base_table.multiply_many(&alpha));
        // Commit to alpha_i
        let a1 = P::Group::normalize_batch(
            &cfg_into_iter!(0..NUM_REPS)
                .map(|i| comm_key_1.commit_as_projective(&alpha[i], &beta_1[i]))
                .collect::<Vec<_>>(),
        );
        // Commit to coordinates of gamma_i
        let a2_a3_ = cfg_into_iter!(0..NUM_REPS)
            .map(|i| {
                PointCommitmentWithOpening::<C>::new_given_randomness::<P>(
                    &gamma[i], beta_2[i], beta_3[i], comm_key_2,
                )
            })
            .collect::<Vec<_>>();
        let mut a2_a3 = Vec::with_capacity(NUM_REPS);
        for a in a2_a3_ {
            a2_a3.push(a?);
        }

        let mut c_byte = [0_u8; 1];
        for i in 0..NUM_REPS {
            transcript.append(b"a_1", &a1[i]);
            transcript.append(b"a2_a3", &a2_a3[i].comm);
            transcript.challenge_bytes(b"challenge", &mut c_byte);
            if c_byte[0] & 1 == 0 {
                proofs.push(ScalarMultiplicationProofSingleRep {
                    a1: a1[i],
                    a2_a3: a2_a3[i].comm.clone(),
                    odd_even_rep: OddEvenRep::EvenRep(EvenRep {
                        alpha: alpha[i],
                        beta_1: beta_1[i],
                        beta_2: beta_2[i],
                        beta_3: beta_3[i],
                    }),
                });
            } else {
                let z1 = alpha[i] + comm_scalar.value;
                let z2 = beta_1[i] + comm_scalar.randomness;
                // t = g * (alpha + lambda)
                let t = base_table.multiply(&z1).into_affine();
                let addition_proof = PointAdditionProof::<P, C>::new(
                    rng,
                    a2_a3[i].clone(),
                    comm_result.clone(),
                    gamma[i],
                    result,
                    t,
                    comm_key_2,
                    transcript,
                )?;
                proofs.push(ScalarMultiplicationProofSingleRep {
                    a1: a1[i],
                    a2_a3: a2_a3[i].comm.clone(),
                    odd_even_rep: OddEvenRep::OddRep(OddRep {
                        z1,
                        z2,
                        t,
                        addition_proof,
                    }),
                });
            }
        }
        Ok(Self(proofs))
    }

    /// For verifying `base * scalar = result` where `comm_scalar` and `comm_result` are commitments to `scalar`
    /// and `result` respectively
    pub fn verify(
        &self,
        comm_scalar: &P,
        comm_result: &PointCommitment<C>,
        base: &P,
        comm_key_1: &PedersenCommitmentKey<P>,
        comm_key_2: &PedersenCommitmentKey<C>,
        transcript: &mut (impl Transcript + Clone + Write),
    ) -> Result<(), Error> {
        if self.0.len() != NUM_REPS {
            return Err(Error::InsufficientNumberOfRepetitions(
                self.0.len(),
                NUM_REPS,
            ));
        }
        let base_table = WindowTable::new(NUM_REPS, base.into_group());
        let mut c_byte = [0_u8; 1];
        for i in 0..NUM_REPS {
            transcript.append(b"a_1", &self.0[i].a1);
            transcript.append(b"a2_a3", &self.0[i].a2_a3);
            transcript.challenge_bytes(b"challenge", &mut c_byte);
            if c_byte[0] & 1 == 0 {
                match self.0[i].odd_even_rep {
                    OddEvenRep::EvenRep(rep) => {
                        let gamma_i = base_table.multiply(&rep.alpha).into_affine();
                        if self.0[i].a1 != comm_key_1.commit(&rep.alpha, &rep.beta_1) {
                            return Err(Error::IncorrectA1OpeningAtIndex(i));
                        }
                        if self.0[i].a2_a3
                            != PointCommitmentWithOpening::new_given_randomness(
                                &gamma_i, rep.beta_2, rep.beta_3, comm_key_2,
                            )?
                            .comm
                        {
                            return Err(Error::IncorrectPointOpeningAtIndex(i));
                        }
                    }
                    _ => return Err(Error::ExpectedEvenButFoundOddAtRep(i)),
                }
            } else {
                match self.0[i].odd_even_rep {
                    OddEvenRep::OddRep(rep) => {
                        // Check g * z1 + h * z2 = Com(alpha) + Com(lambda)
                        if comm_key_1.commit_as_projective(&rep.z1, &rep.z2)
                            != self.0[i].a1 + comm_scalar
                        {
                            return Err(Error::IncorrectScalarOpeningAtIndex(i));
                        }
                        let er = rep.addition_proof.verify(
                            &self.0[i].a2_a3,
                            comm_result,
                            &rep.t,
                            comm_key_2,
                            transcript,
                        );
                        if er.is_err() {
                            return er;
                        }
                    }
                    _ => return Err(Error::ExpectedOddButFoundEvenAtRep(i)),
                }
            }
        }
        Ok(())
    }
}

impl<P: AffineRepr, C: AffineRepr> Default for OddEvenRep<P, C> {
    fn default() -> Self {
        OddEvenRep::EvenRep(EvenRep::default())
    }
}

mod serialization {
    use super::*;
    use ark_serialize::{Compress, SerializationError, Valid, Validate};
    use ark_std::io::Read;

    impl<P: AffineRepr, C: AffineRepr> Valid for OddEvenRep<P, C> {
        fn check(&self) -> Result<(), SerializationError> {
            match self {
                Self::EvenRep(e) => e.check(),
                Self::OddRep(e) => e.check(),
            }
        }
    }

    impl<P: AffineRepr, C: AffineRepr> CanonicalSerialize for OddEvenRep<P, C> {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            compress: Compress,
        ) -> Result<(), SerializationError> {
            match self {
                Self::EvenRep(r) => {
                    CanonicalSerialize::serialize_with_mode(&0u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)
                }
                Self::OddRep(r) => {
                    CanonicalSerialize::serialize_with_mode(&1u8, &mut writer, compress)?;
                    CanonicalSerialize::serialize_with_mode(r, &mut writer, compress)
                }
            }
        }

        fn serialized_size(&self, compress: Compress) -> usize {
            match self {
                Self::EvenRep(r) => 0u8.serialized_size(compress) + r.serialized_size(compress),
                Self::OddRep(r) => 1u8.serialized_size(compress) + r.serialized_size(compress),
            }
        }
    }

    impl<P: AffineRepr, C: AffineRepr> CanonicalDeserialize for OddEvenRep<P, C> {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            compress: Compress,
            validate: Validate,
        ) -> Result<Self, SerializationError> {
            let t: u8 =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            match t {
                0u8 => Ok(Self::EvenRep(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                1u8 => Ok(Self::OddRep(CanonicalDeserialize::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?)),
                _ => Err(SerializationError::InvalidData),
            }
        }
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

    #[test]
    fn scalar_mult() {
        let mut rng = OsRng::default();

        let comm_key_1 = PedersenCommitmentKey::<secpAff>::new::<Blake2b512>(b"test1");
        let comm_key_2 = PedersenCommitmentKey::<tomAff>::new::<Blake2b512>(b"test2");

        let base = secpAff::rand(&mut rng);
        let scalar = secpFr::rand(&mut rng);
        let result = (base * scalar).into_affine();

        let comm_scalar = CommitmentWithOpening::new(&mut rng, scalar, &comm_key_1);
        let comm_result = PointCommitmentWithOpening::new(&mut rng, &result, &comm_key_2).unwrap();

        let mut prover_transcript = new_merlin_transcript(b"test");
        prover_transcript.append(b"comm_key_1", &comm_key_1);
        prover_transcript.append(b"comm_key_2", &comm_key_2);
        prover_transcript.append(b"comm_scalar", &comm_scalar.comm);
        prover_transcript.append(b"comm_result", &comm_result.comm);
        let proof = ScalarMultiplicationProof::<secpAff, tomAff>::new(
            &mut rng,
            comm_scalar.clone(),
            comm_result.clone(),
            result,
            base,
            &comm_key_1,
            &comm_key_2,
            &mut prover_transcript,
        )
        .unwrap();

        let mut verifier_transcript = new_merlin_transcript(b"test");
        verifier_transcript.append(b"comm_key_1", &comm_key_1);
        verifier_transcript.append(b"comm_key_2", &comm_key_2);
        verifier_transcript.append(b"comm_scalar", &comm_scalar.comm);
        verifier_transcript.append(b"comm_result", &comm_result.comm);
        proof
            .verify(
                &comm_scalar.comm,
                &comm_result.comm,
                &base,
                &comm_key_1,
                &comm_key_2,
                &mut verifier_transcript,
            )
            .unwrap();
    }
}
