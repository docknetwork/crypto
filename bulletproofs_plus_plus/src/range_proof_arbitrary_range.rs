use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::{format, rand::RngCore, vec::Vec};

use crate::rangeproof::{Proof, Prover};

use crate::error::BulletproofsPlusPlusError;
use dock_crypto_utils::transcript::Transcript;

use crate::setup::SetupParams;
use dock_crypto_utils::msm::WindowTable;

/// Range proof for values in arbitrary ranges where each value `v_i` belongs to interval `[min_i, max_i)`
/// Uses the range proof for perfect ranges of form `[0, base^l)` where upper bound is a power of the base.
/// It splits a single range check of the form `min_i <= v_i < max_i` into 2 as `0 <= v_i - min_i` and `0 <= max_i - 1 - v_i`
/// and creates proofs both both checks. Along the proofs, it outputs commitments to `v_i - min_i` and `max_i - 1 - v_i` as
/// `g * (v_i - min_i) + h * {r_i}_1` and `g * (max_i - 1 - v_i) + h * {r_i}_2` respectively and both which can be
/// transformed to `g * v_i + h * {r_i}_1`, `g * v_i + h * {r_i}_2` by the verifier and the prover proves that
/// `v_i` in `g * v_i + h * r_i` in is same as `v_i` in `g * v_i + h * {r_i}_1`, `g * v_i + h * {r_i}_2`
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofArbitraryRange<G: AffineRepr> {
    pub V: Vec<G>,
    pub proof: Proof<G>,
}

impl<G: AffineRepr> ProofArbitraryRange<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        num_bits: u16,
        values_and_bounds: Vec<(u64, u64, u64)>,
        randomness: Vec<G::ScalarField>,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<Self, BulletproofsPlusPlusError> {
        let base = 2;
        Self::new_with_given_base(
            rng,
            base,
            num_bits,
            values_and_bounds,
            randomness,
            setup_params,
            transcript,
        )
    }

    pub fn new_with_given_base<R: RngCore>(
        rng: &mut R,
        base: u16,
        num_bits: u16,
        values_and_bounds: Vec<(u64, u64, u64)>,
        randomness: Vec<G::ScalarField>,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<Self, BulletproofsPlusPlusError> {
        let (V, v) =
            Self::compute_commitments_and_values(values_and_bounds, &randomness, &setup_params)?;
        let prover = Prover::new_with_given_base(base, num_bits, V.clone(), v, randomness)?;
        let proof = prover.prove(rng, setup_params, transcript)?;
        Ok(Self { V, proof })
    }

    pub fn verify(
        &self,
        num_bits: u16,
        setup_params: &SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(), BulletproofsPlusPlusError> {
        self.proof
            .verify(num_bits, &self.V, setup_params, transcript)
    }

    pub fn compute_commitments_and_values(
        values_and_bounds: Vec<(u64, u64, u64)>,
        randomness: &[G::ScalarField],
        setup_params: &SetupParams<G>,
    ) -> Result<(Vec<G>, Vec<u64>), BulletproofsPlusPlusError> {
        if values_and_bounds.len() * 2 != randomness.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of randomness={} should be double of length of values_and_bounds={}",
                    values_and_bounds.len(),
                    randomness.len()
                ),
            ));
        }
        let mut V = Vec::<G>::with_capacity(randomness.len());
        let mut v = Vec::<u64>::with_capacity(randomness.len());
        for (i, (v_i, min, max)) in values_and_bounds.iter().enumerate() {
            if min > v_i {
                return Err(BulletproofsPlusPlusError::IncorrectBounds(format!(
                    "value={} should be >= min={}",
                    v_i, min
                )));
            }
            if v_i >= max {
                return Err(BulletproofsPlusPlusError::IncorrectBounds(format!(
                    "value={} should be < max={}",
                    v_i, max
                )));
            }
            // Commit to `v_i - min` as `g * (v_i - min) + h * randomness[2 * i]`
            V.push(setup_params.compute_pedersen_commitment(v_i - min, &randomness[2 * i]));
            // Commit to `max - 1 - v_i` as `g * (max -1 - v_i) + h * randomness[2 * i]`
            V.push(setup_params.compute_pedersen_commitment(max - 1 - v_i, &randomness[2 * i + 1]));
            v.push(v_i - min);
            v.push(max - 1 - v_i);
        }
        Ok((V, v))
    }

    pub fn num_proofs(&self) -> u32 {
        self.V.len() as u32 / 2
    }

    /// Returns a vector of tuples where each tuple is a pair of commitments as (`(v_i - min_i)`, `(max_i - v_i)`)
    pub fn get_split_commitments(&self) -> Vec<(G, G)> {
        let mut comms = Vec::with_capacity(self.num_proofs() as usize);
        for i in (0..self.V.len()).step_by(2) {
            comms.push((self.V[i], self.V[i + 1]));
        }
        comms
    }

    /// Returns a vector of tuples where each tuple is a pair of commitments to the `v_i` but with different randomnesses
    pub fn get_commitments_to_values(
        &self,
        bounds: Vec<(u64, u64)>,
        setup_params: &SetupParams<G>,
    ) -> Result<Vec<(G, G)>, BulletproofsPlusPlusError> {
        self.get_commitments_to_values_given_g(bounds, &setup_params.G)
    }

    /// Same as `Self::get_commitments_to_values` but accepts the generator `g` from the setup params
    pub fn get_commitments_to_values_given_g(
        &self,
        bounds: Vec<(u64, u64)>,
        g: &G,
    ) -> Result<Vec<(G, G)>, BulletproofsPlusPlusError> {
        if bounds.len() != self.num_proofs() as usize {
            return Err(BulletproofsPlusPlusError::IncorrectNumberOfCommitments(
                bounds.len(),
                self.num_proofs() as usize,
            ));
        }
        Self::get_commitments_to_values_given_transformed_commitments_and_g(&self.V, bounds, g)
    }

    pub fn get_commitments_to_values_given_transformed_commitments_and_g(
        transformed_comms: &[G],
        bounds: Vec<(u64, u64)>,
        g: &G,
    ) -> Result<Vec<(G, G)>, BulletproofsPlusPlusError> {
        let table = WindowTable::new(transformed_comms.len(), g.into_group());
        let mut comms = Vec::with_capacity(transformed_comms.len() / 2);
        for i in (0..transformed_comms.len()).step_by(2) {
            let (min, max) = (bounds[i / 2].0, bounds[i / 2].1);
            if max <= min {
                return Err(BulletproofsPlusPlusError::IncorrectBounds(format!(
                    "max={} should be > min={}",
                    max, min
                )));
            }
            // `V[i]` is a commitment to `value - min` and `V[i+1]` is a commitment to `max - 1 - value`. Generate commitments
            // to `value` by `V[i] + g * min` and `g * (max - 1) - V[i+1]`
            comms.push((
                (transformed_comms[i] + table.multiply(&G::ScalarField::from(min))).into_affine(),
                (table.multiply(&G::ScalarField::from(max - 1)) - transformed_comms[i + 1])
                    .into_affine(),
            ));
        }
        Ok(comms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::new_merlin_transcript;
    use std::time::{Duration, Instant};

    fn test_rangeproof_for_arbitrary_range<G: AffineRepr>(
        base: u16,
        num_bits: u16,
        values_and_bounds: Vec<(u64, u64, u64)>,
    ) -> (Duration, Duration) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let mut gamma = vec![];
        for _ in 0..values_and_bounds.len() * 2 {
            gamma.push(G::ScalarField::rand(&mut rng));
        }

        let setup_params = SetupParams::<G>::new_for_arbitrary_range_proof::<Blake2b512>(
            b"test",
            base,
            num_bits,
            values_and_bounds.len() as u32,
        );

        let start = Instant::now();
        let mut transcript = new_merlin_transcript(b"BPP/tests");
        let proof = ProofArbitraryRange::new_with_given_base(
            &mut rng,
            base,
            num_bits,
            values_and_bounds.clone(),
            gamma.clone(),
            setup_params.clone(),
            &mut transcript,
        )
        .unwrap();
        let proving_time = start.elapsed();

        let bounds = values_and_bounds
            .clone()
            .into_iter()
            .map(|(_, min, max)| (min, max))
            .collect();
        let split_comms = proof.get_split_commitments();
        let comms = proof
            .get_commitments_to_values(bounds, &setup_params)
            .unwrap();

        let start = Instant::now();
        let mut transcript = new_merlin_transcript(b"BPP/tests");
        proof
            .verify(num_bits, &setup_params, &mut transcript)
            .unwrap();
        let verifying_time = start.elapsed();

        for (i, (v, min, max)) in values_and_bounds.into_iter().enumerate() {
            let (comm_min, comm_max) = split_comms[i];
            assert_eq!(
                comm_min + setup_params.compute_pedersen_commitment(min, &-gamma[2 * i]),
                setup_params.G * G::ScalarField::from(v)
            );
            assert_eq!(
                setup_params
                    .compute_pedersen_commitment(max - 1, &gamma[2 * i + 1])
                    .into_group()
                    - comm_max,
                setup_params.G * G::ScalarField::from(v)
            );
            assert_eq!(
                comms[i].0 + setup_params.H_vec[0].mul(-gamma[2 * i]),
                setup_params.G * G::ScalarField::from(v)
            );
            assert_eq!(
                comms[i].1 + setup_params.H_vec[0].mul(gamma[2 * i + 1]),
                setup_params.G * G::ScalarField::from(v)
            );
        }

        (proving_time, verifying_time)
    }

    fn check_for_arbitrary_range<G: AffineRepr>() {
        for (base, num_bits, val_bounds) in [
            (2, 4, vec![(7, 3, 10)]),
            (2, 4, vec![(0, 0, 15), (14, 0, 15)]),
            (16, 8, vec![(60, 40, 80), (15, 10, 20)]),
            (16, 8, vec![(100, 50, 150)]),
        ] {
            let size = val_bounds.len();
            let (p, v) = test_rangeproof_for_arbitrary_range::<G>(base, num_bits, val_bounds);
            println!("For base={}, max value bits={} for {} checks, proving time = {:?} and verifying time = {:?}", base, num_bits, size, p, v);
        }
    }

    #[test]
    fn rangeproof_bls12381() {
        check_for_arbitrary_range::<ark_bls12_381::G1Affine>()
    }
}
