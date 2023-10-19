//! Weighted Norm Linear argument for relation `v = <c, l> + {|n|_mu}^2` given commitment `C = v*G + <l, H_vec> + <n, G_vec>`

use crate::error::BulletproofsPlusPlusError;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, format, ops::Neg, vec, vec::Vec};
use dock_crypto_utils::{
    ff::{inner_product, weighted_inner_product, weighted_norm},
    transcript::Transcript,
};

use dock_crypto_utils::ff::scale;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::setup::SetupParams;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct WeightedNormLinearArgument<G: AffineRepr> {
    pub X: Vec<G>,
    pub R: Vec<G>,
    pub l: Vec<G::ScalarField>,
    pub n: Vec<G::ScalarField>,
}

impl<G: AffineRepr> WeightedNormLinearArgument<G> {
    /// Create new argument
    pub fn new(
        mut l: Vec<G::ScalarField>,
        mut n: Vec<G::ScalarField>,
        mut c: Vec<G::ScalarField>,
        mut rho: G::ScalarField,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<Self, BulletproofsPlusPlusError> {
        let SetupParams {
            G: g,
            G_vec: mut g_vec,
            H_vec: mut h_vec,
        } = setup_params;
        if l.len() != c.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of l={} not equal to length of c={}",
                    l.len(),
                    c.len()
                ),
            ));
        }
        if c.len() != h_vec.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of c={} not equal to length of H_vec={}",
                    c.len(),
                    h_vec.len()
                ),
            ));
        }
        if n.len() != g_vec.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of n={} not equal to length of G_vec={}",
                    n.len(),
                    g_vec.len()
                ),
            ));
        }
        if !l.len().is_power_of_two() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!("length of l={} must be power of 2", l.len()),
            ));
        }
        if !n.len().is_power_of_two() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!("length of n={} must be power of 2", n.len()),
            ));
        }

        let mut mu = rho.square();
        let mut X = Vec::new();
        let mut R = Vec::new();

        while l.len() > 1 || n.len() > 1 {
            let (l_0, l_1) = Self::split_vec(&l);
            let (n_0, n_1) = Self::split_vec(&n);
            let (c_0, c_1) = Self::split_vec(&c);
            let (g_0, g_1) = Self::split_vec(&g_vec);
            let (h_0, h_1) = Self::split_vec(&h_vec);
            let rho_inv = rho.inverse().unwrap();
            let mu_sqr = mu.square();

            let v_x = rho_inv.double() * weighted_inner_product(&n_0, &n_1, &mu_sqr)
                + inner_product(&c_0, &l_1)
                + inner_product(&c_1, &l_0);
            let v_r = weighted_norm(&n_1, &mu_sqr) + inner_product(&c_1, &l_1);

            let scaled_n_0 = cfg_iter!(n_0).map(|n| *n * rho_inv).collect::<Vec<_>>();
            let scaled_n_1 = cfg_iter!(n_1).map(|n| *n * rho).collect::<Vec<_>>();

            // X_i = g * v_x + <h_0, l_1> + <h_1, l_0> + <g_0, scaled_n_1> + <g_1, scaled_n_0>

            // Create X_i using MSM
            let msm_size = 1 + l_1.len() + l_0.len() + n_1.len() + n_0.len();
            let mut bases = Vec::with_capacity(msm_size);
            let mut scalars = Vec::with_capacity(msm_size);
            bases.push(g);
            scalars.push(v_x);
            // For <h_0, l_1>
            let min = core::cmp::min(h_0.len(), l_1.len());
            bases.extend_from_slice(&h_0[0..min]);
            scalars.extend_from_slice(&l_1[0..min]);
            // For <h_1, l_0>
            let min = core::cmp::min(h_1.len(), l_0.len());
            bases.extend_from_slice(&h_1[0..min]);
            scalars.extend_from_slice(&l_0[0..min]);
            // For <g_0, scaled_n_1>
            let min = core::cmp::min(g_0.len(), scaled_n_1.len());
            bases.extend_from_slice(&g_0[0..min]);
            scalars.extend_from_slice(&scaled_n_1[0..min]);
            // <g_1, scaled_n_0>
            let min = core::cmp::min(g_1.len(), scaled_n_0.len());
            bases.extend_from_slice(&g_1[0..min]);
            scalars.extend_from_slice(&scaled_n_0[0..min]);

            let X_i = G::Group::msm_unchecked(&bases, &scalars);

            // R_i = g * v_r + <h_1, l_1> + <g_1, n_1>

            // Create R_i using MSM
            let msm_size = 1 + l_1.len() + n_1.len();
            let mut bases = Vec::with_capacity(msm_size);
            let mut scalars = Vec::with_capacity(msm_size);
            bases.push(g);
            scalars.push(v_r);
            // For <h_1, l_1>
            let min = core::cmp::min(h_1.len(), l_1.len());
            bases.extend_from_slice(&h_1[0..min]);
            scalars.extend_from_slice(&l_1[0..min]);
            // For <g_1, n_1>
            let min = core::cmp::min(g_1.len(), n_1.len());
            bases.extend_from_slice(&g_1[0..min]);
            scalars.extend_from_slice(&n_1[0..min]);

            let R_i = G::Group::msm_unchecked(&bases, &scalars);

            transcript.append(b"X", &X_i);
            transcript.append(b"R", &R_i);
            let gamma = transcript.challenge_scalar::<G::ScalarField>(b"gamma");

            if l.len() > 1 {
                l = cfg_into_iter!(l_0)
                    .zip(l_1)
                    .map(|(_0, _1)| _0 + gamma * _1)
                    .collect();
                c = cfg_into_iter!(c_0)
                    .zip(c_1)
                    .map(|(_0, _1)| _0 + gamma * _1)
                    .collect();
                h_vec = G::Group::normalize_batch(
                    &cfg_iter!(h_0)
                        .zip(h_1)
                        .map(|(_0, _1)| *_0 + _1 * gamma)
                        .collect::<Vec<_>>(),
                );
            }
            if n.len() > 1 {
                n = cfg_iter!(n_0)
                    .zip(&n_1)
                    .map(|(_0, _1)| *_0 * rho_inv + gamma * _1)
                    .collect();
                g_vec = G::Group::normalize_batch(
                    &cfg_iter!(g_0)
                        .zip(g_1)
                        .map(|(_0, _1)| *_0 * rho + _1 * gamma)
                        .collect::<Vec<_>>(),
                );
            }

            rho = mu;
            mu = mu_sqr;
            X.push(X_i);
            R.push(R_i);
        }
        Ok(Self {
            X: G::Group::normalize_batch(&X),
            R: G::Group::normalize_batch(&R),
            l,
            n,
        })
    }

    /// Verify the argument.
    pub fn verify(
        &self,
        c: Vec<G::ScalarField>,
        rho: G::ScalarField,
        commitment: &G,
        setup_params: &SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(), BulletproofsPlusPlusError> {
        // Check if given commitment C == g * v + <h_vec, h_multiples> * l + <g_vec, g_multiples> * n - <self.X, gamma> - <self.R, gamma_sq_minus_1>
        let (bases, scalars) =
            self.get_bases_and_scalars_for_reduced_commitment(c, rho, setup_params, transcript)?;

        if commitment.into_group() != G::Group::msm_unchecked(&bases, &scalars) {
            return Err(BulletproofsPlusPlusError::WeightedNormLinearArgumentVerificationFailed);
        }
        Ok(())
    }

    /// Same as `Self::verify` except that it does not take the commitment directly but takes the `bases` and `scalars`
    /// whose inner product (MSM) gives the commitment. This is used when the calling protocol (range-proof in this case)
    /// has to create the commitment. The calling protocol rather than creating the commitment by MSM, passed the vectors here
    /// thus resulting in only 1 large MSM rather than 2 as verification also does an MSM
    pub fn verify_given_commitment_multiplicands(
        &self,
        c: Vec<G::ScalarField>,
        rho: G::ScalarField,
        mut commitment_bases: Vec<G>,
        mut commitment_scalars: Vec<G::ScalarField>,
        setup_params: &SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(), BulletproofsPlusPlusError> {
        let (mut bases, mut scalars) =
            self.get_bases_and_scalars_for_reduced_commitment(c, rho, setup_params, transcript)?;

        // Check if given commitment C == g * v + <h_vec, h_multiples> * l + <g_vec, g_multiples> * n - <self.X, gamma> - <self.R, gamma_sq_minus_1>
        // But C = <commitment_bases, commitment_scalars>
        // so check g * v + <h_vec, h_multiples> * l + <g_vec, g_multiples> * n - <self.X, gamma> - <self.R, gamma_sq_minus_1> - <commitment_bases, commitment_scalars> == 0

        bases.append(&mut commitment_bases);
        cfg_iter_mut!(commitment_scalars).for_each(|elem| *elem = elem.neg());
        scalars.append(&mut commitment_scalars);

        if !G::Group::msm_unchecked(&bases, &scalars).is_zero() {
            return Err(BulletproofsPlusPlusError::WeightedNormLinearArgumentVerificationFailed);
        }

        Ok(())
    }

    /// Verify the argument recursively. This is inefficient compared to `Self::verify` and only used for debugging
    #[cfg(test)]
    pub fn verify_recursively(
        &self,
        mut c: Vec<G::ScalarField>,
        mut rho: G::ScalarField,
        commitment: &G,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(), BulletproofsPlusPlusError> {
        let SetupParams {
            G: g,
            G_vec: mut g_vec,
            H_vec: mut h_vec,
        } = setup_params;
        if c.len() != h_vec.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of c={} not equal to length of H_vec={}",
                    c.len(),
                    h_vec.len()
                ),
            ));
        }
        if self.X.len() != self.R.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of X={} not equal to length of R={}",
                    self.X.len(),
                    self.X.len()
                ),
            ));
        }
        let mut mu = rho.square();
        let mut commitment = commitment.into_group();
        for i in 0..self.X.len() {
            transcript.append(b"X", &self.X[i]);
            transcript.append(b"R", &self.R[i]);
            let gamma = transcript.challenge_scalar::<G::ScalarField>(b"gamma");
            let (c_0, c_1) = Self::split_vec(&c);
            let (g_0, g_1) = Self::split_vec(&g_vec);
            let (h_0, h_1) = Self::split_vec(&h_vec);
            c = cfg_into_iter!(c_0)
                .zip(c_1)
                .map(|(_0, _1)| _0 + gamma * _1)
                .collect();
            h_vec = G::Group::normalize_batch(
                &cfg_iter!(h_0)
                    .zip(h_1)
                    .map(|(_0, _1)| *_0 + _1 * gamma)
                    .collect::<Vec<_>>(),
            );
            g_vec = G::Group::normalize_batch(
                &cfg_iter!(g_0)
                    .zip(g_1)
                    .map(|(_0, _1)| *_0 * rho + _1 * gamma)
                    .collect::<Vec<_>>(),
            );
            commitment += self.X[i] * gamma + self.R[i] * (gamma.square() - G::ScalarField::one());
            rho = mu;
            mu.square_in_place();
        }
        let v = Self::compute_v(&self.l, &self.n, &c, &mu);
        if commitment.into_affine()
            != SetupParams::compute_commitment_given_bases(&v, &self.l, &self.n, &g, &g_vec, &h_vec)
        {
            return Err(BulletproofsPlusPlusError::WeightedNormLinearArgumentVerificationFailed);
        }
        Ok(())
    }

    /// Returns <c, l> + {|n|^2}_mu
    #[cfg(test)]
    fn compute_v(
        l: &[G::ScalarField],
        n: &[G::ScalarField],
        c: &[G::ScalarField],
        mu: &G::ScalarField,
    ) -> G::ScalarField {
        inner_product(c, l) + weighted_norm(n, mu)
    }

    /// Split a vector into 2 vectors of even and odd indices elements respectively.
    fn split_vec<T: Clone>(original: &[T]) -> (Vec<T>, Vec<T>) {
        let mut odd = Vec::with_capacity(original.len() / 2);
        let mut even = Vec::with_capacity(original.len() / 2);
        for (i, v) in original.iter().enumerate() {
            if i % 2 == 0 {
                even.push(v.clone());
            } else {
                odd.push(v.clone());
            }
        }
        (even, odd)
    }

    fn get_h_multiples(n: usize, gamma: &[G::ScalarField]) -> Vec<G::ScalarField> {
        let mut multiples = vec![G::ScalarField::one(); n];
        let len = (n as u32).ilog2() as usize;
        for i in 0..len {
            let partition_size = 1 << i;
            let partitions = n / partition_size;
            for j in 0..partitions {
                if j % 2 == 1 {
                    for l in 0..partition_size {
                        multiples[j * partition_size + l] *= gamma[i];
                    }
                }
            }
        }
        multiples
    }

    fn get_g_multiples(
        n: usize,
        rho: &G::ScalarField,
        gamma: &[G::ScalarField],
    ) -> Vec<G::ScalarField> {
        let mut multiples = vec![G::ScalarField::one(); n];
        let len = (n as u32).ilog2() as usize;
        let mut rho_i = *rho;
        for i in 0..len {
            let partition_size = 1 << i;
            let partitions = n / partition_size;
            for j in 0..partitions {
                if j % 2 == 0 {
                    for l in 0..partition_size {
                        multiples[j * partition_size + l] *= rho_i;
                    }
                } else {
                    for l in 0..partition_size {
                        multiples[j * partition_size + l] *= gamma[i];
                    }
                }
            }
            rho_i.square_in_place();
        }
        multiples
    }

    fn get_bases_and_scalars_for_reduced_commitment(
        &self,
        c: Vec<G::ScalarField>,
        rho: G::ScalarField,
        setup_params: &SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(Vec<G>, Vec<G::ScalarField>), BulletproofsPlusPlusError> {
        let SetupParams {
            G: g,
            G_vec: g_vec,
            H_vec: h_vec,
        } = setup_params;
        if c.len() != h_vec.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of c={} not equal to length of H_vec={}",
                    c.len(),
                    h_vec.len()
                ),
            ));
        }
        if self.X.len() != self.R.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of X={} not equal to length of R={}",
                    self.X.len(),
                    self.R.len()
                ),
            ));
        }
        let mut mu = rho.square();
        let mut gamma = Vec::with_capacity(self.X.len());
        let mut gamma_sq_minus_1 = Vec::with_capacity(self.X.len());
        for i in 0..self.X.len() {
            transcript.append(b"X", &self.X[i]);
            transcript.append(b"R", &self.R[i]);
            gamma.push(transcript.challenge_scalar::<G::ScalarField>(b"gamma"));
            gamma_sq_minus_1.push(gamma[i].square() - G::ScalarField::one());
        }
        for _ in 0..g_vec.len().ilog2() {
            mu.square_in_place();
        }
        let g_multiples = Self::get_g_multiples(g_vec.len(), &rho, &gamma);
        let h_multiples = Self::get_h_multiples(h_vec.len(), &gamma);

        let v = self.l[0] * inner_product(&c, &h_multiples) + weighted_norm(&self.n, &mu);

        // C' = g * v + <h_vec, h_multiples> * l + <g_vec, g_multiples> * n
        // Check if C + <self.X, gamma> + <self.R, gamma_sq_minus_1> == C'
        // => C == C' - <self.X, gamma> - <self.R, gamma_sq_minus_1>
        // => C == g * v + <h_vec, h_multiples> * l + <g_vec, g_multiples> * n - <self.X, gamma> - <self.R, gamma_sq_minus_1>

        // RHS of above can be created using an MSM
        let msm_size =
            1 + h_multiples.len() + g_multiples.len() + gamma.len() + gamma_sq_minus_1.len();
        let mut bases = Vec::with_capacity(msm_size);
        let mut scalars = Vec::with_capacity(msm_size);
        // For g*v
        bases.push(*g);
        scalars.push(v);
        // For <h_vec, h_multiples> * l
        bases.extend_from_slice(&h_vec[0..h_multiples.len()]);
        scalars.append(&mut scale(&h_multiples, &self.l[0]));
        // For <g_vec, g_multiples> * n
        bases.extend_from_slice(&g_vec[0..g_multiples.len()]);
        scalars.append(&mut scale(&g_multiples, &self.n[0]));
        // For - <self.X, gamma>
        bases.extend_from_slice(&self.X);
        scalars.append(&mut scale(&gamma, &G::ScalarField::one().neg()));
        // For - <self.R, gamma_sq_minus_1>
        bases.extend_from_slice(&self.R);
        scalars.append(&mut scale(&gamma_sq_minus_1, &G::ScalarField::one().neg()));
        Ok((bases, scalars))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};

    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::{misc::n_rand, transcript::new_merlin_transcript};
    use std::time::Instant;

    #[test]
    fn check_when_powers_of_2() {
        let mut rng = StdRng::seed_from_u64(0u64);

        for count in [1, 2, 4, 8, 16, 32, 64] {
            let setup_params = SetupParams::new::<Blake2b512>(b"test", count, count);
            let c = n_rand(&mut rng, count).collect::<Vec<_>>();

            let l = n_rand(&mut rng, count).collect::<Vec<_>>();
            let n = n_rand(&mut rng, count).collect::<Vec<_>>();

            let rho = Fr::rand(&mut rng);

            let v = WeightedNormLinearArgument::<G1Affine>::compute_v(&l, &n, &c, &rho.square());
            let commitment = setup_params.compute_commitment(&v, &l, &n);

            let start = Instant::now();
            let mut prover_transcript = new_merlin_transcript(b"test");
            let arg = WeightedNormLinearArgument::<G1Affine>::new(
                l,
                n,
                c.clone(),
                rho.clone(),
                setup_params.clone(),
                &mut prover_transcript,
            )
            .unwrap();
            let prover_time = start.elapsed();

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            arg.verify(
                c.clone(),
                rho.clone(),
                &commitment,
                &setup_params,
                &mut verifier_transcript,
            )
            .unwrap();
            let verifying_non_recursively_time = start.elapsed();

            let start = Instant::now();
            let mut verifier_transcript = new_merlin_transcript(b"test");
            arg.verify_recursively(c, rho, &commitment, setup_params, &mut verifier_transcript)
                .unwrap();
            let verifying_time = start.elapsed();

            println!(
                "For {} elements, proving time is {:?}, recursively verifying time is {:?} and non-recursively verifying time is {:?}",
                count, prover_time, verifying_time, verifying_non_recursively_time
            );
        }
    }
}
