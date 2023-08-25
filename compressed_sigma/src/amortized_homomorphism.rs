//! Amortized sigma protocol with homomorphism as described in section 3.4 of the paper "Compressing Proofs of k-Out-Of-n".
//! This is for the relation R_{AMOREXP} where a single homomorphism is applied over many witness vectors and
//! there is a separate commitment to each witness vector.

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;

use crate::{
    compressed_homomorphism,
    error::CompSigmaError,
    transforms::Homomorphism,
    utils::{amortized_response, get_n_powers},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineRepr> {
    /// Maximum size of the witness vectors
    pub max_size: u32,
    /// Random vector from Z_q^n
    pub r: Vec<G::ScalarField>,
    /// A = \vec{g}^{\vec{r}}
    pub A: G,
    /// t = f(\vec{r})
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineRepr> {
    /// z_tilde = r + \sum_{i=1}^s c^i*\vec{x_i}
    pub z_tilde: Vec<G::ScalarField>,
}

impl<G> RandomCommitment<G>
where
    G: AffineRepr,
{
    pub fn new<R: RngCore, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        max_size: u32,
        f: &F,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Result<Self, CompSigmaError> {
        if g.len() < max_size as usize {
            return Err(CompSigmaError::VectorTooShort);
        };
        let r = if let Some(blindings) = blindings {
            if blindings.len() != max_size as usize {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            blindings
        } else {
            (0..max_size).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = f.eval(&r).unwrap();
        let A = G::Group::msm_unchecked(g, &r);
        Ok(Self {
            max_size: max_size,
            r,
            A: A.into_affine(),
            t,
        })
    }

    pub fn response(
        &self,
        witnesses: Vec<&[G::ScalarField]>,
        challenge: &G::ScalarField,
    ) -> Response<G> {
        let count_commitments = witnesses.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^{n-1}]
        let challenge_powers = get_n_powers(challenge.clone(), count_commitments);

        // z_tilde_i = r_i + \sum_{j in count_commitments}(witnesses_j_i * challenge^j)
        let z_tilde = amortized_response(self.max_size, &challenge_powers, &self.r, witnesses);
        Response { z_tilde }
    }
}

impl<G> Response<G>
where
    G: AffineRepr,
{
    pub fn is_valid<F: Homomorphism<G::ScalarField, Output = G>>(
        &self,
        g: &[G],
        max_size: u32,
        P: &[G],
        y: &[G],
        f: &F,
        A: &G,
        t: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        if g.len() < max_size as usize {
            return Err(CompSigmaError::VectorTooShort);
        }
        if P.len() != y.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if self.z_tilde.len() != max_size as usize {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let count_commitments = P.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^{n-1}]
        let challenge_powers = get_n_powers(challenge.clone(), count_commitments);
        let challenge_powers_repr = cfg_iter!(challenge_powers)
            .map(|c| c.into_bigint())
            .collect::<Vec<_>>();

        // P_tilde = A + \sum_{i}(P_i * c^i)
        let mut P_tilde = A.into_group();
        P_tilde += G::Group::msm_bigint(P, &challenge_powers_repr);

        // Check g*z_tilde == P_tilde
        let g_z = G::Group::msm_unchecked(g, &self.z_tilde);
        if g_z != P_tilde {
            return Err(CompSigmaError::InvalidResponse);
        }

        // Check \sum_{i}(y_i * c^i) + t == f(z_tilde)
        let c_y = G::Group::msm_bigint(y, &challenge_powers_repr);
        if (c_y + t).into_affine() != f.eval(&self.z_tilde).unwrap() {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    /// Compress a response to reduce its size to lg(n)
    pub fn compress<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        self,
        g: &[G],
        f: &F,
    ) -> compressed_homomorphism::Response<G> {
        compressed_homomorphism::RandomCommitment::compressed_response::<D, F>(
            self.z_tilde,
            g.to_vec(),
            f.clone(),
        )
    }

    /// Check if a compressed response is valid.
    pub fn is_valid_compressed<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        g: &[G],
        f: &F,
        Ps: &[G],
        ys: &[G],
        A: &G,
        t: &G,
        challenge: &G::ScalarField,
        compressed_resp: &compressed_homomorphism::Response<G>,
    ) -> Result<(), CompSigmaError> {
        let (Q, Y) = calculate_Q_and_Y::<G>(Ps, ys, A, t, challenge);
        compressed_resp.validate_compressed::<D, F>(Q, Y, g.to_vec(), f.clone())
    }
}

/// Q = A + \sum_{i}(P_i * c^i)
/// Y = t + \sum_{i}(Y_i * c^i)
pub fn calculate_Q_and_Y<G: AffineRepr>(
    Ps: &[G],
    Ys: &[G],
    A: &G,
    t: &G,
    challenge: &G::ScalarField,
) -> (G::Group, G::Group) {
    assert_eq!(Ps.len(), Ys.len());
    let count_commitments = Ps.len();
    let challenge_powers = get_n_powers(challenge.clone(), count_commitments);
    let challenge_powers_repr = cfg_iter!(challenge_powers)
        .map(|c| c.into_bigint())
        .collect::<Vec<_>>();

    let Q = G::Group::msm_bigint(Ps, &challenge_powers_repr) + A;
    let Y = G::Group::msm_bigint(Ys, &challenge_powers_repr) + t;
    (Q, Y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use std::time::Instant;

    type Fr = <Bls12_381 as Pairing>::ScalarField;
    type G1 = <Bls12_381 as Pairing>::G1Affine;

    #[derive(Clone)]
    struct TestHom<G: AffineRepr> {
        pub constants: Vec<G>,
    }

    impl_simple_homomorphism!(TestHom, Fr, G1);

    #[test]
    fn amortization() {
        fn check(max_size: u32) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let homomorphism = TestHom {
                constants: (0..max_size)
                    .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                    .collect::<Vec<_>>(),
            };

            let x1 = (0..max_size - 2)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x2 = (0..max_size - 1)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x3 = (0..max_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            let g = (0..max_size)
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();

            let comm1 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x1).into_affine();
            let eval1 = homomorphism.eval(&x1).unwrap();

            let comm2 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x2).into_affine();
            let eval2 = homomorphism.eval(&x2).unwrap();

            let comm3 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x3).into_affine();
            let eval3 = homomorphism.eval(&x3).unwrap();

            let rand_comm =
                RandomCommitment::new(&mut rng, &g, max_size, &homomorphism, None).unwrap();
            assert_eq!(rand_comm.r.len(), max_size as usize);
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm.response(vec![&x1, &x2, &x3], &challenge);
            assert_eq!(response.z_tilde.len(), max_size as usize);
            response
                .is_valid(
                    &g,
                    max_size,
                    &[comm1, comm2, comm3],
                    &[eval1, eval2, eval3],
                    &homomorphism,
                    &rand_comm.A,
                    &rand_comm.t,
                    &challenge,
                )
                .unwrap();
        }

        check(3);
        check(7);
        check(15);
        check(31);
    }

    #[test]
    fn amortization_and_compression() {
        let max_size = 8;

        let mut rng = StdRng::seed_from_u64(0u64);
        let homomorphism = TestHom {
            constants: (0..max_size)
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };

        let x1 = (0..max_size - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let x2 = (0..max_size - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let x3 = (0..max_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let g = (0..max_size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm1 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x1).into_affine();
        let eval1 = homomorphism.eval(&x1).unwrap();

        let comm2 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x2).into_affine();
        let eval2 = homomorphism.eval(&x2).unwrap();

        let comm3 = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x3).into_affine();
        let eval3 = homomorphism.eval(&x3).unwrap();

        let comms = [comm1, comm2, comm3];
        let evals = [eval1, eval2, eval3];

        let rand_comm = RandomCommitment::new(&mut rng, &g, max_size, &homomorphism, None).unwrap();
        assert_eq!(rand_comm.r.len(), max_size as usize);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(vec![&x1, &x2, &x3], &challenge);
        assert_eq!(response.z_tilde.len(), max_size as usize);

        let start = Instant::now();
        response
            .is_valid(
                &g,
                max_size,
                &comms,
                &evals,
                &homomorphism,
                &rand_comm.A,
                &rand_comm.t,
                &challenge,
            )
            .unwrap();
        println!(
            "Verification of uncompressed response of {} commitments, with max size {} takes: {:?}",
            comms.len(),
            max_size,
            start.elapsed()
        );

        let start = Instant::now();
        let comp_resp = response.compress::<Blake2b512, _>(&g, &homomorphism);
        println!(
            "Compressing response of {} commitments, with max size {} takes: {:?}",
            comms.len(),
            max_size,
            start.elapsed()
        );

        let start = Instant::now();
        Response::is_valid_compressed::<Blake2b512, _>(
            &g,
            &homomorphism,
            &comms,
            &evals,
            &rand_comm.A,
            &rand_comm.t,
            &challenge,
            &comp_resp,
        )
        .unwrap();
        println!(
            "Verification of compressed response of {} commitments, with max size {} takes: {:?}",
            comms.len(),
            max_size,
            start.elapsed()
        );
    }
}
