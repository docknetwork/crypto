//! Amortized sigma protocol with homomorphism as described in section 3.4 of the paper "Compressing Proofs of k-Out-Of-n".
//! This is for the relation R_{AMOREXP} where a single homomorphism is applied over many witness vectors and
//! there is a separate commitment to each witness vector.

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{cfg_iter, vec, vec::Vec, UniformRand};
use ark_std::{
    io::{Read, Write},
    ops::Add,
    rand::RngCore,
};

use crate::error::CompSigmaError;
use crate::transforms::Homomorphism;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub max_size: usize,
    pub r: Vec<G::ScalarField>,
    pub A: G,
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineCurve> {
    pub z: Vec<G::ScalarField>,
}

impl<G> RandomCommitment<G>
where
    G: AffineCurve,
{
    pub fn new<R: RngCore, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        max_size: usize,
        f: &F,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Self {
        assert!(g.len() >= max_size);
        let r = if let Some(blindings) = blindings {
            assert_eq!(blindings.len(), max_size);
            blindings
        } else {
            (0..max_size).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = f.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();
        let A = VariableBaseMSM::multi_scalar_mul(g, &scalars);
        Self {
            max_size,
            r,
            A: A.into_affine(),
            t,
        }
    }

    pub fn response(
        &self,
        witnesses: Vec<&[G::ScalarField]>,
        challenge: &G::ScalarField,
    ) -> Response<G> {
        let count_commitments = witnesses.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^{n-1}]
        let mut challenge_powers = vec![challenge.clone(); count_commitments];
        for i in 1..count_commitments {
            challenge_powers[i] = challenge_powers[i - 1] * *challenge;
        }
        let mut zs = vec![];
        for i in 0..self.max_size {
            let mut z = self.r[i];
            for j in 0..count_commitments {
                if witnesses.len() > j && witnesses[j].len() > i {
                    z += challenge_powers[j] * witnesses[j][i];
                }
            }
            zs.push(z);
        }
        Response { z: zs }
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    pub fn is_valid<F: Homomorphism<G::ScalarField, Output = G>>(
        &self,
        g: &[G],
        max_size: usize,
        commitments: &[G],
        evals: &[G],
        f: &F,
        A: &G,
        t: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert!(g.len() >= max_size);
        assert_eq!(commitments.len(), evals.len());
        let count_commitments = commitments.len();
        let mut challenge_powers = vec![challenge.clone(); count_commitments];
        for i in 1..count_commitments {
            challenge_powers[i] = challenge_powers[i - 1] * *challenge;
        }
        let challenge_powers_repr = cfg_iter!(challenge_powers)
            .map(|c| c.into_repr())
            .collect::<Vec<_>>();
        let mut P_tilde = A.into_projective();
        P_tilde += VariableBaseMSM::multi_scalar_mul(commitments, &challenge_powers_repr);

        // g*z == P_tilde
        let g_z = VariableBaseMSM::multi_scalar_mul(
            g,
            &self.z.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
        );
        if g_z != P_tilde {
            return Err(CompSigmaError::InvalidResponse);
        }

        let c_y = VariableBaseMSM::multi_scalar_mul(evals, &challenge_powers_repr);
        if c_y.add_mixed(t).into_affine() != f.eval(&self.z) {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_ff::One;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b;
    use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1 = <Bls12_381 as PairingEngine>::G1Affine;

    #[derive(Clone)]
    struct TestHom<G: AffineCurve> {
        pub constants: Vec<G>,
    }

    impl_simple_homomorphism!(TestHom, Fr, G1);

    #[test]
    fn amortization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 7;
        let homomorphism = TestHom {
            constants: (0..max_size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
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
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm1 = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x1.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let eval1 = homomorphism.eval(&x1);

        let comm2 = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x2.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let eval2 = homomorphism.eval(&x2);

        let comm3 = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x3.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let eval3 = homomorphism.eval(&x3);

        let rand_comm = RandomCommitment::new(&mut rng, &g, max_size, &homomorphism, None);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(vec![&x1, &x2, &x3], &challenge);
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
}
