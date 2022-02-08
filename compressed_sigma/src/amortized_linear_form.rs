//! Amortized sigma protocol as described in Appendix B of the paper "Compressed Sigma Protocol Theory..."

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
use crate::transforms::LinearForm;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub max_size: usize,
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub A: G,
    pub t: G::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineCurve> {
    pub z_tilde: Vec<G::ScalarField>,
    pub phi: G::ScalarField,
}

impl<G> RandomCommitment<G>
where
    G: AffineCurve,
{
    pub fn new<R: RngCore, L: LinearForm<G::ScalarField>>(
        rng: &mut R,
        g: &[G],
        h: &G,
        max_size: usize,
        linear_form: &L,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Self {
        assert!(g.len() >= max_size);
        let r = if let Some(blindings) = blindings {
            assert_eq!(blindings.len(), max_size);
            blindings
        } else {
            (0..max_size).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let rho = G::ScalarField::rand(rng);
        let t = linear_form.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();
        // h * rho is done separately to avoid copying g
        let A = VariableBaseMSM::multi_scalar_mul(g, &scalars).add(&h.mul(rho.into_repr()));
        Self {
            max_size,
            r,
            rho,
            A: A.into_affine(),
            t,
        }
    }

    pub fn response(
        &self,
        witnesses: Vec<&[G::ScalarField]>,
        gammas: Vec<&G::ScalarField>,
        challenge: &G::ScalarField,
    ) -> Response<G> {
        assert_eq!(witnesses.len(), gammas.len());
        let count_commitments = witnesses.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^{n-1}]
        let mut challenge_powers = vec![challenge.clone(); count_commitments];
        for i in 1..count_commitments {
            challenge_powers[i] = challenge_powers[i - 1] * *challenge;
        }
        let mut z_tilde = vec![];
        for i in 0..self.max_size {
            let mut z = self.r[i];
            for j in 0..count_commitments {
                if witnesses.len() > j && witnesses[j].len() > i {
                    z += challenge_powers[j] * witnesses[j][i];
                }
            }
            z_tilde.push(z);
        }
        let mut phi = self.rho;
        for i in 0..count_commitments {
            phi += challenge_powers[i] * gammas[i];
        }
        Response { phi, z_tilde }
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    pub fn is_valid<L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        max_size: usize,
        commitments: &[G],
        evals: &[G::ScalarField],
        linear_form: &L,
        A: &G,
        t: &G::ScalarField,
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

        // g*z + h*phi == P_tilde
        let z_tilde_repr = cfg_iter!(self.z_tilde)
            .map(|z| z.into_repr())
            .collect::<Vec<_>>();
        let g_z = VariableBaseMSM::multi_scalar_mul(g, &z_tilde_repr);
        let h_phi = h.mul(self.phi);
        if (g_z + h_phi) != P_tilde {
            return Err(CompSigmaError::InvalidResponse);
        }

        // c*y + t == L(z)
        let mut c_y = G::ScalarField::zero();
        for i in 0..count_commitments {
            c_y += challenge_powers[i] * evals[i];
        }
        if !(c_y + t - linear_form.eval(&self.z_tilde)).is_zero() {
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
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    struct TestLinearForm1 {}

    impl LinearForm<Fr> for TestLinearForm1 {
        fn eval(&self, x: &[Fr]) -> Fr {
            x.iter().fold(Fr::zero(), |accum, item| accum + item)
        }

        fn scale(&self, _scalar: &Fr) -> Self {
            TestLinearForm1 {}
        }

        fn add(&self, _other: &Self) -> Self {
            TestLinearForm1 {}
        }

        fn split_in_half(&self) -> (Self, Self) {
            unimplemented!()
        }

        fn size(&self) -> usize {
            unimplemented!()
        }
    }

    struct TestLinearForm2 {
        pub constants: Vec<Fr>,
    }

    impl LinearForm<Fr> for TestLinearForm2 {
        fn eval(&self, x: &[Fr]) -> Fr {
            self.constants
                .iter()
                .zip(x.iter())
                .fold(Fr::zero(), |accum, (c, i)| accum + *c * i)
        }

        fn scale(&self, scalar: &Fr) -> Self {
            TestLinearForm2 {
                constants: self
                    .constants
                    .iter()
                    .map(|c| *c * scalar)
                    .collect::<Vec<_>>(),
            }
        }

        fn add(&self, other: &Self) -> Self {
            TestLinearForm2 {
                constants: self
                    .constants
                    .iter()
                    .zip(other.constants.iter())
                    .map(|(a, b)| *a + b)
                    .collect::<Vec<_>>(),
            }
        }

        fn split_in_half(&self) -> (Self, Self) {
            unimplemented!()
        }

        fn size(&self) -> usize {
            unimplemented!()
        }
    }

    #[test]
    fn amortization() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let max_size = 7;
        let linear_form_1 = TestLinearForm1 {};
        let linear_form_2 = TestLinearForm2 {
            constants: (0..max_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>(),
        };

        let x1 = (0..max_size - 2)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let gamma1 = Fr::rand(&mut rng);
        let x2 = (0..max_size - 1)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let gamma2 = Fr::rand(&mut rng);
        let x3 = (0..max_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let gamma3 = Fr::rand(&mut rng);

        let g = (0..max_size)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

        let comm1 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x1.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma1.into_repr()))
        .into_affine();
        let eval1 = linear_form_1.eval(&x1);
        let eval12 = linear_form_2.eval(&x1);

        let comm2 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x2.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma2.into_repr()))
        .into_affine();
        let eval2 = linear_form_1.eval(&x2);
        let eval22 = linear_form_2.eval(&x2);

        let comm3 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x3.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma3.into_repr()))
        .into_affine();
        let eval3 = linear_form_1.eval(&x3);
        let eval32 = linear_form_2.eval(&x3);

        let rand_comm = RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_1, None);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(
            vec![&x1, &x2, &x3],
            vec![&gamma1, &gamma2, &gamma3],
            &challenge,
        );
        response
            .is_valid(
                &g,
                &h,
                max_size,
                &[comm1, comm2, comm3],
                &[eval1, eval2, eval3],
                &linear_form_1,
                &rand_comm.A,
                &rand_comm.t,
                &challenge,
            )
            .unwrap();

        let rand_comm = RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_2, None);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(
            vec![&x1, &x2, &x3],
            vec![&gamma1, &gamma2, &gamma3],
            &challenge,
        );
        response
            .is_valid(
                &g,
                &h,
                max_size,
                &[comm1, comm2, comm3],
                &[eval12, eval22, eval32],
                &linear_form_2,
                &rand_comm.A,
                &rand_comm.t,
                &challenge,
            )
            .unwrap();
    }
}
