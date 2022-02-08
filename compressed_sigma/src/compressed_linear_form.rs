//! Compressed sigma protocol as described as Protocol 5 of the paper "Compressed Sigma Protocol Theory..."

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    cfg_iter,
    io::{Read, Write},
    ops::{Add, MulAssign},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use digest::Digest;

use crate::error::CompSigmaError;
use crate::transforms::LinearForm;
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub A_hat: G,
    pub t: G::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineCurve> {
    pub z_prime_0: G::ScalarField,
    pub z_prime_1: G::ScalarField,
    pub A: Vec<G>,
    pub B: Vec<G>,
}

impl<G> RandomCommitment<G>
where
    G: AffineCurve,
{
    pub fn new<R: RngCore, L: LinearForm<G::ScalarField>>(
        rng: &mut R,
        g: &[G],
        h: &G,
        linear_form: &L,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Self {
        assert!((g.len() + 1).is_power_of_two());
        let r = if let Some(blindings) = blindings {
            assert_eq!(blindings.len(), g.len());
            blindings
        } else {
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let rho = G::ScalarField::rand(rng);
        let t = linear_form.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();
        // h * rho is done separately to avoid copying g
        let A_hat = VariableBaseMSM::multi_scalar_mul(g, &scalars).add(&h.mul(rho.into_repr()));
        Self {
            r,
            rho,
            A_hat: A_hat.into_affine(),
            t,
        }
    }

    pub fn response<D: Digest, L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        P: &G,
        linear_form: &L,
        x: &[G::ScalarField],
        gamma: &G::ScalarField,
        y: &G::ScalarField,
        c_0: &G::ScalarField,
        c_1: &G::ScalarField,
    ) -> Response<G> {
        assert!((g.len() + 1).is_power_of_two());
        assert_eq!(g.len(), x.len());
        assert!(linear_form.size().is_power_of_two());
        assert_eq!(linear_form.size() - 1, x.len());

        let mut z_hat = x
            .iter()
            .zip(self.r.iter())
            .map(|(x_, r)| *x_ * c_0 + r)
            .collect::<Vec<_>>();
        let phi = *gamma * c_0 + self.rho;
        z_hat.push(phi);

        let mut g_hat = g.to_vec();
        g_hat.push(*h);
        let L_tilde = linear_form.scale(c_1);
        // Q = P*c_0 + k * (c_1*(c_0*y + t)) + A_hat
        let Q = (P.mul(c_0.into_repr()) + k.mul(*c_1 * (*c_0 * y + self.t))).add_mixed(&self.A_hat);

        Self::compressed_response::<D, L>(z_hat, Q, g_hat, k, L_tilde)
    }

    pub fn compressed_response<D: Digest, L: LinearForm<G::ScalarField>>(
        mut z_hat: Vec<G::ScalarField>,
        mut Q: G::Projective,
        mut g_hat: Vec<G>,
        k: &G,
        mut L_tilde: L,
    ) -> Response<G> {
        let mut bytes = vec![];

        let mut As = vec![];
        let mut Bs = vec![];

        while z_hat.len() > 2 {
            let m = g_hat.len();
            // Split `g_hat` into 2 halves, `g_hat` will be the 1st half and `g_hat_r` will be the 2nd
            let g_hat_r = g_hat.split_off(m / 2);
            // Split `z_hat` into 2 halves, `z_hat` will be the 1st half and `z_hat_r` will be the 2nd
            let z_hat_r = z_hat.split_off(m / 2);
            // Split `L_tilde` into 2 halves, `L_tilde_l` will be the 1st half and `L_tilde_r` will be the 2nd
            let (L_tilde_l, L_tilde_r) = L_tilde.split_in_half();

            let A = VariableBaseMSM::multi_scalar_mul(
                &g_hat_r,
                &z_hat.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            ) + k.mul(L_tilde_r.eval(&z_hat).into_repr());
            let B = VariableBaseMSM::multi_scalar_mul(
                &g_hat,
                &z_hat_r.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            ) + k.mul(L_tilde_l.eval(&z_hat_r).into_repr());

            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_repr();

            // Set `g_hat` as g' in the paper
            g_hat = g_hat
                .iter()
                .zip(g_hat_r.iter())
                .map(|(l, r)| l.mul(c_repr).add_mixed(r).into_affine())
                .collect::<Vec<_>>();
            // Set `Q` as Q' in the paper
            Q = A + Q.mul(c_repr) + B.mul(c.square().into_repr());
            // Set `L_tilde` to L' in the paper
            L_tilde = L_tilde_l.scale(&c).add(&L_tilde_r);
            // Set `z_hat` as z' in the paper
            z_hat = z_hat
                .iter()
                .zip(z_hat_r.iter())
                .map(|(l, r)| *l + *r * c)
                .collect::<Vec<_>>();
            As.push(A);
            Bs.push(B);
        }

        Response {
            z_prime_0: z_hat[0],
            z_prime_1: z_hat[1],
            A: batch_normalize_projective_into_affine(As),
            B: batch_normalize_projective_into_affine(Bs),
        }
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    pub fn is_valid_recursive<D: Digest, L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        P: &G,
        y: &G::ScalarField,
        linear_form: &L,
        A_hat: &G,
        t: &G::ScalarField,
        c_0: &G::ScalarField,
        c_1: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert!((g.len() + 1).is_power_of_two());
        assert_eq!(self.A.len(), self.B.len());
        assert_eq!(g.len() + 1, 1 << (self.A.len() + 1));
        assert!(linear_form.size().is_power_of_two());

        let mut g_hat = g.to_vec();
        g_hat.push(*h);
        let mut L_tilde = linear_form.scale(c_1);
        // Q = P*c_0 + k * (c_1*(c_0*y + t)) + A_hat
        let mut Q = (P.mul(c_0.into_repr()) + k.mul(*c_1 * (*c_0 * y + t))).add_mixed(&A_hat);

        let mut bytes = vec![];
        for (A, B) in self.A.iter().zip(self.B.iter()) {
            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_repr();

            let m = g_hat.len();
            let g_hat_r = g_hat.split_off(m / 2);

            g_hat = g_hat
                .iter()
                .zip(g_hat_r.iter())
                .map(|(l, r)| l.mul(c_repr).add_mixed(r).into_affine())
                .collect::<Vec<_>>();
            Q = A.into_projective() + Q.mul(c_repr) + B.mul(c.square().into_repr());
            let (L_tilde_l, L_tilde_r) = L_tilde.split_in_half();
            L_tilde = L_tilde_l.scale(&c).add(&L_tilde_r);
        }

        if (g_hat.len() != 2) || (L_tilde.size() != 2) {
            return Err(CompSigmaError::InvalidResponse);
        }

        let mut scalars = vec![self.z_prime_0.into_repr(), self.z_prime_1.into_repr()];
        let l_z = L_tilde.eval(&[self.z_prime_0, self.z_prime_1]);

        g_hat.push(*k);
        scalars.push(l_z.into_repr());

        if VariableBaseMSM::multi_scalar_mul(&g_hat, &scalars) == Q {
            Ok(())
        } else {
            Err(CompSigmaError::InvalidResponse)
        }
    }

    /// This will delay scalar multiplications till the end similar to whats described in the Bulletproofs
    /// paper, thus is faster than the naive version above
    pub fn is_valid<D: Digest, L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        P: &G,
        y: &G::ScalarField,
        linear_form: &L,
        A_hat: &G,
        t: &G::ScalarField,
        c_0: &G::ScalarField,
        c_1: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert!((g.len() + 1).is_power_of_two());
        assert_eq!(self.A.len(), self.B.len());
        assert_eq!(g.len() + 1, 1 << (self.A.len() + 1));
        assert!(linear_form.size().is_power_of_two());

        let mut g_hat = g.to_vec();
        g_hat.push(*h);
        let mut L_tilde = linear_form.scale(c_1);
        // Q = P*c_0 + k * (c_1*(c_0*y + t)) + A_hat
        let mut Q = (P.mul(c_0.into_repr()) + k.mul(*c_1 * (*c_0 * y + t))).add_mixed(&A_hat);

        let mut challenge_squares = vec![];
        let mut challenges = vec![];
        let g_len = g_hat.len();
        let mut g_hat_multiples = vec![G::ScalarField::one(); g_len];
        let mut bytes = vec![];
        for (A, B) in self.A.iter().zip(self.B.iter()) {
            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);

            let (L_tilde_l, L_tilde_r) = L_tilde.split_in_half();
            L_tilde = L_tilde_l.scale(&c).add(&L_tilde_r);

            challenge_squares.push(c.square());
            challenges.push(c);
        }

        for i in 0..challenges.len() {
            let p = 1 << (i + 1);
            let s = g_len / p;
            for j in (0..p).step_by(2) {
                for k in 0..s {
                    g_hat_multiples[j * s + k] *= challenges[i];
                }
            }
        }

        for i in 0..g_hat_multiples.len() {
            if (i % 2) == 0 {
                g_hat_multiples[i] *= self.z_prime_0;
            } else {
                g_hat_multiples[i] *= self.z_prime_1;
            }
        }

        // Convert challenge vector from [c_1, c_2, c_3, ..., c_{n-2}, c_{n-1}, c_n] to [c_1*c_2*c_3*..*c_{n-2}*c_{n-1}*c_n, c_2*c_3*..*c_{n-2}*c_{n-1}*c_n, c_3*..*c_{n-2}*c_{n-1}*c_n, ..., c_{n-2}*c_{n-1}*c_n, c_{n-1}*c_n, c_n]
        for i in (1..challenges.len()).rev() {
            let c = challenges[i - 1] * challenges[i];
            challenges[i - 1] = c;
        }

        // Set Q to Q*(c_1*c_2*c_3*..*c_{n-2}*c_{n-1}*c_n)
        Q.mul_assign(challenges.remove(0));
        challenges.push(G::ScalarField::one());

        let B_multiples = challenges
            .iter()
            .zip(challenge_squares.iter())
            .map(|(c, c_sqr)| (*c * c_sqr).into_repr())
            .collect::<Vec<_>>();
        let Q_prime = VariableBaseMSM::multi_scalar_mul(
            &self.A,
            &challenges
                .into_iter()
                .map(|c| c.into_repr())
                .collect::<Vec<_>>(),
        ) + VariableBaseMSM::multi_scalar_mul(&self.B, &B_multiples)
            + Q;

        let l_z = L_tilde.eval(&[self.z_prime_0, self.z_prime_1]);

        g_hat.push(*k);
        g_hat_multiples.push(l_z);

        if VariableBaseMSM::multi_scalar_mul(
            &g_hat,
            &g_hat_multiples
                .into_iter()
                .map(|m| m.into_repr())
                .collect::<Vec<_>>(),
        ) == Q_prime
        {
            Ok(())
        } else {
            Err(CompSigmaError::InvalidResponse)
        }
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
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    struct TestLinearForm {
        pub constants: Vec<Fr>,
    }

    impl LinearForm<Fr> for TestLinearForm {
        fn eval(&self, x: &[Fr]) -> Fr {
            self.constants
                .iter()
                .zip(x.iter())
                .fold(Fr::zero(), |accum, (c, i)| accum + *c * i)
        }

        fn scale(&self, scalar: &Fr) -> Self {
            Self {
                constants: self
                    .constants
                    .iter()
                    .map(|c| *c * scalar)
                    .collect::<Vec<_>>(),
            }
        }

        fn add(&self, other: &Self) -> Self {
            Self {
                constants: self
                    .constants
                    .iter()
                    .zip(other.constants.iter())
                    .map(|(a, b)| *a + b)
                    .collect::<Vec<_>>(),
            }
        }

        fn split_in_half(&self) -> (Self, Self) {
            (
                Self {
                    constants: self.constants[..self.constants.len() / 2].to_vec(),
                },
                Self {
                    constants: self.constants[self.constants.len() / 2..].to_vec(),
                },
            )
        }

        fn size(&self) -> usize {
            self.constants.len()
        }
    }

    #[test]
    fn compression() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let size = 31;
        let mut linear_form = TestLinearForm {
            constants: (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>(),
        };
        linear_form.constants.push(Fr::zero());

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let gamma = Fr::rand(&mut rng);
        let g = (0..size)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
        let k = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

        let P = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma.into_repr()))
        .into_affine();
        let y = linear_form.eval(&x);

        let rand_comm = RandomCommitment::new(&mut rng, &g, &h, &linear_form, None);

        let c_0 = Fr::rand(&mut rng);
        let c_1 = Fr::rand(&mut rng);

        let response = rand_comm.response::<Blake2b, _>(
            &g,
            &h,
            &k,
            &P,
            &linear_form,
            &x,
            &gamma,
            &y,
            &c_0,
            &c_1,
        );

        let start = Instant::now();
        response
            .is_valid_recursive::<Blake2b, _>(
                &g,
                &h,
                &k,
                &P,
                &y,
                &linear_form,
                &rand_comm.A_hat,
                &rand_comm.t,
                &c_0,
                &c_1,
            )
            .unwrap();
        println!(
            "Recursive verification for compressed linear form of size {} takes: {:?}",
            size,
            start.elapsed()
        );

        let start = Instant::now();
        response
            .is_valid::<Blake2b, _>(
                &g,
                &h,
                &k,
                &P,
                &y,
                &linear_form,
                &rand_comm.A_hat,
                &rand_comm.t,
                &c_0,
                &c_1,
            )
            .unwrap();
        println!(
            "Verification for compressed linear form of size {} takes: {:?}",
            size,
            start.elapsed()
        );
    }
}
