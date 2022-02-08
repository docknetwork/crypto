//! Compressed sigma protocol with homomorphism as described in section 3 of the paper "Compressing Proofs of k-Out-Of-n".

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::RngCore;
use ark_std::{
    cfg_iter,
    io::{Read, Write},
    ops::{Mul, MulAssign},
    vec,
    vec::Vec,
    UniformRand,
};
use digest::Digest;

use crate::error::CompSigmaError;
use crate::transforms::Homomorphism;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// TODO: Add a different type parameter for `t` in RandomCommitment and `a` and `b` in Response. It should
// not be mandatory for the result of homomorphism to be of the same type

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub r: Vec<G::ScalarField>,
    pub A_hat: G,
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineCurve> {
    pub z_prime_0: G::ScalarField,
    pub z_prime_1: G::ScalarField,
    pub A: Vec<G>,
    pub B: Vec<G>,
    pub a: Vec<G>,
    pub b: Vec<G>,
}

impl<G> RandomCommitment<G>
where
    G: AffineCurve,
{
    pub fn new<R: RngCore, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        homomorphism: &F,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Self {
        assert!(g.len().is_power_of_two());
        let r = if let Some(blindings) = blindings {
            assert_eq!(blindings.len(), g.len());
            blindings
        } else {
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = homomorphism.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();

        let A_hat = VariableBaseMSM::multi_scalar_mul(g, &scalars);
        Self {
            r,
            A_hat: A_hat.into_affine(),
            t,
        }
    }

    pub fn response<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        P: &G,
        f: &F,
        x: &[G::ScalarField],
        c_0: &G::ScalarField,
    ) -> Response<G> {
        assert!(g.len().is_power_of_two());
        assert_eq!(g.len(), x.len());
        assert!(f.size().is_power_of_two());
        assert_eq!(f.size(), x.len());

        let z = x
            .iter()
            .zip(self.r.iter())
            .map(|(x_, r)| *x_ * c_0 + r)
            .collect::<Vec<_>>();

        Self::compressed_response::<D, F>(z, &self.A_hat, P, g.to_vec(), f, c_0)
    }

    pub fn compressed_response<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        mut z: Vec<G::ScalarField>,
        A_hat: &G,
        P: &G,
        mut g: Vec<G>,
        f: &F,
        c_0: &G::ScalarField,
    ) -> Response<G> {
        let mut bytes = vec![];

        let mut As = vec![];
        let mut Bs = vec![];
        let mut as_ = vec![];
        let mut bs = vec![];

        let mut Q = P.mul(c_0.into_repr()).add_mixed(&A_hat);
        let mut f = f.clone();

        while z.len() > 2 {
            let m = g.len();
            // Split `g` into 2 halves, `g` will be the 1st half and `g_r` will be the 2nd
            let g_r = g.split_off(m / 2);
            // Split `z` into 2 halves, `z` will be the 1st half and `z_r` will be the 2nd
            let z_r = z.split_off(m / 2);
            // Split `f` into 2 halves, `f_l` will be the 1st half and `f_r` will be the 2nd
            let (f_l, f_r) = f.split_in_half();

            let A = VariableBaseMSM::multi_scalar_mul(
                &g_r,
                &z.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            );
            let B = VariableBaseMSM::multi_scalar_mul(
                &g,
                &z_r.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            );
            let a = f_r.eval(&z);
            let b = f_l.eval(&z_r);

            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            a.serialize(&mut bytes).unwrap();
            b.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_repr();

            // Set `g` as g' in the paper
            g = g
                .iter()
                .zip(g_r.iter())
                .map(|(l, r)| l.mul(c_repr).add_mixed(r).into_affine())
                .collect::<Vec<_>>();
            Q = A + Q.mul(c_repr) + B.mul(c.square().into_repr());
            // Set `f` to f' in the paper
            f = f_l.scale(&c).add(&f_r);
            z = z
                .iter()
                .zip(z_r.iter())
                .map(|(l, r)| *l + *r * c)
                .collect::<Vec<_>>();
            As.push(A);
            Bs.push(B);
            as_.push(a);
            bs.push(b);
        }

        Response {
            z_prime_0: z[0],
            z_prime_1: z[1],
            A: batch_normalize_projective_into_affine(As),
            B: batch_normalize_projective_into_affine(Bs),
            a: as_,
            b: bs,
        }
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    pub fn is_valid_recursive<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        P: &G,
        y: &G,
        f: &F,
        A_hat: &G,
        t: &G,
        c_0: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert!(g.len().is_power_of_two());
        assert_eq!(self.A.len(), self.B.len());
        assert_eq!(self.a.len(), self.b.len());
        assert_eq!(self.A.len(), self.a.len());
        assert_eq!(g.len(), 1 << (self.A.len() + 1));
        assert!(f.size().is_power_of_two());

        let mut g = g.to_vec();
        let mut f = f.clone();
        let c_0_repr = c_0.into_repr();
        let mut Q = P.mul(c_0_repr).add_mixed(A_hat);
        let mut Y = y.mul(c_0_repr).add_mixed(t);

        let mut bytes = vec![];
        for i in 0..self.A.len() {
            let A = &self.A[i];
            let B = &self.B[i];
            let a = &self.a[i];
            let b = &self.b[i];

            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            a.serialize(&mut bytes).unwrap();
            b.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_repr();

            let m = g.len();
            let g_r = g.split_off(m / 2);

            g = g
                .iter()
                .zip(g_r.iter())
                .map(|(l, r)| l.mul(c_repr).add_mixed(r).into_affine())
                .collect::<Vec<_>>();

            let (f_l, f_r) = f.split_in_half();
            f = f_l.scale(&c).add(&f_r);

            let c_sq = c.square().into_repr();
            Q = A.into_projective() + Q.mul(c_repr) + B.mul(c_sq);
            Y = a.into_projective() + Y.mul(c_repr) + b.mul(c_sq);
        }

        if (g.len() != 2) || (f.size() != 2) {
            return Err(CompSigmaError::InvalidResponse);
        }

        if VariableBaseMSM::multi_scalar_mul(
            &g,
            &[self.z_prime_0.into_repr(), self.z_prime_1.into_repr()],
        ) != Q
        {
            return Err(CompSigmaError::InvalidResponse);
        }

        let f_prime_z_prime = f.eval(&[self.z_prime_0, self.z_prime_1]).into_projective();

        if Y != f_prime_z_prime {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    /// This will delay scalar multiplications till the end similar to whats described in the Bulletproofs
    /// paper, thus is faster than the naive version above
    pub fn is_valid<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        P: &G,
        y: &G,
        f: &F,
        A_hat: &G,
        t: &G,
        c_0: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert!(g.len().is_power_of_two());
        assert_eq!(self.A.len(), self.B.len());
        assert_eq!(self.a.len(), self.b.len());
        assert_eq!(self.A.len(), self.a.len());
        assert_eq!(g.len(), 1 << (self.A.len() + 1));
        assert!(f.size().is_power_of_two());

        let g = g.to_vec();
        let mut f = f.clone();
        let c_0_repr = c_0.into_repr();
        let mut Q = P.mul(c_0_repr).add_mixed(A_hat);
        let mut Y = y.mul(c_0_repr).add_mixed(t);

        let mut challenge_squares = vec![];
        let mut challenges = vec![];
        let g_len = g.len();
        let mut g_multiples = vec![G::ScalarField::one(); g_len];
        let mut bytes = vec![];
        for i in 0..self.A.len() {
            let A = &self.A[i];
            let B = &self.B[i];
            let a = &self.a[i];
            let b = &self.b[i];

            A.serialize(&mut bytes).unwrap();
            B.serialize(&mut bytes).unwrap();
            a.serialize(&mut bytes).unwrap();
            b.serialize(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);

            // TODO: When `f` is an elliptic curve group, the following can use MSM and can be taken out
            // of this loop
            let (f_l, f_r) = f.split_in_half();
            f = f_l.scale(&c).add(&f_r);

            challenge_squares.push(c.square());
            challenges.push(c);
        }

        for i in 0..challenges.len() {
            let p = 1 << (i + 1);
            let s = g_len / p;
            for j in (0..p).step_by(2) {
                for k in 0..s {
                    g_multiples[j * s + k] *= challenges[i];
                }
            }
        }

        for i in 0..g_multiples.len() {
            if (i % 2) == 0 {
                g_multiples[i] *= self.z_prime_0;
            } else {
                g_multiples[i] *= self.z_prime_1;
            }
        }

        // Convert challenge vector from [c_1, c_2, c_3, ..., c_{n-2}, c_{n-1}, c_n] to [c_1*c_2*c_3*..*c_{n-2}*c_{n-1}*c_n, c_2*c_3*..*c_{n-2}*c_{n-1}*c_n, c_3*..*c_{n-2}*c_{n-1}*c_n, ..., c_{n-2}*c_{n-1}*c_n, c_{n-1}*c_n, c_n]
        for i in (1..challenges.len()).rev() {
            let c = challenges[i - 1] * challenges[i];
            challenges[i - 1] = c;
        }

        // Set Q to Q*(c_1*c_2*c_3*..*c_{n-2}*c_{n-1}*c_n)
        let all_challenges_product = challenges.remove(0);
        Q.mul_assign(all_challenges_product);
        Y.mul_assign(all_challenges_product);

        challenges.push(G::ScalarField::one());

        let B_multiples = challenges
            .iter()
            .zip(challenge_squares.iter())
            .map(|(c, c_sqr)| (*c * c_sqr).into_repr())
            .collect::<Vec<_>>();

        let challenges_repr = cfg_iter!(challenges)
            .map(|c| c.into_repr())
            .collect::<Vec<_>>();
        let Q_prime = VariableBaseMSM::multi_scalar_mul(&self.A, &challenges_repr)
            + VariableBaseMSM::multi_scalar_mul(&self.B, &B_multiples)
            + Q;

        let Y_prime = VariableBaseMSM::multi_scalar_mul(&self.a, &challenges_repr)
            + VariableBaseMSM::multi_scalar_mul(&self.b, &B_multiples)
            + Y;

        let g_multiples_repr = cfg_iter!(g_multiples)
            .map(|g| g.into_repr())
            .collect::<Vec<_>>();
        if VariableBaseMSM::multi_scalar_mul(&g, &g_multiples_repr) != Q_prime {
            return Err(CompSigmaError::InvalidResponse);
        }

        let f_prime_z_prime = f.eval(&[self.z_prime_0, self.z_prime_1]).into_projective();

        if Y_prime != f_prime_z_prime {
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
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1 = <Bls12_381 as PairingEngine>::G1Affine;

    #[derive(Clone)]
    struct TestHom<G: AffineCurve> {
        pub constants: Vec<G>,
    }

    impl_simple_homomorphism!(TestHom, Fr, G1);

    #[test]
    fn compression() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let size = 16;
        let homomorphism = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let P = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();
        let y = homomorphism.eval(&x);

        let rand_comm = RandomCommitment::new(&mut rng, &g, &homomorphism, None);

        let c_0 = Fr::rand(&mut rng);

        let response = rand_comm.response::<Blake2b, _>(&g, &P, &homomorphism, &x, &c_0);

        let start = Instant::now();
        response
            .is_valid_recursive::<Blake2b, _>(
                &g,
                &P,
                &y,
                &homomorphism,
                &rand_comm.A_hat,
                &rand_comm.t,
                &c_0,
            )
            .unwrap();
        println!(
            "Recursive verification for compressed homomorphism form of size {} takes: {:?}",
            size,
            start.elapsed()
        );

        let start = Instant::now();
        response
            .is_valid::<Blake2b, _>(
                &g,
                &P,
                &y,
                &homomorphism,
                &rand_comm.A_hat,
                &rand_comm.t,
                &c_0,
            )
            .unwrap();
        println!(
            "Verification for compressed homomorphism form of size {} takes: {:?}",
            size,
            start.elapsed()
        );
    }
}
