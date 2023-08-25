//! Compressed sigma protocol with homomorphism as described in section 3 of the paper "Compressing Proofs of k-Out-Of-n".

use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, ops::MulAssign, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;

use crate::{error::CompSigmaError, transforms::Homomorphism};
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

use crate::utils::{elements_to_element_products, get_g_multiples_for_verifying_compression};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// TODO: Add a different type parameter for `t` in RandomCommitment and `a` and `b` in Response. It should
// not be mandatory for the result of homomorphism to be of the same type

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineRepr> {
    pub r: Vec<G::ScalarField>,
    pub A_hat: G,
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineRepr> {
    pub z_prime_0: G::ScalarField,
    pub z_prime_1: G::ScalarField,
    pub A: Vec<G>,
    pub B: Vec<G>,
    pub a: Vec<G>,
    pub b: Vec<G>,
}

impl<G> RandomCommitment<G>
where
    G: AffineRepr,
{
    pub fn new<R: RngCore, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        homomorphism: &F,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Result<Self, CompSigmaError> {
        if !g.len().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        let r = if let Some(blindings) = blindings {
            if blindings.len() != g.len() {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            blindings
        } else {
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = homomorphism.eval(&r).unwrap();

        let A_hat = G::Group::msm_unchecked(g, &r);
        Ok(Self {
            r,
            A_hat: A_hat.into_affine(),
            t,
        })
    }

    pub fn response<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        f: &F,
        x: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> Result<Response<G>, CompSigmaError> {
        if !g.len().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if g.len() != x.len() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if !f.size().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if f.size() != x.len() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }

        // z = [c_0 * r_0 + x_0, c_0 * r_1 + x_1, ..., c_0 * r_n + x_n]
        let z = x
            .iter()
            .zip(self.r.iter())
            .map(|(x_, r)| *x_ * challenge + r)
            .collect::<Vec<_>>();

        Ok(Self::compressed_response::<D, F>(z, g.to_vec(), f.clone()))
    }

    pub fn compressed_response<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        mut z: Vec<G::ScalarField>,
        mut g: Vec<G>,
        mut f: F,
    ) -> Response<G> {
        let mut bytes = vec![];

        let mut As = vec![];
        let mut Bs = vec![];
        let mut as_ = vec![];
        let mut bs = vec![];

        while z.len() > 2 {
            let m = g.len();
            // Split `g` into 2 halves, `g` will be the 1st half and `g_r` will be the 2nd
            let g_r = g.split_off(m / 2);
            // Split `z` into 2 halves, `z` will be the 1st half and `z_r` will be the 2nd
            let z_r = z.split_off(m / 2);
            // Split `f` into 2 halves, `f_l` will be the 1st half and `f_r` will be the 2nd
            let (f_l, f_r) = f.split_in_half();

            let A = G::Group::msm_unchecked(&g_r, &z);
            let B = G::Group::msm_unchecked(&g, &z_r);
            let a = f_r.eval(&z).unwrap();
            let b = f_l.eval(&z_r).unwrap();

            A.serialize_compressed(&mut bytes).unwrap();
            B.serialize_compressed(&mut bytes).unwrap();
            a.serialize_compressed(&mut bytes).unwrap();
            b.serialize_compressed(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_bigint();

            // Set `g` as g' in the paper
            g = g
                .iter()
                .zip(g_r.iter())
                .map(|(l, r)| (l.mul_bigint(c_repr) + r).into_affine())
                .collect::<Vec<_>>();
            // Set `f` to f' in the paper
            f = f_l.scale(&c).add(&f_r).unwrap();
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
            A: G::Group::normalize_batch(&As),
            B: G::Group::normalize_batch(&Bs),
            a: as_,
            b: bs,
        }
    }
}

impl<G> Response<G>
where
    G: AffineRepr,
{
    /// Check if response is valid. A naive and thus slower implementation than `is_valid`
    pub fn is_valid_recursive<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        P: &G,
        y: &G,
        f: &F,
        A_hat: &G,
        t: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        self.check_sizes(g, f)?;

        let (Q, Y) = calculate_Q_and_Y(P, y, A_hat, t, challenge);
        self.recursively_validate_compressed::<D, F>(Q, Y, g.to_vec(), f.clone())
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
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        self.check_sizes(g, f)?;

        let (Q, Y) = calculate_Q_and_Y(P, y, A_hat, t, challenge);
        self.validate_compressed::<D, F>(Q, Y, g.to_vec(), f.clone())
    }

    pub fn recursively_validate_compressed<
        D: Digest,
        F: Homomorphism<G::ScalarField, Output = G> + Clone,
    >(
        &self,
        mut Q: G::Group,
        mut Y: G::Group,
        mut g: Vec<G>,
        mut f: F,
    ) -> Result<(), CompSigmaError> {
        let mut bytes = vec![];
        for i in 0..self.A.len() {
            let A = &self.A[i];
            let B = &self.B[i];
            let a = &self.a[i];
            let b = &self.b[i];

            A.serialize_compressed(&mut bytes).unwrap();
            B.serialize_compressed(&mut bytes).unwrap();
            a.serialize_compressed(&mut bytes).unwrap();
            b.serialize_compressed(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
            let c_repr = c.into_bigint();

            let m = g.len();
            let g_r = g.split_off(m / 2);

            g = g
                .iter()
                .zip(g_r.iter())
                .map(|(l, r)| (l.mul_bigint(c_repr) + r).into_affine())
                .collect::<Vec<_>>();

            let (f_l, f_r) = f.split_in_half();
            f = f_l.scale(&c).add(&f_r).unwrap();

            let c_sq = c.square().into_bigint();
            Q = A.into_group() + Q.mul_bigint(c_repr) + B.mul_bigint(c_sq);
            Y = a.into_group() + Y.mul_bigint(c_repr) + b.mul_bigint(c_sq);
        }

        if (g.len() != 2) || (f.size() != 2) {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }

        if G::Group::msm_unchecked(&g, &[self.z_prime_0, self.z_prime_1]) != Q {
            return Err(CompSigmaError::InvalidResponse);
        }

        let f_prime_z_prime = f
            .eval(&[self.z_prime_0, self.z_prime_1])
            .unwrap()
            .into_group();

        if Y != f_prime_z_prime {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    pub fn validate_compressed<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        mut Q: G::Group,
        mut Y: G::Group,
        g: Vec<G>,
        f: F,
    ) -> Result<(), CompSigmaError> {
        // Create challenges for each round and store in `challenges`
        let mut challenges = vec![];
        // Holds squares of challenge of each round
        let mut challenge_squares = vec![];
        let mut bytes = vec![];
        for i in 0..self.A.len() {
            let A = &self.A[i];
            let B = &self.B[i];
            let a = &self.a[i];
            let b = &self.b[i];

            A.serialize_compressed(&mut bytes).unwrap();
            B.serialize_compressed(&mut bytes).unwrap();
            a.serialize_compressed(&mut bytes).unwrap();
            b.serialize_compressed(&mut bytes).unwrap();
            let c = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);

            challenge_squares.push(c.square());
            challenges.push(c);
        }

        // Calculate the final g' and Q' for checking the relations Q' == g' * z' and f'(z') == a + c * y + c^2 * b
        let g_len = g.len();

        // Multiples of original g vector to create the final product g' * z'
        // The same multiples are also used for the homomorphism
        let g_multiples = get_g_multiples_for_verifying_compression(
            g_len,
            &challenges,
            &self.z_prime_0,
            &self.z_prime_1,
        );

        // In each round, new Q_{i+1} = A_{i+1} + c_{i+1} * Q_i + c_{i+1}^2 * B_{i+1} where A_{i+1}, B_{i+1} and c_{i+1} are
        // A, B and the challenge for that round, thus in the final Q, contribution of original Q is {c_1*c_2*c_3*..*c_n} * Q.
        // Also, expanding Q_i in Q_{i+1} = A_{i+1} + c_{i+1} * Q_i + c_{i+1}^2 * B_{i+1}
        // = A_{i+1} + c_{i+1} * (A_{i} + c_{i} * Q_{i-1} + c_{i}^2 * B_{i}) + c_{i+1}^2 * B_{i+1}
        // = A_{i+1} + c_{i+1} * A_{i} + c_{i+1} * c_i * Q_{i-1} + c_{i+1} * c_{i}^2 * B_{i} + c_{i+1}^2 * B_{i+1}
        // From above, contribution of A vector in final Q will be A_1 * (c_2*c_3*..*c_n) + A_2 * (c_3*c_4..*c_n) + ... + A_n.
        // Similarly, contribution of B vector in final Q will be B_1 * (c_1^2*c_2*c_3*...*c_n) + B_2 * (c_2^2*c_3*...*c_n) + ... + B_n * c_n^2
        // Similar logic is followed for constructing Y as well.

        // Convert challenge vector from [c_1, c_2, c_3, ..., c_n] to [c_1*c_2*c_3*..*c_n, c_2*c_3*..*c_n, ..., c_{n-1}*c_n, c_n]
        let mut challenge_products = elements_to_element_products(challenges);

        // c_1*c_2*c_3*...*c_n
        let all_challenges_product = challenge_products.remove(0);

        // `B_multiples` is of form [c_1^2*c_2*c_3*..*c_n, c_2^2*c_3*c_4..*c_n, ..., c_{n-1}^2*c_n, c_n^2]
        let B_multiples = cfg_iter!(challenge_products)
            .zip(cfg_iter!(challenge_squares))
            .map(|(c, c_sqr)| (*c * c_sqr).into_bigint())
            .collect::<Vec<_>>();

        let challenges_repr = cfg_iter!(challenge_products)
            .map(|c| c.into_bigint())
            .collect::<Vec<_>>();

        // Q' = A * [c_2*c_3*...*c_n, c_3*...*c_n, ..., c_{n-1}*c_n, c_n, 1] + B * [c_1^2*c_2*c_3*...*c_n, c_2^2*c_3...*c_n, ..., c_{n-1}^2*c_n, c_n^2] + Q * c_1^2*c_2*c_3*...*c_n
        // Set Q to Q*(c_1*c_2*c_3*...*c_n)
        Q.mul_assign(all_challenges_product);
        let Q_prime = G::Group::msm_bigint(&self.A, &challenges_repr)
            + G::Group::msm_bigint(&self.B, &B_multiples)
            + Q;

        // Check if g' * z' == Q'
        if G::Group::msm_unchecked(&g, &g_multiples) != Q_prime {
            return Err(CompSigmaError::InvalidResponse);
        }

        // Check if f'(z') == a + c * Y + c^2 * b'

        // Y' = a + c * Y + c^2 * b'
        // Y' = a * [c_2*c_3*...*c_n, c_3*...*c_n, ..., c_{n-1}*c_n, c_n, 1] + b * [c_1^2*c_2*...*c_n, c_2^2*c_3*...*c_n, ..., c_{n-1}^2*c_n, c_n^2] + Y
        // Set Y to Y*(c_1*c_2*...*c_n)
        Y.mul_assign(all_challenges_product);
        let Y_prime = G::Group::msm_bigint(&self.a, &challenges_repr)
            + G::Group::msm_bigint(&self.b, &B_multiples)
            + Y;
        let f_prime_z_prime = f.eval(&g_multiples).unwrap().into_group();
        if Y_prime != f_prime_z_prime {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    fn check_sizes<F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        f: &F,
    ) -> Result<(), CompSigmaError> {
        if !g.len().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if self.A.len() != self.B.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if self.a.len() != self.b.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if self.A.len() != self.a.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if g.len() != 1 << (self.A.len() + 1) {
            return Err(CompSigmaError::WrongRecursionLevel);
        }
        if !f.size().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        Ok(())
    }
}

/// Q = A + P * challenge
/// Y = t + Y * challenge
pub fn calculate_Q_and_Y<G: AffineRepr>(
    P: &G,
    Y: &G,
    A: &G,
    t: &G,
    challenge: &G::ScalarField,
) -> (G::Group, G::Group) {
    let challenge_repr = challenge.into_bigint();
    (
        P.mul_bigint(challenge_repr) + A,
        Y.mul_bigint(challenge_repr) + t,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;
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
    fn compression() {
        fn check_compression(size: u32) {
            let mut rng = StdRng::seed_from_u64(0u64);
            // Setup
            let mut homomorphism = TestHom {
                constants: (0..size)
                    .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                    .collect::<Vec<_>>(),
            };

            let mut x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let mut g = (0..size)
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();

            // Pad if necessary
            if !size.is_power_of_two() {
                let new_size = size.next_power_of_two();
                let pod_size = new_size - size;
                homomorphism = homomorphism.pad(new_size);
                for _ in 0..pod_size {
                    x.push(Fr::zero());
                    g.push(<Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine());
                }
            }

            let P = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine();
            let y = homomorphism.eval(&x).unwrap();

            let rand_comm = RandomCommitment::new(&mut rng, &g, &homomorphism, None).unwrap();

            let challenge = Fr::rand(&mut rng);

            let response = rand_comm
                .response::<Blake2b512, _>(&g, &homomorphism, &x, &challenge)
                .unwrap();

            let start = Instant::now();
            response
                .is_valid_recursive::<Blake2b512, _>(
                    &g,
                    &P,
                    &y,
                    &homomorphism,
                    &rand_comm.A_hat,
                    &rand_comm.t,
                    &challenge,
                )
                .unwrap();
            println!(
                "Recursive verification for compressed homomorphism form of size {} takes: {:?}",
                size,
                start.elapsed()
            );

            let start = Instant::now();
            response
                .is_valid::<Blake2b512, _>(
                    &g,
                    &P,
                    &y,
                    &homomorphism,
                    &rand_comm.A_hat,
                    &rand_comm.t,
                    &challenge,
                )
                .unwrap();
            println!(
                "Verification for compressed homomorphism form of size {} takes: {:?}",
                size,
                start.elapsed()
            );
        }
        check_compression(4);
        check_compression(5);
        check_compression(6);
        check_compression(7);
        check_compression(8);
        check_compression(9);
        check_compression(11);
        check_compression(15);
        check_compression(16);
        check_compression(17);
        check_compression(18);
        check_compression(20);
        check_compression(25);
        check_compression(31);
        check_compression(32);
        check_compression(48);
        check_compression(63);
        check_compression(64);
    }
}
