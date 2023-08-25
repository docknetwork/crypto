//! Amortized sigma protocol as described in Appendix B of the paper "Compressed Sigma Protocol Theory..."

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Add, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;

use dock_crypto_utils::ff::inner_product;

use crate::{
    compressed_linear_form,
    error::CompSigmaError,
    transforms::LinearForm,
    utils::{amortized_response, get_n_powers},
};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineRepr> {
    /// Maximum size of the witness vectors
    pub max_size: u32,
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub A: G,
    pub t: G::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineRepr> {
    pub z_tilde: Vec<G::ScalarField>,
    pub phi: G::ScalarField,
}

impl<G> RandomCommitment<G>
where
    G: AffineRepr,
{
    pub fn new<R: RngCore, L: LinearForm<G::ScalarField>>(
        rng: &mut R,
        g: &[G],
        h: &G,
        max_size: u32,
        linear_form: &L,
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Result<Self, CompSigmaError> {
        if g.len() < max_size as usize {
            return Err(CompSigmaError::VectorTooShort);
        }
        let r = if let Some(blindings) = blindings {
            if blindings.len() != max_size as usize {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            blindings
        } else {
            (0..max_size).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let rho = G::ScalarField::rand(rng);
        let t = linear_form.eval(&r);
        // h * rho is done separately to avoid copying g
        let A = G::Group::msm_unchecked(g, &r).add(&h.mul_bigint(rho.into_bigint()));
        Ok(Self {
            max_size: max_size,
            r,
            rho,
            A: A.into_affine(),
            t,
        })
    }

    pub fn response(
        &self,
        witnesses: Vec<&[G::ScalarField]>,
        gammas: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> Result<Response<G>, CompSigmaError> {
        if witnesses.len() != gammas.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        let count_commitments = witnesses.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^n]
        let challenge_powers = get_n_powers(challenge.clone(), count_commitments);

        // z_tilde_i = r_i + \sum_{j in count_commitments}(witnesses_j_i * challenge^j)
        let z_tilde = amortized_response(self.max_size, &challenge_powers, &self.r, witnesses);

        // phi = rho + \sum_{j}(gamma_j * c^j)
        let phi = self.rho + inner_product(&challenge_powers, gammas);
        Ok(Response { z_tilde, phi })
    }
}

impl<G> Response<G>
where
    G: AffineRepr,
{
    pub fn is_valid<L: LinearForm<G::ScalarField>>(
        &self,
        g: &[G],
        h: &G,
        max_size: u32,
        commitments: &[G],
        y: &[G::ScalarField],
        linear_form: &L,
        A: &G,
        t: &G::ScalarField,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        if g.len() < max_size as usize {
            return Err(CompSigmaError::VectorTooShort);
        }
        if commitments.len() != y.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if self.z_tilde.len() != max_size as usize {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let count_commitments = commitments.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^n]
        let challenge_powers = get_n_powers(challenge.clone(), count_commitments);

        // P_tilde = A + \sum_{i}(P_i * c^i)
        let mut P_tilde = A.into_group();
        P_tilde += G::Group::msm_unchecked(commitments, &challenge_powers);

        // Check g*z_tilde + h*phi == P_tilde
        let g_z = G::Group::msm_unchecked(g, &self.z_tilde);
        let h_phi = h.mul(self.phi);
        if (g_z + h_phi) != P_tilde {
            return Err(CompSigmaError::InvalidResponse);
        }

        // Check \sum_{i}(y_i * c^i) + t == L(z_tilde)
        let c_y = inner_product(&challenge_powers, y);
        if !(c_y + t - linear_form.eval(&self.z_tilde)).is_zero() {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    pub fn compress<D: Digest, L: LinearForm<G::ScalarField>>(
        self,
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        new_challenge: &G::ScalarField,
    ) -> compressed_linear_form::Response<G> {
        let (g_hat, L_tilde) =
            compressed_linear_form::prepare_generators_and_linear_form_for_compression(
                g,
                h,
                linear_form,
                new_challenge,
            );

        let mut z_hat = self.z_tilde;
        z_hat.push(self.phi);
        compressed_linear_form::RandomCommitment::compressed_response::<D, L>(
            z_hat, g_hat, &k, L_tilde,
        )
    }

    pub fn is_valid_compressed<D: Digest, L: LinearForm<G::ScalarField>>(
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        Ps: &[G],
        ys: &[G::ScalarField],
        A: &G,
        t: &G::ScalarField,
        challenge: &G::ScalarField,
        new_challenge: &G::ScalarField,
        compressed_resp: &compressed_linear_form::Response<G>,
    ) -> Result<(), CompSigmaError> {
        let (g_hat, L_tilde) =
            compressed_linear_form::prepare_generators_and_linear_form_for_compression(
                g,
                h,
                linear_form,
                new_challenge,
            );
        let Q = calculate_Q(k, Ps, ys, A, t, challenge, new_challenge);
        compressed_resp.validate_compressed::<D, L>(Q, g_hat, L_tilde, &k)
    }
}

pub fn prepare_for_compression<G: AffineRepr, L: LinearForm<G::ScalarField>>(
    g: &[G],
    h: &G,
    k: &G,
    linear_form: &L,
    Ps: &[G],
    ys: &[G::ScalarField],
    A: &G,
    t: &G::ScalarField,
    challenge: &G::ScalarField,
    new_challenge: &G::ScalarField,
) -> (Vec<G>, G::Group, L) {
    // g_hat = (g_0, g_1, ... g_n, h)
    let mut g_hat = g.to_vec();
    g_hat.push(*h);

    // L_tilde = new_challenge * linear_form
    let L_tilde = linear_form.scale(new_challenge);

    let challenge_powers = get_n_powers(challenge.clone(), Ps.len());
    let P = G::Group::msm_unchecked(Ps, &challenge_powers);
    let Y = challenge_powers
        .iter()
        .zip(ys.iter())
        .map(|(c, y)| *c * y)
        .reduce(|a, b| a + b)
        .unwrap();

    // Q = P + k * (new_challenge*(Y + t)) + A
    let Q = P + k.mul(*new_challenge * (Y + t)) + A;
    (g_hat, Q, L_tilde)
}

fn calculate_Q<G: AffineRepr>(
    k: &G,
    Ps: &[G],
    ys: &[G::ScalarField],
    A: &G,
    t: &G::ScalarField,
    challenge: &G::ScalarField,
    new_challenge: &G::ScalarField,
) -> G::Group {
    let challenge_powers = get_n_powers(challenge.clone(), Ps.len());
    let P = G::Group::msm_unchecked(Ps, &challenge_powers);
    let Y = challenge_powers
        .iter()
        .zip(ys.iter())
        .map(|(c, y)| *c * y)
        .reduce(|a, b| a + b)
        .unwrap();

    // Q = P + k * (new_challenge*(Y + t)) + A
    P + k.mul(*new_challenge * (Y + t)) + A
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

    type Fr = <Bls12_381 as Pairing>::ScalarField;

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

        fn pad(&self, _new_size: u32) -> Self {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    struct TestLinearForm2 {
        pub constants: Vec<Fr>,
    }

    impl_simple_linear_form!(TestLinearForm2, Fr);

    #[test]
    fn amortization() {
        fn check(max_size: u32) {
            let mut rng = StdRng::seed_from_u64(0u64);
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
                .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let h = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();

            let comm1 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x1)
                + h.mul_bigint(gamma1.into_bigint()))
            .into_affine();
            let eval1 = linear_form_1.eval(&x1);
            let eval12 = linear_form_2.eval(&x1);

            let comm2 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x2)
                + h.mul_bigint(gamma2.into_bigint()))
            .into_affine();
            let eval2 = linear_form_1.eval(&x2);
            let eval22 = linear_form_2.eval(&x2);

            let comm3 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x3)
                + h.mul_bigint(gamma3.into_bigint()))
            .into_affine();
            let eval3 = linear_form_1.eval(&x3);
            let eval32 = linear_form_2.eval(&x3);

            let rand_comm =
                RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_1, None).unwrap();
            assert_eq!(rand_comm.r.len(), max_size as usize);
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm
                .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &challenge)
                .unwrap();
            assert_eq!(response.z_tilde.len(), max_size as usize);
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

            let rand_comm =
                RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_2, None).unwrap();
            assert_eq!(rand_comm.r.len(), max_size as usize);
            let challenge = Fr::rand(&mut rng);
            let response = rand_comm
                .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &challenge)
                .unwrap();
            assert_eq!(response.z_tilde.len(), max_size as usize);
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

        check(3);
        check(7);
        check(15);
        check(31);
    }

    #[test]
    fn amortization_and_compression() {
        let max_size = 7;
        let mut rng = StdRng::seed_from_u64(0u64);
        let mut linear_form = TestLinearForm2 {
            constants: (0..max_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>(),
        };
        linear_form.constants.push(Fr::zero());

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
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let h = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
        let k = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();

        let comm1 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x1)
            + h.mul_bigint(gamma1.into_bigint()))
        .into_affine();
        let eval1 = linear_form.eval(&x1);

        let comm2 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x2)
            + h.mul_bigint(gamma2.into_bigint()))
        .into_affine();
        let eval2 = linear_form.eval(&x2);

        let comm3 = (<Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x3)
            + h.mul_bigint(gamma3.into_bigint()))
        .into_affine();
        let eval3 = linear_form.eval(&x3);

        let comms = [comm1, comm2, comm3];
        let evals = [eval1, eval2, eval3];
        let rand_comm =
            RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form, None).unwrap();
        assert_eq!(rand_comm.r.len(), max_size as usize);
        let c_0 = Fr::rand(&mut rng);
        let response = rand_comm
            .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &c_0)
            .unwrap();
        assert_eq!(response.z_tilde.len(), max_size as usize);
        response
            .is_valid(
                &g,
                &h,
                max_size,
                &comms,
                &evals,
                &linear_form,
                &rand_comm.A,
                &rand_comm.t,
                &c_0,
            )
            .unwrap();

        let c_1 = Fr::rand(&mut rng);
        let comp_resp = response.compress::<Blake2b512, _>(&g, &h, &k, &linear_form, &c_1);
        Response::is_valid_compressed::<Blake2b512, _>(
            &g,
            &h,
            &k,
            &linear_form,
            &comms,
            &evals,
            &rand_comm.A,
            &rand_comm.t,
            &c_0,
            &c_1,
            &comp_resp,
        )
        .unwrap();
    }
}
