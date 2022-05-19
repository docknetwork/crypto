//! Amortized sigma protocol as described in Appendix B of the paper "Compressed Sigma Protocol Theory..."

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{cfg_into_iter, cfg_iter, vec, vec::Vec, UniformRand};
use ark_std::{
    io::{Read, Write},
    ops::Add,
    rand::RngCore,
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

use dock_crypto_utils::ff::inner_product;
use dock_crypto_utils::transcript::{self, ChallengeContributor, Transcript};

use crate::compressed_linear_form;
use crate::error::CompSigmaError;
use crate::transforms::LinearForm;

use crate::utils::{amortized_response, get_n_powers};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    /// Maximum size of the witness vectors
    pub max_size: usize,
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub A: G,
    pub t: G::ScalarField,
}

impl<G> ChallengeContributor for RandomCommitment<G>
where
    G: AffineCurve,
{
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
        for i in 0..self.r.len() {
            self.r[i].serialize_unchecked(&mut writer)?;
        }
        self.rho.serialize_unchecked(&mut writer)?;
        self.A.serialize_unchecked(&mut writer)?;
        self.t
            .serialize_unchecked(&mut writer)
            .map_err(|e| e.into())
    }
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
    ) -> Result<Self, CompSigmaError> {
        if g.len() < max_size {
            return Err(CompSigmaError::VectorTooShort);
        }
        let r = if let Some(blindings) = blindings {
            if blindings.len() != max_size {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            blindings
        } else {
            (0..max_size).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let rho = G::ScalarField::rand(rng);
        let t = linear_form.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();
        // h * rho is done separately to avoid copying g
        let A = VariableBaseMSM::multi_scalar_mul(g, &scalars).add(&h.mul(rho.into_repr()));
        Ok(Self {
            max_size,
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
    G: AffineCurve,
{
    pub fn is_valid<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        g: &[G],
        h: &G,
        max_size: usize,
        commitments: &[G],
        y: &[G::ScalarField],
        linear_form: &L,
        A: &G,
        t: &G::ScalarField,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        if g.len() < max_size {
            return Err(CompSigmaError::VectorTooShort);
        }
        if commitments.len() != y.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if self.z_tilde.len() != max_size {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let count_commitments = commitments.len();
        // `challenge_powers` is of form [c, c^2, c^3, ..., c^n]
        let challenge_powers = get_n_powers(challenge.clone(), count_commitments);
        let challenge_powers_repr = cfg_iter!(challenge_powers)
            .map(|c| c.into_repr())
            .collect::<Vec<_>>();

        // P_tilde = A + \sum_{i}(P_i * c^i)
        let mut P_tilde = A.into_projective();
        P_tilde += VariableBaseMSM::multi_scalar_mul(commitments, &challenge_powers_repr);

        // Check g*z_tilde + h*phi == P_tilde
        let z_tilde_repr = cfg_iter!(self.z_tilde)
            .map(|z| z.into_repr())
            .collect::<Vec<_>>();
        let g_z = VariableBaseMSM::multi_scalar_mul(g, &z_tilde_repr);
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

    pub fn compress<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        self,
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        new_challenge: &G::ScalarField,
        transcript: Option<&mut Transcript>,
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

        compressed_linear_form::RandomCommitment::compressed_response::<L, H>(
            z_hat, g_hat, k, L_tilde, transcript,
        )
    }

    pub fn is_valid_compressed<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        Ps: &[G],
        ys: &[G::ScalarField],
        A: &G,
        t: &G::ScalarField,
        c_0: &G::ScalarField,
        c_1: &G::ScalarField,
        compressed_resp: &compressed_linear_form::Response<G>,
        transcript: Option<&mut Transcript>,
    ) -> Result<(), CompSigmaError> {
        let (g_hat, L_tilde) =
            compressed_linear_form::prepare_generators_and_linear_form_for_compression(
                g,
                h,
                linear_form,
                &c_1,
            );
        let Q = calculate_Q(k, Ps, ys, A, t, c_0, c_1);
        compressed_resp.validate_compressed::<L, H>(Q, g_hat, L_tilde, k, transcript)
    }
}

pub fn prepare_for_compression<G: AffineCurve, L: LinearForm<G::ScalarField>>(
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
) -> (Vec<G>, G::Projective, L) {
    // g_hat = (g_0, g_1, ... g_n, h)
    let mut g_hat = g.to_vec();
    g_hat.push(*h);

    // L_tilde = new_challenge * linear_form
    let L_tilde = linear_form.scale(new_challenge);

    let challenge_powers = get_n_powers(challenge.clone(), Ps.len());
    let challenge_powers_repr = cfg_iter!(challenge_powers)
        .map(|c| c.into_repr())
        .collect::<Vec<_>>();
    let P = VariableBaseMSM::multi_scalar_mul(Ps, &challenge_powers_repr);
    let Y = challenge_powers
        .iter()
        .zip(ys.iter())
        .map(|(c, y)| *c * y)
        .reduce(|a, b| a + b)
        .unwrap();

    // Q = P + k * (new_challenge*(Y + t)) + A
    let Q = (P + k.mul(*new_challenge * (Y + t))).add_mixed(&A);
    (g_hat, Q, L_tilde)
}

fn calculate_Q<G: AffineCurve>(
    k: &G,
    Ps: &[G],
    ys: &[G::ScalarField],
    A: &G,
    t: &G::ScalarField,
    challenge: &G::ScalarField,
    new_challenge: &G::ScalarField,
) -> G::Projective {
    let challenge_powers = get_n_powers(challenge.clone(), Ps.len());
    let challenge_powers_repr = cfg_iter!(challenge_powers)
        .map(|c| c.into_repr())
        .collect::<Vec<_>>();
    let P = VariableBaseMSM::multi_scalar_mul(Ps, &challenge_powers_repr);
    let Y = challenge_powers
        .iter()
        .zip(ys.iter())
        .map(|(c, y)| *c * y)
        .reduce(|a, b| a + b)
        .unwrap();

    // Q = P + k * (new_challenge*(Y + t)) + A
    (P + k.mul(*new_challenge * (Y + t))).add_mixed(&A)
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

        fn pad(&self, _new_size: usize) -> Self {
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
        fn check(max_size: usize) {
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

            let rand_comm =
                RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_1, None).unwrap();
            assert_eq!(rand_comm.r.len(), max_size);
            let mut transcript = Transcript::new();
            rand_comm.challenge_contribution(&mut transcript).unwrap();
            let challenge = transcript.hash::<Fr, Blake2b>(None);
            let response = rand_comm
                .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &challenge)
                .unwrap();
            assert_eq!(response.z_tilde.len(), max_size);

            let mut verifier_transcript = Transcript::new();
            rand_comm
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let verifier_challenge = verifier_transcript.hash::<Fr, Blake2b>(None);
            response
                .is_valid::<TestLinearForm1, Blake2b>(
                    &g,
                    &h,
                    max_size,
                    &[comm1, comm2, comm3],
                    &[eval1, eval2, eval3],
                    &linear_form_1,
                    &rand_comm.A,
                    &rand_comm.t,
                    &verifier_challenge,
                )
                .unwrap();

            let rand_comm =
                RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form_2, None).unwrap();
            assert_eq!(rand_comm.r.len(), max_size);
            let mut transcript_2 = Transcript::new();
            rand_comm.challenge_contribution(&mut transcript_2).unwrap();
            let challenge = transcript_2.hash::<Fr, Blake2b>(None);
            let response = rand_comm
                .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &challenge)
                .unwrap();
            assert_eq!(response.z_tilde.len(), max_size);

            let mut verifier_transcript_2 = Transcript::new();
            rand_comm
                .challenge_contribution(&mut verifier_transcript_2)
                .unwrap();
            let verifier_challenge_2 = verifier_transcript_2.hash::<Fr, Blake2b>(None);
            response
                .is_valid::<TestLinearForm2, Blake2b>(
                    &g,
                    &h,
                    max_size,
                    &[comm1, comm2, comm3],
                    &[eval12, eval22, eval32],
                    &linear_form_2,
                    &rand_comm.A,
                    &rand_comm.t,
                    &verifier_challenge_2,
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
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let h = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
        let k = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

        let comm1 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x1.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma1.into_repr()))
        .into_affine();
        let eval1 = linear_form.eval(&x1);

        let comm2 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x2.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma2.into_repr()))
        .into_affine();
        let eval2 = linear_form.eval(&x2);

        let comm3 = (VariableBaseMSM::multi_scalar_mul(
            &g,
            &x3.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        ) + h.mul(gamma3.into_repr()))
        .into_affine();
        let eval3 = linear_form.eval(&x3);

        let comms = [comm1, comm2, comm3];
        let evals = [eval1, eval2, eval3];
        let rand_comm =
            RandomCommitment::new(&mut rng, &g, &h, max_size, &linear_form, None).unwrap();
        assert_eq!(rand_comm.r.len(), max_size);
        let mut transcript = Transcript::new();
        rand_comm.challenge_contribution(&mut transcript).unwrap();
        let c_0 = transcript.hash::<Fr, Blake2b>(Some(b"c_0"));
        let response = rand_comm
            .response(vec![&x1, &x2, &x3], &[gamma1, gamma2, gamma3], &c_0)
            .unwrap();
        assert_eq!(response.z_tilde.len(), max_size);

        let mut verifier_transcript = Transcript::new();
        rand_comm
            .challenge_contribution(&mut verifier_transcript)
            .unwrap();
        let verifier_c_0 = verifier_transcript.hash::<Fr, Blake2b>(Some(b"c_0"));
        response
            .is_valid::<TestLinearForm2, Blake2b>(
                &g,
                &h,
                max_size,
                &comms,
                &evals,
                &linear_form,
                &rand_comm.A,
                &rand_comm.t,
                &verifier_c_0,
            )
            .unwrap();
        let c_1 = transcript.hash::<Fr, Blake2b>(Some(b"c_1"));

        let comp_resp =
            response.compress::<_, Blake2b>(&g, &h, &k, &linear_form, &c_1, Some(&mut transcript));
        let verifier_c_1 = verifier_transcript.hash::<Fr, Blake2b>(Some(b"c_1"));
        Response::is_valid_compressed::<_, Blake2b>(
            &g,
            &h,
            &k,
            &linear_form,
            &comms,
            &evals,
            &rand_comm.A,
            &rand_comm.t,
            &verifier_c_0,
            &verifier_c_1,
            &comp_resp,
            Some(&mut verifier_transcript),
        )
        .unwrap();
    }
}
