//! Compressed sigma protocol as described as Protocol 5 of the paper "Compressed Sigma Protocol Theory..."

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    cfg_into_iter, cfg_iter,
    io::{Read, Write},
    ops::{Add, MulAssign},
    rand::RngCore,
    vec,
    vec::Vec,
    UniformRand,
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};

use crate::error::CompSigmaError;
use crate::transforms::LinearForm;
use dock_crypto_utils::ec::batch_normalize_projective_into_affine;
use dock_crypto_utils::transcript::{ChallengeContributor, Transcript};

use crate::utils::{elements_to_element_products, get_g_multiples_for_verifying_compression};
use dock_crypto_utils::msm::WindowTable;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub r: Vec<G::ScalarField>,
    pub rho: G::ScalarField,
    pub A_hat: G,
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
        self.A_hat.serialize_unchecked(&mut writer)?;
        self.t
            .serialize_unchecked(&mut writer)
            .map_err(|e| e.into())
    }
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
    ) -> Result<Self, CompSigmaError> {
        if !(g.len() + 1).is_power_of_two() {
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
        let rho = G::ScalarField::rand(rng);
        let t = linear_form.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();
        // h * rho is done separately to avoid copying g
        let A_hat = VariableBaseMSM::multi_scalar_mul(g, &scalars).add(&h.mul(rho.into_repr()));
        Ok(Self {
            r,
            rho,
            A_hat: A_hat.into_affine(),
            t,
        })
    }

    pub fn response<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        g: &[G],
        h: &G,
        k: &G,
        linear_form: &L,
        x: &[G::ScalarField],
        gamma: &G::ScalarField,
        c_0: &G::ScalarField,
        c_1: &G::ScalarField,
        transcript: Option<&mut Transcript>,
    ) -> Result<Response<G>, CompSigmaError> {
        if !(g.len() + 1).is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if g.len() != x.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if !linear_form.size().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if (linear_form.size() - 1) != x.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        // phi = c_0 * gamma + rho
        let phi = *gamma * c_0 + self.rho;

        // z_hat = (c_0 * x_0 + r_0, c_0 * x_1 + r_1, ..., c_0 * x_n + r_n, phi)
        let mut z_hat = x
            .iter()
            .zip(self.r.iter())
            .map(|(x_, r)| *x_ * c_0 + r)
            .collect::<Vec<_>>();
        z_hat.push(phi);

        let (g_hat, L_tilde) =
            prepare_generators_and_linear_form_for_compression::<G, L>(g, h, linear_form, c_1);

        Ok(Self::compressed_response::<L, H>(
            z_hat, g_hat, k, L_tilde, transcript,
        ))
    }

    /// Run the compressed (non-zero) proof of knowledge of the response vector as described in the
    /// Protocol 4 in the paper. The relation in this proof is Q = g_hat * z_hat + k * L_tilde(z_hat)
    /// and knowledge of z_hat needs to be proven but the proof is not zero-knowledge
    pub fn compressed_response<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        mut z_hat: Vec<G::ScalarField>,
        mut g_hat: Vec<G>,
        k: &G,
        mut L_tilde: L,
        transcript: Option<&mut Transcript>,
    ) -> Response<G> {
        let mut temp_transcript = Transcript::new();
        let mut serialise_to = match transcript {
            Some(t) => t,
            None => &mut temp_transcript,
        };

        let mut As = vec![];
        let mut Bs = vec![];
        let mut c = G::ScalarField::zero();
        let mut c_repr = c.into_repr();

        // There are many multiplications done with `k`, so creating a table for it
        let lg2 = z_hat.len() & (z_hat.len() - 1);
        let k_table = WindowTable::new(G::ScalarField::size_in_bits(), lg2, k.into_projective());

        // In each iteration of the loop, size of `z_hat`, `g_hat` and `L_tilde` is reduced by half
        while z_hat.len() > 2 {
            let m = g_hat.len();
            // Split `g_hat` into 2 halves, `g_hat` will be the 1st half and `g_hat_r` will be the 2nd
            let g_hat_r = g_hat.split_off(m / 2);
            // Split `z_hat` into 2 halves, `z_hat` will be the 1st half and `z_hat_r` will be the 2nd
            let z_hat_r = z_hat.split_off(m / 2);
            // Split `L_tilde` into 2 halves, `L_tilde_l` will be the 1st half and `L_tilde_r` will be the 2nd
            let (L_tilde_l, L_tilde_r) = L_tilde.split_in_half();

            // A = g_hat_r * z_hat_l + k * L_tilde_r(z_hat_l)
            let A = VariableBaseMSM::multi_scalar_mul(
                &g_hat_r,
                &z_hat.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            ) + k_table.multiply(&L_tilde_r.eval(&z_hat));

            // B = g_hat_l * z_hat_r + k * L_tilde_l(z_hat_r)
            let B = VariableBaseMSM::multi_scalar_mul(
                &g_hat,
                &z_hat_r.iter().map(|z| z.into_repr()).collect::<Vec<_>>(),
            ) + k_table.multiply(&L_tilde_l.eval(&z_hat_r));

            A.serialize(&mut serialise_to).unwrap();
            B.serialize(&mut serialise_to).unwrap();
            c = serialise_to.hash::<_, H>(None);
            c_repr = c.into_repr();

            // Set `g_hat` as g' in the paper
            g_hat = g_hat
                .iter()
                .zip(g_hat_r.iter())
                .map(|(l, r)| l.mul(c_repr).add_mixed(r).into_affine())
                .collect::<Vec<_>>();
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

        let response = Response {
            z_prime_0: z_hat[0],
            z_prime_1: z_hat[1],
            A: batch_normalize_projective_into_affine(As),
            B: batch_normalize_projective_into_affine(Bs),
        };

        response
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    /// Validate the proof of knowledge in the recursive manner where the size of the various
    /// vectors is reduced to half in each iteration. This execution is similar to the prover's.
    /// A naive and thus slower implementation than `is_valid`
    pub fn is_valid_recursive<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
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
        transcript: Option<&mut Transcript>,
    ) -> Result<(), CompSigmaError> {
        if !(g.len() + 1).is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }
        if self.A.len() != self.B.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        if (g.len() + 1) != (1 << (self.A.len() + 1)) {
            return Err(CompSigmaError::WrongRecursionLevel);
        }
        if !linear_form.size().is_power_of_two() {
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }

        let (g_hat, L_tilde) =
            prepare_generators_and_linear_form_for_compression::<G, L>(g, h, linear_form, &c_1);
        let Q = calculate_Q(k, P, y, A_hat, t, &c_0, &c_1);
        self.recursively_validate_compressed::<L, H>(Q, g_hat, L_tilde, k, transcript)
    }

    /// Validate the proof of knowledge in the non-recursive manner. This will delay scalar multiplications
    /// till the end similar to whats described in the Bulletproofs paper, thus is faster than the recursive
    /// version above. The key idea is that the verifier knows both `A` and `B` at the start and thus he knows
    /// all the immediate challenges `c` also at the start. Thus the verifier can create the final g' and Q
    /// in a single multi-scalar multiplication
    pub fn is_valid<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
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
        transcript: Option<&mut Transcript>,
    ) -> Result<(), CompSigmaError> {
        assert!((g.len() + 1).is_power_of_two());
        assert_eq!(self.A.len(), self.B.len());
        assert_eq!(g.len() + 1, 1 << (self.A.len() + 1));
        assert!(linear_form.size().is_power_of_two());

        let (g_hat, L_tilde) =
            prepare_generators_and_linear_form_for_compression::<G, L>(g, h, linear_form, &c_1);
        let Q = calculate_Q(k, P, y, A_hat, t, &c_0, &c_1);
        self.validate_compressed::<L, H>(Q, g_hat, L_tilde, k, transcript)
    }

    pub fn recursively_validate_compressed<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        mut Q: G::Projective,
        mut g_hat: Vec<G>,
        mut L_tilde: L,
        k: &G,
        transcript: Option<&mut Transcript>,
    ) -> Result<(), CompSigmaError> {
        let mut temp_transcript = Transcript::new();
        let mut serialise_to = match transcript {
            Some(t) => t,
            None => &mut temp_transcript,
        };

        let mut c = G::ScalarField::zero();
        let mut c_repr = c.into_repr();

        for (A, B) in self.A.iter().zip(self.B.iter()) {
            A.serialize(&mut serialise_to).unwrap();
            B.serialize(&mut serialise_to).unwrap();
            c = serialise_to.hash::<_, H>(None);
            c_repr = c.into_repr();

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
            return Err(CompSigmaError::UncompressedNotPowerOf2);
        }

        // Check if g_hat * [z'_0, z'_1] + k * L_tilde([z'_0, z'_1]) == Q
        g_hat.push(*k);

        let mut scalars = vec![self.z_prime_0.into_repr(), self.z_prime_1.into_repr()];
        let l_z = L_tilde.eval(&[self.z_prime_0, self.z_prime_1]);
        scalars.push(l_z.into_repr());

        if VariableBaseMSM::multi_scalar_mul(&g_hat, &scalars) == Q {
            Ok(())
        } else {
            Err(CompSigmaError::InvalidResponse)
        }
    }

    pub fn validate_compressed<
        L: LinearForm<G::ScalarField>,
        H: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
    >(
        &self,
        mut Q: G::Projective,
        mut g_hat: Vec<G>,
        mut L_tilde: L,
        k: &G,
        transcript: Option<&mut Transcript>,
    ) -> Result<(), CompSigmaError> {
        // Create challenges for each round and store in `challenges`
        let mut challenges = vec![];
        // Holds squares of challenge of each round
        let mut challenge_squares = vec![];

        let mut temp_transcript = Transcript::new();
        let mut serialise_to = match transcript {
            Some(t) => t,
            None => &mut temp_transcript,
        };

        let mut c = G::ScalarField::zero();

        for (A, B) in self.A.iter().zip(self.B.iter()) {
            A.serialize(&mut serialise_to).unwrap();
            B.serialize(&mut serialise_to).unwrap();
            c = serialise_to.hash::<_, H>(None);

            let (L_tilde_l, L_tilde_r) = L_tilde.split_in_half();
            L_tilde = L_tilde_l.scale(&c).add(&L_tilde_r);

            challenge_squares.push(c.square());
            challenges.push(c);
        }

        // Calculate the final g' and Q' for checking the relation Q' = g' * z' + k * L'(z')
        let g_len = g_hat.len();

        // Multiples of original g vector to create the final product g' * z'
        let mut g_hat_multiples = get_g_multiples_for_verifying_compression(
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
        // Similarly, contribution of B vector in final Q will be B_1 * (c_1^2*c_2*c_3*..*c_n) + B_2 * (c_2^2*c_3*..*c_n) + ... + B_n * c_n^2

        // Convert challenge vector from [c_1, c_2, ..., c_n] to [c_1*c_2*...*c_n, c_2*c_3*...*c_n, c_3*...*c_n, ..., c_{n-1}*c_n, c_n, 1]
        let mut challenge_products = elements_to_element_products(challenges);

        // c_1*c_2*c_3*...*c_n (and remove it from challenge_products)
        let all_challenges_product = challenge_products.remove(0);

        // `B_multiples` is of form [c_1^2*c_2*c_3*..*c_n, c_2^2*c_3*c_4..*c_n, ..., c_{n-1}^2*c_n, c_n^2]
        let B_multiples = challenge_products
            .iter()
            .zip(challenge_squares.iter())
            .map(|(c, c_sqr)| (*c * c_sqr).into_repr())
            .collect::<Vec<_>>();

        // Q' = A * [c_2*c_3*...*c_n, c_3*...*c_n, ..., c_{n-1}*c_n, c_n, 1] + B * [c_1^2*c_2*c_3*..*c_n, c_2^2*c_3*..*c_n, ..., c_{n-1}^2*c_n, c_n^2] + Q * c_1^2*c_2*c_3*..*c_n
        // Set Q to Q*(c_1*c_2*c_3*...*c_n)
        Q.mul_assign(all_challenges_product);
        let Q_prime = VariableBaseMSM::multi_scalar_mul(
            &self.A,
            &cfg_iter!(challenge_products)
                .map(|c| c.into_repr())
                .collect::<Vec<_>>(),
        ) + VariableBaseMSM::multi_scalar_mul(&self.B, &B_multiples)
            + Q;

        let l_z = L_tilde.eval(&[self.z_prime_0, self.z_prime_1]);

        g_hat.push(*k);
        g_hat_multiples.push(l_z);

        // Check if g' * z' + k * L'(z') == Q'
        if VariableBaseMSM::multi_scalar_mul(
            &g_hat,
            &cfg_iter!(g_hat_multiples)
                .map(|g| g.into_repr())
                .collect::<Vec<_>>(),
        ) == Q_prime
        {
            Ok(())
        } else {
            Err(CompSigmaError::InvalidResponse)
        }
    }
}

pub fn prepare_generators_and_linear_form_for_compression<
    G: AffineCurve,
    L: LinearForm<G::ScalarField>,
>(
    g: &[G],
    h: &G,
    linear_form: &L,
    c_1: &G::ScalarField,
) -> (Vec<G>, L) {
    // g_hat = (g_0, g_1, ... g_n, h)
    let mut g_hat = g.to_vec();
    g_hat.push(*h);

    // L_tilde = c_1 * linear_form
    let L_tilde = linear_form.scale(c_1);

    (g_hat, L_tilde)
}

/// Q = P*c_0 + k * (c_1*(c_0*y + t)) + A_hat
fn calculate_Q<G: AffineCurve>(
    k: &G,
    P: &G,
    y: &G::ScalarField,
    A: &G,
    t: &G::ScalarField,
    c_0: &G::ScalarField,
    c_1: &G::ScalarField,
) -> G::Projective {
    (P.mul(c_0.into_repr()) + k.mul(*c_1 * (*c_0 * y + t))).add_mixed(A)
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
    use std::time::Instant;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    struct TestLinearForm {
        pub constants: Vec<Fr>,
    }

    impl_simple_linear_form!(TestLinearForm, Fr);

    #[test]
    fn compression() {
        fn check_compression(size: usize) {
            let mut rng = StdRng::seed_from_u64(0u64);
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

            let rand_comm = RandomCommitment::new(&mut rng, &g, &h, &linear_form, None).unwrap();
            let mut transcript = Transcript::new();
            rand_comm.challenge_contribution(&mut transcript);
            let c_0 = transcript.hash::<Fr, Blake2b>(Some(b"c_0"));
            let c_1 = transcript.hash::<Fr, Blake2b>(Some(b"c_1"));

            let response = rand_comm
                .response::<_, Blake2b>(
                    &g,
                    &h,
                    &k,
                    &linear_form,
                    &x,
                    &gamma,
                    &c_0,
                    &c_1,
                    Some(&mut transcript),
                )
                .unwrap();

            let start = Instant::now();
            let mut verifier_transcript = Transcript::new();
            rand_comm
                .challenge_contribution(&mut verifier_transcript)
                .unwrap();
            let verifier_c_0 = verifier_transcript.hash::<Fr, Blake2b>(Some(b"c_0"));
            let verifier_c_1 = verifier_transcript.hash::<Fr, Blake2b>(Some(b"c_1"));
            response
                .is_valid_recursive::<_, Blake2b>(
                    &g,
                    &h,
                    &k,
                    &P,
                    &y,
                    &linear_form,
                    &rand_comm.A_hat,
                    &rand_comm.t,
                    &verifier_c_0,
                    &verifier_c_1,
                    Some(&mut verifier_transcript),
                )
                .unwrap();
            println!(
                "Recursive verification for compressed linear form of size {} takes: {:?}",
                size,
                start.elapsed()
            );

            let start = Instant::now();
            let mut verifier_transcript_2 = Transcript::new();
            rand_comm
                .challenge_contribution(&mut verifier_transcript_2)
                .unwrap();
            let verifier_2_c_0 = verifier_transcript_2.hash::<Fr, Blake2b>(Some(b"c_0"));
            let verifier_2_c_1 = verifier_transcript_2.hash::<Fr, Blake2b>(Some(b"c_1"));
            response
                .is_valid::<_, Blake2b>(
                    &g,
                    &h,
                    &k,
                    &P,
                    &y,
                    &linear_form,
                    &rand_comm.A_hat,
                    &rand_comm.t,
                    &verifier_2_c_0,
                    &verifier_2_c_1,
                    Some(&mut verifier_transcript_2),
                )
                .unwrap();
            println!(
                "Verification for compressed linear form of size {} takes: {:?}",
                size,
                start.elapsed()
            );
        }

        check_compression(3);
        check_compression(7);
        check_compression(15);
        check_compression(31);
        check_compression(63);
    }
}
