//! Amortized sigma protocol with homomorphism as described in section 3.4 of the paper "Compressing Proofs of k-Out-Of-n".
//! This is for the relation R_{AMORHOM} where a many homomorphisms are applied over a single witness vector and
//! there is a commitment to the witness vector.

use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{cfg_iter, vec, vec::Vec, UniformRand};
use ark_std::{
    io::{Read, Write},
    ops::Add,
    rand::RngCore,
};
use digest::Digest;

use crate::error::CompSigmaError;
use crate::transforms::Homomorphism;

use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

use crate::compressed_homomorphism;
use crate::utils::get_n_powers;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineCurve> {
    pub r: Vec<G::ScalarField>,
    pub A: G,
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineCurve> {
    pub z: Vec<G::ScalarField>,
}

pub fn create_rho_powers<D: Digest, G: AffineCurve>(
    g: &[G],
    P: &G,
    ys: &[G],
) -> Vec<G::ScalarField> {
    let mut bytes = vec![];
    P.serialize(&mut bytes).unwrap();
    for g_ in g.iter() {
        g_.serialize(&mut bytes).unwrap();
    }
    for y in ys.iter() {
        y.serialize(&mut bytes).unwrap();
    }

    let rho = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
    // rho_powers = [1, rho, rho^2, rho^3, ..., rho^{ys.len()-1}]
    let mut rho_powers = get_n_powers(rho, ys.len() - 1);
    rho_powers.insert(0, G::ScalarField::one());
    rho_powers
}

pub fn combine_y<G: AffineCurve>(ys: &[G], rho_powers: &[G::ScalarField]) -> G::Projective {
    let r = cfg_iter!(rho_powers)
        .map(|r| r.into_repr())
        .collect::<Vec<_>>();
    VariableBaseMSM::multi_scalar_mul(ys, &r)
}

pub fn combine_f<G: AffineCurve, F: Homomorphism<G::ScalarField, Output = G>>(
    fs: &[F],
    rho_powers: &[G::ScalarField],
) -> F {
    fs.iter()
        .zip(rho_powers.iter())
        .map(|(f, r)| f.scale(r))
        .reduce(|a, b| a.add(&b))
        .unwrap()
}

impl<G> RandomCommitment<G>
where
    G: AffineCurve,
{
    pub fn new<R: RngCore, D: Digest, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        P: &G,
        ys: &[G],
        fs: &[F],
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Self {
        assert_eq!(ys.len(), fs.len());

        let rho_powers = create_rho_powers::<D, _>(g, P, ys);
        let f_rho = combine_f(fs, &rho_powers);

        let r = if let Some(blindings) = blindings {
            assert_eq!(blindings.len(), g.len());
            blindings
        } else {
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = f_rho.eval(&r);
        let scalars = cfg_iter!(r).map(|b| b.into_repr()).collect::<Vec<_>>();

        let A = VariableBaseMSM::multi_scalar_mul(g, &scalars);
        Self {
            r,
            A: A.into_affine(),
            t,
        }
    }

    pub fn response(&self, x: &[G::ScalarField], challenge: &G::ScalarField) -> Response<G> {
        assert_eq!(self.r.len(), x.len());
        Response {
            z: self
                .r
                .iter()
                .zip(x.iter())
                .map(|(r, x)| *r + *x * challenge)
                .collect(),
        }
    }
}

impl<G> Response<G>
where
    G: AffineCurve,
{
    pub fn is_valid<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        &self,
        g: &[G],
        P: &G,
        ys: &[G],
        fs: &[F],
        A: &G,
        t: &G,
        challenge: &G::ScalarField,
    ) -> Result<(), CompSigmaError> {
        assert_eq!(ys.len(), fs.len());

        let z_repr = cfg_iter!(self.z).map(|z| z.into_repr()).collect::<Vec<_>>();
        let challenge_repr = challenge.into_repr();

        if VariableBaseMSM::multi_scalar_mul(g, &z_repr) != P.mul(challenge_repr).add_mixed(A) {
            return Err(CompSigmaError::InvalidResponse);
        }

        let rho_powers = create_rho_powers::<D, _>(g, P, ys);
        let f_rho = combine_f(fs, &rho_powers);
        let y_rho = combine_y(ys, &rho_powers);
        if f_rho.eval(&self.z) != y_rho.mul(challenge_repr).add_mixed(t).into_affine() {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    pub fn compress<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        self,
        g: &[G],
        P: &G,
        ys: &[G],
        fs: &[F],
    ) -> compressed_homomorphism::Response<G> {
        let rho_powers = create_rho_powers::<D, _>(g, P, ys);
        let f_rho = combine_f(fs, &rho_powers);
        compressed_homomorphism::RandomCommitment::compressed_response::<D, F>(
            self.z,
            g.to_vec(),
            f_rho,
        )
    }

    pub fn is_valid_compressed<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        g: &[G],
        fs: &[F],
        P: &G,
        ys: &[G],
        A: &G,
        t: &G,
        challenge: &G::ScalarField,
        compressed_resp: &compressed_homomorphism::Response<G>,
    ) -> Result<(), CompSigmaError> {
        let rho_powers = create_rho_powers::<D, _>(g, P, ys);
        let f_rho = combine_f(fs, &rho_powers);
        let y_rho = combine_y(ys, &rho_powers);
        let (Q, Y) = compressed_homomorphism::calculate_Q_and_Y::<G>(
            P,
            &y_rho.into_affine(),
            A,
            t,
            challenge,
        );
        compressed_resp.recursively_validate_compressed::<D, F>(Q, Y, g.to_vec(), f_rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::pad_homomorphisms_to_have_same_size;
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
        let size = 8;
        let hom1 = TestHom {
            constants: (0..size - 1)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom2 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom3 = TestHom {
            constants: (0..size - 2)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom4 = TestHom {
            constants: (0..size + 5)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom5 = TestHom {
            constants: (0..size + 1)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let homs = [hom1, hom2, hom3, hom4, hom5];

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();

        let fs = pad_homomorphisms_to_have_same_size(&homs);
        let ys = fs.iter().map(|f| f.eval(&x)).collect::<Vec<_>>();
        let rand_comm = RandomCommitment::new::<_, Blake2b, _>(&mut rng, &g, &comm, &ys, &fs, None);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(&x, &challenge);
        response
            .is_valid::<Blake2b, _>(&g, &comm, &ys, &fs, &rand_comm.A, &rand_comm.t, &challenge)
            .unwrap();
    }

    #[test]
    fn amortization_and_compression() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let size = 8;
        let hom1 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom2 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom3 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom4 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let hom5 = TestHom {
            constants: (0..size)
                .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>(),
        };
        let homs = [hom1, hom2, hom3, hom4, hom5];

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm = VariableBaseMSM::multi_scalar_mul(
            &g,
            &x.iter().map(|x| x.into_repr()).collect::<Vec<_>>(),
        )
        .into_affine();

        let fs = pad_homomorphisms_to_have_same_size(&homs);
        let ys = fs.iter().map(|f| f.eval(&x)).collect::<Vec<_>>();
        let rand_comm = RandomCommitment::new::<_, Blake2b, _>(&mut rng, &g, &comm, &ys, &fs, None);
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(&x, &challenge);
        response
            .is_valid::<Blake2b, _>(&g, &comm, &ys, &fs, &rand_comm.A, &rand_comm.t, &challenge)
            .unwrap();

        let comp_resp = response.compress::<Blake2b, _>(&g, &comm, &ys, &fs);
        Response::is_valid_compressed::<Blake2b, _>(
            &g,
            &fs,
            &comm,
            &ys,
            &rand_comm.A,
            &rand_comm.t,
            &challenge,
            &comp_resp,
        )
        .unwrap();
    }
}
