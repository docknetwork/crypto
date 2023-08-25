//! Amortized sigma protocol with homomorphism as described in section 3.4 of the paper "Compressing Proofs of k-Out-Of-n".
//! This is for the relation R_{AMORHOM} where a many homomorphisms are applied over a single witness vector and
//! there is a commitment to the witness vector.

use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::Digest;

use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

use crate::{
    compressed_homomorphism, error::CompSigmaError, transforms::Homomorphism, utils::get_n_powers,
};

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomCommitment<G: AffineRepr> {
    /// Random vector from Z_q^n
    pub r: Vec<G::ScalarField>,
    /// A = \vec{g}^{\vec{r}}
    pub A: G,
    /// t = f(\vec{r})
    pub t: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Response<G: AffineRepr> {
    /// \vec{z} = r + \sum_{i=1}^s c^i*\vec{x_i}
    pub z: Vec<G::ScalarField>,
}

/// To amortize many given homomorphisms into a single
pub struct AmortizeHomomorphisms<G: AffineRepr, F: Homomorphism<G::ScalarField, Output = G>>(
    PhantomData<G>,
    PhantomData<F>,
);

impl<G: AffineRepr, F: Homomorphism<G::ScalarField, Output = G>> AmortizeHomomorphisms<G, F> {
    /// Amortize many homomorphisms into a single by generating randomness from the given public
    /// data.
    pub fn new_homomorphism<D: Digest>(g: &[G], ys: &[G], fs: &[F]) -> F {
        let randomness = Self::generate_randomness::<D>(g, ys);
        Self::new_homomorphism_from_given_randomness(fs, &randomness)
    }

    /// Amortize many homomorphisms and their respective evaluations into a single by generating randomness
    /// from the given public data. Returns the new homomorphism and its evaluation as a pair
    pub fn new_homomorphism_and_evaluation<D: Digest>(
        g: &[G],
        ys: &[G],
        fs: &[F],
    ) -> (F, G::Group) {
        let randomness = Self::generate_randomness::<D>(g, ys);
        (
            Self::new_homomorphism_from_given_randomness(fs, &randomness),
            Self::new_evaluation_from_given_randomness(ys, &randomness),
        )
    }

    /// Create a random challenge `rho` and returns its `n` powers as `[1, rho, rho^2, ..., rho^{n-1}]`
    /// `rho` is created by hashing the publicly known values, in this case vectors `g` and `ys`
    pub fn generate_randomness<D: Digest>(g: &[G], ys: &[G]) -> Vec<G::ScalarField> {
        let mut bytes = vec![];
        for g_ in g.iter() {
            g_.serialize_compressed(&mut bytes).unwrap();
        }
        for y in ys.iter() {
            y.serialize_compressed(&mut bytes).unwrap();
        }

        let rho = field_elem_from_try_and_incr::<G::ScalarField, D>(&bytes);
        // rho_powers = [1, rho, rho^2, rho^3, ..., rho^{ys.len()-1}]
        let mut rho_powers = get_n_powers(rho, ys.len() - 1);
        rho_powers.insert(0, G::ScalarField::one());
        rho_powers
    }

    /// Inner product of vectors `ys` and `rho_powers`
    /// Outputs the point y_1 + rho*y_2 + ... + rho^{s-1}*y_s
    pub fn new_evaluation_from_given_randomness(
        ys: &[G],
        rho_powers: &[G::ScalarField],
    ) -> G::Group {
        G::Group::msm_unchecked(ys, &rho_powers[..ys.len()])
    }

    /// Inner product of vectors `fs` and `rho_powers`.
    /// Outputs the homomorphism f(x) `fs[0] * rho_powers[0] + fs[1] * rho_powers[1] + ... + fs[n] * rho_powers[n]`
    pub fn new_homomorphism_from_given_randomness(fs: &[F], rho_powers: &[G::ScalarField]) -> F {
        fs.iter()
            .zip(rho_powers.iter())
            .map(|(f, r)| f.scale(r))
            .reduce(|a, b| a.add(&b).unwrap())
            .unwrap()
    }
}

impl<G> RandomCommitment<G>
where
    G: AffineRepr,
{
    pub fn new<R: RngCore, D: Digest, F: Homomorphism<G::ScalarField, Output = G>>(
        rng: &mut R,
        g: &[G],
        ys: &[G],
        fs: &[F],
        blindings: Option<Vec<G::ScalarField>>,
    ) -> Result<Self, CompSigmaError> {
        if ys.len() != fs.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let f_rho = AmortizeHomomorphisms::<_, _>::new_homomorphism::<D>(g, ys, fs);

        let r = if let Some(blindings) = blindings {
            if blindings.len() != g.len() {
                return Err(CompSigmaError::VectorLenMismatch);
            }
            blindings
        } else {
            (0..g.len()).map(|_| G::ScalarField::rand(rng)).collect()
        };
        let t = f_rho.eval(&r).unwrap();
        let A = G::Group::msm_unchecked(g, &r);
        Ok(Self {
            r,
            A: A.into_affine(),
            t,
        })
    }

    pub fn response(
        &self,
        x: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> Result<Response<G>, CompSigmaError> {
        if self.r.len() != x.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }
        Ok(Response {
            z: self
                .r
                .iter()
                .zip(x.iter())
                .map(|(r, x)| *r + *x * challenge)
                .collect(),
        })
    }
}

impl<G> Response<G>
where
    G: AffineRepr,
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
        if ys.len() != fs.len() {
            return Err(CompSigmaError::VectorLenMismatch);
        }

        let challenge_repr = challenge.into_bigint();

        if G::Group::msm_unchecked(g, &self.z) != (P.mul_bigint(challenge_repr) + A) {
            return Err(CompSigmaError::InvalidResponse);
        }

        let (f_rho, y_rho) =
            AmortizeHomomorphisms::<_, _>::new_homomorphism_and_evaluation::<D>(g, ys, fs);
        if f_rho.eval(&self.z).unwrap() != (y_rho.mul_bigint(challenge_repr) + t).into_affine() {
            return Err(CompSigmaError::InvalidResponse);
        }
        Ok(())
    }

    pub fn compress<D: Digest, F: Homomorphism<G::ScalarField, Output = G> + Clone>(
        self,
        g: &[G],
        ys: &[G],
        fs: &[F],
    ) -> compressed_homomorphism::Response<G> {
        let f_rho = AmortizeHomomorphisms::<_, _>::new_homomorphism::<D>(g, ys, fs);
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
        let (f_rho, y_rho) =
            AmortizeHomomorphisms::<_, _>::new_homomorphism_and_evaluation::<D>(g, ys, fs);
        let (Q, Y) = compressed_homomorphism::calculate_Q_and_Y::<G>(
            P,
            &y_rho.into_affine(),
            A,
            t,
            challenge,
        );
        compressed_resp.validate_compressed::<D, F>(Q, Y, g.to_vec(), f_rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::pad_homomorphisms_to_have_same_size;
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
    struct TestHom<G1> {
        pub constants: Vec<G1>,
    }

    impl TestHom<G1> {
        fn new<R: RngCore>(rng: &mut R, size: u32) -> Self {
            Self {
                constants: (0..size)
                    .map(|_| <Bls12_381 as Pairing>::G1::rand(rng).into_affine())
                    .collect::<Vec<_>>(),
            }
        }
    }

    impl_simple_homomorphism!(TestHom, Fr, G1);

    #[test]
    fn amortization() {
        let size = 8;
        let mut rng = StdRng::seed_from_u64(0u64);
        let hom1 = TestHom::new(&mut rng, size - 1);
        let hom2 = TestHom::new(&mut rng, size);
        let hom3 = TestHom::new(&mut rng, size - 2);
        let hom4 = TestHom::new(&mut rng, size + 5);
        let hom5 = TestHom::new(&mut rng, size + 1);
        let homs = [hom1, hom2, hom3, hom4, hom5];

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine();

        let fs = pad_homomorphisms_to_have_same_size(&homs);
        let ys = fs.iter().map(|f| f.eval(&x).unwrap()).collect::<Vec<_>>();
        let rand_comm =
            RandomCommitment::new::<_, Blake2b512, _>(&mut rng, &g, &ys, &fs, None).unwrap();
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(&x, &challenge).unwrap();
        response
            .is_valid::<Blake2b512, _>(&g, &comm, &ys, &fs, &rand_comm.A, &rand_comm.t, &challenge)
            .unwrap();
    }

    #[test]
    fn amortization_and_compression() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let size = 8;
        let hom1 = TestHom::new(&mut rng, size);
        let hom2 = TestHom::new(&mut rng, size);
        let hom3 = TestHom::new(&mut rng, size);
        let hom4 = TestHom::new(&mut rng, size);
        let hom5 = TestHom::new(&mut rng, size);
        let homs = [hom1, hom2, hom3, hom4, hom5];

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine();

        let fs = pad_homomorphisms_to_have_same_size(&homs);
        let ys = fs.iter().map(|f| f.eval(&x).unwrap()).collect::<Vec<_>>();
        let rand_comm =
            RandomCommitment::new::<_, Blake2b512, _>(&mut rng, &g, &ys, &fs, None).unwrap();
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm.response(&x, &challenge).unwrap();

        let start = Instant::now();
        response
            .is_valid::<Blake2b512, _>(&g, &comm, &ys, &fs, &rand_comm.A, &rand_comm.t, &challenge)
            .unwrap();
        println!(
            "Verification of uncompressed response of {} homomorphisms, each of size {} takes: {:?}",
            fs.len(),
            size,
            start.elapsed()
        );

        let start = Instant::now();
        let comp_resp = response.compress::<Blake2b512, _>(&g, &ys, &fs);
        println!(
            "Compressing response of {} homomorphisms, each of size {} takes: {:?}",
            homs.len(),
            size,
            start.elapsed()
        );

        let start = Instant::now();
        Response::is_valid_compressed::<Blake2b512, _>(
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
        println!(
            "Verification of compressed response of {} homomorphisms, each of size {} takes: {:?}",
            fs.len(),
            size,
            start.elapsed()
        );
    }

    #[test]
    fn amortization_and_compression_with_amortization_done_beforehand() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let size = 8;
        let hom1 = TestHom::new(&mut rng, size);
        let hom2 = TestHom::new(&mut rng, size);
        let hom3 = TestHom::new(&mut rng, size);
        let hom4 = TestHom::new(&mut rng, size);
        let hom5 = TestHom::new(&mut rng, size);
        let homs = [hom1, hom2, hom3, hom4, hom5];

        let x = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let g = (0..size)
            .map(|_| <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();

        let comm = <Bls12_381 as Pairing>::G1::msm_unchecked(&g, &x).into_affine();

        let fs = pad_homomorphisms_to_have_same_size(&homs);
        let ys = fs.iter().map(|f| f.eval(&x).unwrap()).collect::<Vec<_>>();

        // Amortize before the protocol is started
        let start = Instant::now();
        let (f_rho, y_rho) = AmortizeHomomorphisms::<_, _>::new_homomorphism_and_evaluation::<
            Blake2b512,
        >(&g, &ys, &fs);
        println!(
            "Time to amortize {} homomorphisms, each of size {} takes: {:?}",
            fs.len(),
            size,
            start.elapsed()
        );

        let rand_comm =
            compressed_homomorphism::RandomCommitment::new(&mut rng, &g, &f_rho, None).unwrap();
        let challenge = Fr::rand(&mut rng);
        let response = rand_comm
            .response::<Blake2b512, _>(&g, &f_rho, &x, &challenge)
            .unwrap();
        response
            .is_valid::<Blake2b512, _>(
                &g,
                &comm,
                &y_rho.into_affine(),
                &f_rho,
                &rand_comm.A_hat,
                &rand_comm.t,
                &challenge,
            )
            .unwrap();
    }
}
