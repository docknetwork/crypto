use ark_ec::bn::G1Affine;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, One, PrimeField, SquareRootField};
use ark_std::{rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use std::ops::AddAssign;

use crate::utils::batch_normalize_projective_into_affine;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;

pub struct Generators<E: PairingEngine> {
    pub G: E::G1Affine,
    pub H: E::G2Affine,
}

/// Used to decrypt
pub struct SecretKey<F: PrimeField + SquareRootField>(pub F);

// TODO: Consider including `n` in encryption and decryption keys to avoid accidental errors

/// Used to encrypt, rerandomize and verify the encryption
pub struct EncryptionKey<E: PairingEngine> {
    /// G * delta
    pub X_0: E::G1Affine,
    /// G * delta*s_i
    pub X: Vec<E::G1Affine>,
    /// G_i * t_i
    pub Y: Vec<E::G1Affine>,
    /// H * t_i
    pub Z: Vec<E::G2Affine>,
    /// (G*delta) * t_0 + (G*delta) * t_1*s_0 + (G*delta) * t_2*s_1 + .. (G*delta) * t_n*s_{n-1}
    pub P_1: E::G1Affine,
    /// (G*-gamma) * (1 + s_0 + s_1 + .. s_{n-1})
    pub P_2: E::G1Affine,
}

pub struct DecryptionKey<E: PairingEngine> {
    // H * rho
    pub V_0: E::G2Affine,
    // H * s_i*v_i
    pub V_1: Vec<E::G2Affine>,
    // H * rho*v_i
    pub V_2: Vec<E::G2Affine>,
}

impl<E: PairingEngine> Generators<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let G = affine_group_elem_from_try_and_incr::<E::G1Affine, D>(
            &to_bytes![label, " : G".as_bytes()].unwrap(),
        );
        let H = affine_group_elem_from_try_and_incr::<E::G2Affine, D>(
            &to_bytes![label, " : H".as_bytes()].unwrap(),
        );
        Self { G, H }
    }

    pub fn new_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let G = E::G1Projective::rand(rng).into_affine();
        let H = E::G2Projective::rand(rng).into_affine();
        Self { G, H }
    }
}

pub fn keygen<R: RngCore, E: PairingEngine>(
    rng: &mut R,
    n: u8,
    gens: &Generators<E>,
    g_i: &[E::G1Affine],
    delta_g: &E::G1Affine,
    gamma_g: &E::G1Affine,
) -> (SecretKey<E::Fr>, EncryptionKey<E>, DecryptionKey<E>) {
    let n = n as usize;
    assert_eq!(g_i.len(), n);

    let rho = E::Fr::rand(rng);
    let s = (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();
    let t = (0..=n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();
    let v = (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>();

    // TODO: Biginteger conversion can be done in parallel
    let delta_g_proj = delta_g.into_projective();
    let X = (0..n)
        .map(|i| delta_g_proj.mul(s[i].into_repr()))
        .collect::<Vec<_>>(); // TODO: Use MSM
    let Y = (0..n).map(|i| g_i[i].mul(t[i + 1].into_repr())).collect();
    let Z = (0..=n).map(|i| gens.H.mul(t[i].into_repr())).collect(); // TODO: Use MSM
    let mut P_1 = delta_g_proj.mul(t[0].into_repr());
    for i in 0..n {
        P_1.add_assign(delta_g_proj.mul((s[i] * t[i + 1]).into_repr()));
    }
    let ek = EncryptionKey {
        X_0: delta_g.clone(),
        X: batch_normalize_projective_into_affine(X),
        Y: batch_normalize_projective_into_affine(Y),
        Z: batch_normalize_projective_into_affine(Z),
        P_1: P_1.into_affine(),
        P_2: gamma_g
            .mul((E::Fr::one() + s.iter().sum::<E::Fr>()).into_repr())
            .into_affine(),
    };
    let V_0 = gens.H.mul(rho.into_repr()).into_affine();
    let V_1 = (0..n)
        .map(|i| gens.H.mul((s[i] * v[i]).into_repr()))
        .collect::<Vec<_>>(); // TODO: Use MSM
    let V_2 = (0..n)
        .map(|i| V_0.mul(v[i].into_repr()))
        .collect::<Vec<_>>(); // TODO: Use MSM
    let dk = DecryptionKey {
        V_0,
        V_1: batch_normalize_projective_into_affine(V_1),
        V_2: batch_normalize_projective_into_affine(V_2),
    };
    (SecretKey(rho), ek, dk)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use ark_bls12_381::Bls12_381;
    use ark_ec::group::Group;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn setup_works() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let n = 4;
        let gens = Generators::<Bls12_381>::new_using_rng(&mut rng);
        let g_i = (0..n)
            .map(|_| <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine())
            .collect::<Vec<_>>();
        let delta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);
        let g_delta = gens.G.mul(delta.into_repr()).into_affine();
        let g_gamma = gens.G.mul(gamma.into_repr()).into_affine();
        let (sk, ek, dk) = keygen(&mut rng, 4, &gens, &g_i, &g_delta, &g_gamma);
        assert_eq!(ek.X.len(), n);
        assert_eq!(ek.Y.len(), n);
        assert_eq!(ek.Z.len(), n + 1);
        assert_eq!(dk.V_1.len(), n);
        assert_eq!(dk.V_2.len(), n);
    }
}
