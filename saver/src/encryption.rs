use crate::setup::{DecryptionKey, EncryptionKey, Generators, SecretKey};
use crate::utils::batch_normalize_projective_into_affine;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, Field, One, PrimeField};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};
use std::ops::{Add, AddAssign};

pub fn decompose<F: PrimeField>(m: &F, n: u8) -> Vec<u8> {
    let bytes = m.into_repr().to_bytes_be();
    let mut decomposition = vec![];
    match n {
        4 => {
            for b in bytes {
                decomposition.push(b & 15);
                decomposition.push(b >> 4);
            }
        }
        8 => {
            for b in bytes {
                decomposition.push(b);
            }
        }
        _ => panic!("Only 4 and 8 allowed"),
    }
    decomposition
}

pub fn encrypt<R: RngCore, E: PairingEngine>(
    rng: &mut R,
    m: E::Fr,
    ek: &EncryptionKey<E>,
    g_i: &[E::G1Affine],
) -> (Vec<E::G1Affine>, E::Fr) {
    let decomposed = decompose(&m, 4);
    encrypt_decomposed_message(rng, decomposed, ek, g_i)
}

pub fn encrypt_decomposed_message<R: RngCore, E: PairingEngine>(
    rng: &mut R,
    m: Vec<u8>,
    ek: &EncryptionKey<E>,
    g_i: &[E::G1Affine],
) -> (Vec<E::G1Affine>, E::Fr) {
    assert_eq!(m.len(), ek.X.len());
    let r = E::Fr::rand(rng);
    let r_repr = r.into_repr();
    let mut ct = vec![];
    ct.push(ek.X_0.mul(r_repr));
    let m = m
        .into_iter()
        .map(|m_i| <E::Fr as PrimeField>::BigInt::from(m_i as u64))
        .collect::<Vec<_>>();
    for i in 0..ek.X.len() {
        ct.push(ek.X[i].mul(r_repr).add(g_i[i].mul(m[i])));
    }
    let mut phi = ek.P_1.mul(r);
    phi.add_assign(VariableBaseMSM::multi_scalar_mul(&ek.Y, &m));
    ct.push(phi);
    (batch_normalize_projective_into_affine(ct), r)
}

pub fn decrypt<E: PairingEngine>(
    ciphertext: &[E::G1Affine],
    sk: &SecretKey<E::Fr>,
    dk: &DecryptionKey<E>,
    g_i: &[E::G1Affine],
    max_bits: u8,
) -> (Vec<u8>, E::G1Affine) {
    let n = ciphertext.len() - 2;
    assert_eq!(n, dk.V_1.len());
    // c_0 * -rho
    let c_0_rho = ciphertext[0].mul((-sk.0).into_repr());
    let c_0_rho_prepared = E::G1Prepared::from(c_0_rho.into_affine());
    let mut pt = vec![];
    for i in 0..n {
        let p = E::product_of_pairings(&[
            (ciphertext[i + 1].into(), dk.V_2[i].into()),
            (c_0_rho_prepared.clone(), dk.V_1[i].into()),
        ]);
        // TODO: Use prepared version
        let g_i_v_i = E::pairing(g_i[i], dk.V_2[i]);
        let max = 1 << max_bits;

        let mut powers_of_2 = Vec::with_capacity(max as usize);
        powers_of_2.push(g_i_v_i);
        for i in 1..max {
            powers_of_2.push(powers_of_2[i - 1].square());
        }
        for j in 0..max {
            /*if g_i_v_i.pow(&[j]) == p {
                pt.push(j as u8);
                break;
            }*/
            if E::Fqk::pow_with_table(&powers_of_2, &[j as u64]).unwrap() == p {
                pt.push(j as u8);
                break;
            }
        }
    }
    (pt, (-c_0_rho).into_affine())
}

pub fn ver_enc<E: PairingEngine>(
    ciphertext: &[E::G1Affine],
    ek: &EncryptionKey<E>,
    gens: &Generators<E>,
) -> bool {
    let mut product = vec![];
    for i in 0..ek.Z.len() {
        product.push((ciphertext[i].into(), ek.Z[i].into()))
    }
    product.push((ciphertext[ciphertext.len() - 1].into(), (-gens.H).into()));
    E::product_of_pairings(&product).is_one()
}

// TODO: Add functions to rerandomize and verify decryption

/*fn find_discrete_log<E: PairingEngine>(g_i_v_i: &E::Fqk, max_bits: u8) -> u8 {
    let max = 1 << max_bits;
    let mut powers_of_2 = Vec::with_capacity(max as usize);
    powers_of_2.push(g_i_v_i);
    for i in 1..max {
        powers_of_2.push(powers_of_2[i-1].square());
    }
    for j in 0..max {
        /*// TODO: Use pow_with_table
        if g_i_v_i.pow(&[j]) == p {
            pt.push(j as u8);
            break;
        }*/
        if E::Fqk::pow_with_table(&powers_of_2, &[j]).unwrap() == p {
            return j;
        }
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::setup::keygen;
    use ark_bls12_381::Bls12_381;
    use ark_ec::group::Group;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{Rng, SeedableRng};

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn encrypt_decrypt() {
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

        let m = vec![2, 47, 239, 155];

        let start = Instant::now();
        let (ct, _) = encrypt_decomposed_message(&mut rng, m.clone(), &ek, &g_i);
        println!("Time taken to encrypt {:?}", start.elapsed());

        assert_eq!(ct.len(), m.len() + 2);
        assert!(ver_enc(&ct, &ek, &gens));

        let start = Instant::now();
        let (m_, nu) = decrypt(&ct, &sk, &dk, &g_i, 8);
        println!("Time taken to decrypt {:?}", start.elapsed());

        assert_eq!(m_, m);
    }
}
