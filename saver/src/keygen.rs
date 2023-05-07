use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{error::SaverError, saver_groth16, setup::EncryptionGens, utils::chunks_count};
use dock_crypto_utils::{msm::multiply_field_elems_with_same_group_elem, serde_utils::*};

/// Used to decrypt
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct SecretKey<F: PrimeField>(#[serde_as(as = "ArkObjectBytes")] pub F);

/// Used to encrypt, rerandomize and verify the encryption. Called "PK" in the paper.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct EncryptionKey<E: Pairing> {
    /// `G * delta`
    #[serde_as(as = "ArkObjectBytes")]
    pub X_0: E::G1Affine,
    /// `G * delta*s_i`
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub X: Vec<E::G1Affine>,
    /// `G_i * t_{i+1}`
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub Y: Vec<E::G1Affine>,
    /// `H * t_i`
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub Z: Vec<E::G2Affine>,
    /// `(G*delta) * t_0 + (G*delta) * t_1*s_0 + (G*delta) * t_2*s_1 + .. (G*delta) * t_n*s_{n-1}`
    #[serde_as(as = "ArkObjectBytes")]
    pub P_1: E::G1Affine,
    /// `(G*-gamma) * (1 + s_0 + s_1 + .. s_{n-1})`
    #[serde_as(as = "ArkObjectBytes")]
    pub P_2: E::G1Affine,
}

/// Same as EncryptionKey but the elements in G2 are prepared for pairing making pairing faster
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedEncryptionKey<E: Pairing> {
    /// `G * delta`
    pub X_0: E::G1Affine,
    /// `G * delta*s_i`
    pub X: Vec<E::G1Affine>,
    /// `G_i * t_{i+1}`
    pub Y: Vec<E::G1Affine>,
    /// `H * t_i`
    pub Z: Vec<E::G2Prepared>,
    /// `(G*delta) * t_0 + (G*delta) * t_1*s_0 + (G*delta) * t_2*s_1 + .. (G*delta) * t_n*s_{n-1}`
    pub P_1: E::G1Affine,
    /// `(G*-gamma) * (1 + s_0 + s_1 + .. s_{n-1})`
    pub P_2: E::G1Affine,
}

/// Used to decrypt and verify decryption. Called "VK" in the paper.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct DecryptionKey<E: Pairing> {
    /// `H * rho`
    #[serde_as(as = "ArkObjectBytes")]
    pub V_0: E::G2Affine,
    /// `H * s_i*v_i`
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub V_1: Vec<E::G2Affine>,
    /// `H * rho*v_i`
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub V_2: Vec<E::G2Affine>,
}

/// Same as DecryptionKey but the elements in G2 are prepared for pairing making pairing faster
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedDecryptionKey<E: Pairing> {
    /// `H * rho`
    pub V_0: E::G2Prepared,
    /// `H * s_i*v_i`
    pub V_1: Vec<E::G2Prepared>,
    /// `H * rho*v_i`
    pub V_2: Vec<E::G2Prepared>,
}

macro_rules! impl_enc_key_funcs {
    () => {
        pub fn supported_chunks_count(&self) -> crate::Result<u8> {
            let n = self.X.len();
            if self.Y.len() != n {
                return Err(SaverError::MalformedEncryptionKey(self.Y.len(), n));
            }
            if self.Z.len() != (n + 1) {
                return Err(SaverError::MalformedEncryptionKey(self.Z.len(), n));
            }
            Ok(n as u8)
        }

        pub fn validate(&self) -> crate::Result<()> {
            self.supported_chunks_count()?;
            Ok(())
        }

        pub fn commitment_key(&self) -> Vec<E::G1Affine> {
            let mut ck = self.Y.clone();
            ck.push(self.P_1.clone());
            ck
        }
    };
}

macro_rules! impl_dec_key_funcs {
    () => {
        pub fn supported_chunks_count(&self) -> crate::Result<u8> {
            let n = self.V_1.len();
            if self.V_2.len() != n {
                return Err(SaverError::MalformedDecryptionKey(self.V_2.len(), n));
            }
            Ok(n as u8)
        }

        pub fn validate(&self) -> crate::Result<()> {
            self.supported_chunks_count()?;
            Ok(())
        }

        pub fn pairing_powers_given_groth16_vk(
            &self,
            chunk_bit_size: u8,
            snark_vk: &ark_groth16::VerifyingKey<E>,
        ) -> crate::Result<Vec<Vec<PairingOutput<E>>>> {
            let g_i = saver_groth16::get_gs_for_encryption(&snark_vk);
            self.pairing_powers(chunk_bit_size, g_i)
        }
    };
}

impl<E: Pairing> EncryptionKey<E> {
    impl_enc_key_funcs!();
}

impl<E: Pairing> From<EncryptionKey<E>> for PreparedEncryptionKey<E> {
    fn from(ek: EncryptionKey<E>) -> Self {
        Self {
            X_0: ek.X_0,
            X: ek.X,
            Y: ek.Y,
            Z: cfg_iter!(ek.Z)
                .map(|z| E::G2Prepared::from(*z))
                .collect::<Vec<_>>(),
            P_1: ek.P_1,
            P_2: ek.P_2,
        }
    }
}

impl<E: Pairing> From<DecryptionKey<E>> for PreparedDecryptionKey<E> {
    fn from(dk: DecryptionKey<E>) -> Self {
        Self {
            V_0: E::G2Prepared::from(dk.V_0),
            V_1: cfg_iter!(dk.V_1)
                .map(|v| E::G2Prepared::from(*v))
                .collect::<Vec<_>>(),
            V_2: cfg_iter!(dk.V_2)
                .map(|v| E::G2Prepared::from(*v))
                .collect::<Vec<_>>(),
        }
    }
}

impl<E: Pairing> PreparedEncryptionKey<E> {
    impl_enc_key_funcs!();
}

impl<E: Pairing> DecryptionKey<E> {
    impl_dec_key_funcs!();

    /// Calling `pairing_powers` on the prepared decryption key
    pub fn pairing_powers(
        &self,
        chunk_bit_size: u8,
        g_i: &[E::G1Affine],
    ) -> crate::Result<Vec<Vec<PairingOutput<E>>>> {
        let prepared_dk = PreparedDecryptionKey::from(self.clone());
        prepared_dk.pairing_powers(chunk_bit_size, g_i)
    }
}

impl<E: Pairing> PreparedDecryptionKey<E> {
    impl_dec_key_funcs!();

    /// Decryption involves solving discrete log of a pairing evaluation (`Fqk`) by brute force. These
    /// pairings involve the decryption key and generators created while creating snark SRS, both of which are
    /// public. Thus all possible pairings and their powers can be precomputed to speed up decryption.
    /// Returns a vector whose each element is itself a vector of `(1 << chunk_bit_size) - 1` powers of `Fqk`
    pub fn pairing_powers(
        &self,
        chunk_bit_size: u8,
        g_i: &[E::G1Affine],
    ) -> crate::Result<Vec<Vec<PairingOutput<E>>>> {
        let n = self.supported_chunks_count()? as usize;
        let chunk_max_val = (1 << chunk_bit_size) - 1;
        let mut powers = Vec::<Vec<PairingOutput<E>>>::with_capacity(n);
        for i in 0..n {
            // Powers of `g_i_v_i` will be created
            let g_i_v_i = E::pairing(g_i[i], self.V_2[i].clone());

            // `powers_i` will have `chunk_max_val` powers of `g_i_v_i` like [g_i_v_i, g_i_v_i^2, g_i_v_i^3, ...]
            let mut powers_i = Vec::<PairingOutput<E>>::with_capacity(chunk_max_val as usize);
            let mut cur = g_i_v_i;
            powers_i.push(cur);
            for _ in 1..chunk_max_val {
                cur += g_i_v_i;
                powers_i.push(cur);
            }
            powers.push(powers_i);
        }
        Ok(powers)
    }
}

/// Generate keys for encryption and decryption. The parameters `g_i`, `delta_g` and `gamma_g` are
/// shared with the SNARK SRS.
pub fn keygen<R: RngCore, E: Pairing>(
    rng: &mut R,
    chunk_bit_size: u8,
    gens: &EncryptionGens<E>,
    g_i: &[E::G1Affine],
    delta_g: &E::G1Affine,
    gamma_g: &E::G1Affine,
) -> crate::Result<(
    SecretKey<E::ScalarField>,
    EncryptionKey<E>,
    DecryptionKey<E>,
)> {
    let n = chunks_count::<E::ScalarField>(chunk_bit_size) as usize;
    if n > g_i.len() {
        return Err(SaverError::VectorShorterThanExpected(g_i.len(), n));
    }

    let rho = E::ScalarField::rand(rng);
    let s = (0..n)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let t = (0..=n)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();
    let v = (0..n)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let delta_g_proj = delta_g.into_group();
    let t_repr = cfg_iter!(t).map(|t| t.into_bigint()).collect::<Vec<_>>();

    let X = multiply_field_elems_with_same_group_elem(delta_g_proj, &s);
    let Y = (0..n)
        .map(|i| g_i[i].mul_bigint(t_repr[i + 1]))
        .collect::<Vec<_>>();
    let Z = multiply_field_elems_with_same_group_elem(gens.H.into_group(), &t);

    // P_1 = G*delta * (t_0 + \sum_{j in 0..n}(s_j * t_{j+1}))
    let P_1 = delta_g_proj
        .mul_bigint((t[0] + (0..n).map(|j| s[j] * t[j + 1]).sum::<E::ScalarField>()).into_bigint());

    let ek = EncryptionKey {
        X_0: *delta_g,
        X: E::G1::normalize_batch(&X),
        Y: E::G1::normalize_batch(&Y),
        Z: E::G2::normalize_batch(&Z),
        P_1: P_1.into_affine(),
        P_2: gamma_g
            .mul_bigint((E::ScalarField::one() + s.iter().sum::<E::ScalarField>()).into_bigint())
            .into_affine(),
    };
    let V_0 = gens.H.mul_bigint(rho.into_bigint());
    let V_2 = multiply_field_elems_with_same_group_elem(V_0, &v);
    let V_1 = multiply_field_elems_with_same_group_elem(
        gens.H.into_group(),
        &s.into_iter()
            .zip(v.into_iter())
            .map(|(s_i, v_i)| s_i * v_i)
            .collect::<Vec<_>>(),
    );
    let dk = DecryptionKey {
        V_0: V_0.into_affine(),
        V_1: E::G2::normalize_batch(&V_1),
        V_2: E::G2::normalize_batch(&V_2),
    };
    Ok((SecretKey(rho), ek, dk))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::test_serialization;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn keygen_works() {
        fn check_keygen(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let chunk_count = chunks_count::<Fr>(chunk_bit_size) as usize;
            let gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let g_i = (0..chunk_count)
                .map(|_| <Bls12_381 as Pairing>::G1Affine::rand(&mut rng))
                .collect::<Vec<_>>();
            let delta = Fr::rand(&mut rng);
            let gamma = Fr::rand(&mut rng);
            let g_delta = gens.G.mul_bigint(delta.into_bigint()).into_affine();
            let g_gamma = gens.G.mul_bigint(gamma.into_bigint()).into_affine();
            let (sk, ek, dk) =
                keygen(&mut rng, chunk_bit_size, &gens, &g_i, &g_delta, &g_gamma).unwrap();

            let prepared_ek = PreparedEncryptionKey::from(ek.clone());
            let prepared_dk = PreparedDecryptionKey::from(dk.clone());

            assert_eq!(ek.X.len(), chunk_count);
            assert_eq!(prepared_ek.X.len(), chunk_count);
            assert_eq!(ek.Y.len(), chunk_count);
            assert_eq!(prepared_ek.Y.len(), chunk_count);
            assert_eq!(ek.Z.len(), chunk_count + 1);
            assert_eq!(prepared_ek.Z.len(), chunk_count + 1);
            assert_eq!(dk.V_1.len(), chunk_count);
            assert_eq!(prepared_dk.V_1.len(), chunk_count);
            assert_eq!(dk.V_2.len(), chunk_count);
            assert_eq!(prepared_dk.V_2.len(), chunk_count);
            ek.validate().unwrap();
            prepared_ek.validate().unwrap();
            dk.validate().unwrap();
            prepared_dk.validate().unwrap();
            assert_eq!(ek.supported_chunks_count().unwrap(), chunk_count as u8);
            assert_eq!(
                prepared_ek.supported_chunks_count().unwrap(),
                chunk_count as u8
            );
            assert_eq!(dk.supported_chunks_count().unwrap(), chunk_count as u8);
            assert_eq!(
                prepared_dk.supported_chunks_count().unwrap(),
                chunk_count as u8
            );
            assert_eq!(ek.commitment_key().len(), chunk_count + 1);
            assert_eq!(prepared_ek.commitment_key().len(), chunk_count + 1);
            assert_eq!(ek.commitment_key()[..chunk_count], ek.Y);
            assert_eq!(prepared_ek.commitment_key()[..chunk_count], ek.Y);
            assert_eq!(ek.commitment_key()[chunk_count], ek.P_1);
            assert_eq!(prepared_ek.commitment_key()[chunk_count], ek.P_1);

            test_serialization!(EncryptionKey<Bls12_381>, ek);
            test_serialization!(DecryptionKey<Bls12_381>, dk);
            test_serialization!(SecretKey<Fr>, sk);

            drop(sk);
        }

        check_keygen(4);
        check_keygen(8);
        check_keygen(16);
    }
}
